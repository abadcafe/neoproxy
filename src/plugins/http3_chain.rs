use std::collections::HashMap;
use std::future::{self, Future};
use std::net::SocketAddr;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use std::{fs, path};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use bytes::Bytes;
use h3::client as h3_cli;
use rustls::pki_types::CertificateDer;
use rustls_native_certs::CertificateResult;
use rustls_pemfile;
use serde::Deserialize;
use tokio::sync::{Mutex, Notify};
use tracing::{error, info, warn};

use crate::config::{SerializedArgs, UserCredential};
use super::utils::{self as utils, ConnectTargetError};
use crate::context::RequestContext;
use crate::h3_stream::H3ClientBidiStream;
use crate::http_utils::{
  Request, Response, build_empty_response, build_error_response,
};
use crate::plugin::Plugin;
use crate::service::{BuildService, Service};
use crate::stream::Io;
use crate::tracker::StreamTracker;

/// Error indicating proxy authentication failure (HTTP 407)
#[derive(Debug)]
struct ProxyAuthRequiredError;

impl std::fmt::Display for ProxyAuthRequiredError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "Proxy Authentication Required (407)")
  }
}

impl std::error::Error for ProxyAuthRequiredError {}

static ALPN: &[u8] = b"h3";

/// Graceful shutdown timeout for HTTP/3 Chain Service
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// H3_NO_ERROR error code for CONNECTION_CLOSE frame
const H3_NO_ERROR_CODE: u32 = 0x100;

// ============================================================================
// Upstream Connection (for graceful close)
// ============================================================================

struct UpstreamConnection {
  conn: quinn::Connection,
}

impl UpstreamConnection {
  fn new(conn: quinn::Connection) -> Self {
    Self { conn }
  }

  fn close(&self) {
    self.conn.close(
      quinn::VarInt::from_u32(H3_NO_ERROR_CODE),
      b"graceful shutdown",
    );
  }
}

// ============================================================================
// Client Credential Configuration Types
// ============================================================================

/// Client TLS configuration for http3_chain.
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
struct ClientTlsConfig {
  #[serde(default)]
  client_cert_path: Option<String>,
  #[serde(default)]
  client_key_path: Option<String>,
  #[serde(default)]
  server_ca_path: Option<String>,
}

impl ClientTlsConfig {
  fn validate_if_non_empty(&self) -> Result<()> {
    let has_cert = self.client_cert_path.is_some();
    let has_key = self.client_key_path.is_some();
    if has_cert != has_key {
      bail!(
        "client_cert_path and client_key_path must both be present or \
         both absent"
      );
    }
    Ok(())
  }

  /// Deep merge with a default TLS config.
  /// Fields in `self` take priority; missing fields are inherited from
  /// `default`.
  fn deep_merge(&self, default: &ClientTlsConfig) -> ClientTlsConfig {
    ClientTlsConfig {
      client_cert_path: self
        .client_cert_path
        .clone()
        .or_else(|| default.client_cert_path.clone()),
      client_key_path: self
        .client_key_path
        .clone()
        .or_else(|| default.client_key_path.clone()),
      server_ca_path: self
        .server_ca_path
        .clone()
        .or_else(|| default.server_ca_path.clone()),
    }
  }
}

/// User password credential for proxy authentication.
#[derive(Clone, Debug)]
struct UserPasswordCredential {
  user: Option<UserCredential>,
}

impl UserPasswordCredential {
  fn none() -> Self {
    Self { user: None }
  }

  fn apply(&self, req: &mut http::Request<()>) {
    if let Some(ref user) = self.user {
      let credentials = base64::engine::general_purpose::STANDARD
        .encode(format!("{}:{}", user.username, user.password));
      req.headers_mut().insert(
        "Proxy-Authorization",
        http::HeaderValue::from_str(&format!("Basic {}", credentials))
          .unwrap(),
      );
    }
  }
}

/// Client certificate credential for TLS authentication.
#[derive(Clone, Debug)]
struct ClientCertCredential {
  cert_path: Option<path::PathBuf>,
  key_path: Option<path::PathBuf>,
}

impl ClientCertCredential {
  fn none() -> Self {
    Self { cert_path: None, key_path: None }
  }

  fn build_tls_config(
    &self,
    roots: rustls::RootCertStore,
  ) -> Result<rustls::ClientConfig> {
    match (&self.cert_path, &self.key_path) {
      (Some(cert_path), Some(key_path)) => {
        let cert_file = fs::File::open(cert_path)?;
        let mut cert_reader = std::io::BufReader::new(cert_file);
        let cert_chain: Vec<CertificateDer> =
          rustls_pemfile::certs(&mut cert_reader)
            .collect::<Result<Vec<_>, _>>()?;
        let key_file = fs::File::open(key_path)?;
        let mut key_reader = std::io::BufReader::new(key_file);
        let key = rustls_pemfile::private_key(&mut key_reader)?
          .ok_or_else(|| anyhow!("no private key found"))?;
        Ok(
          rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(cert_chain, key)?,
        )
      }
      _ => Ok(
        rustls::ClientConfig::builder()
          .with_root_certificates(roots)
          .with_no_client_auth(),
      ),
    }
  }
}

async fn connection_maintaining(
  mut conn: h3_cli::Connection<h3_quinn::Connection, Bytes>,
) -> Result<()> {
  let err = future::poll_fn(|cx| conn.poll_close(cx)).await;
  if !err.is_h3_no_error() {
    Err(anyhow::Error::from(err))
  } else {
    Ok(())
  }
}

/// Build TLS client config based on credentials
fn build_tls_client_config(
  roots: rustls::RootCertStore,
  client_cert_credential: &ClientCertCredential,
) -> Result<rustls::ClientConfig> {
  client_cert_credential.build_tls_config(roots)
}

/// Build a 200 OK tunnel response.
fn build_tunnel_response() -> Response {
  build_empty_response(http::StatusCode::OK)
}

// ============================================================================
// Plugin-level Configuration — Three-level Inheritance
// ============================================================================

/// QUIC transport-layer configuration.
/// Items here are passed directly to `quinn::TransportConfig`.
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
struct QuicConfig {
  /// Interval for sending PING frames to keep the QUIC connection alive.
  /// Default: 3s
  #[serde(with = "humantime_serde", default = "default_keep_alive_interval")]
  keep_alive_interval: Duration,
  /// QUIC connection-level idle timeout.
  /// When set, overrides the peer-negotiated default.
  #[serde(with = "humantime_serde", default)]
  max_idle_timeout: Option<Duration>,
}

#[derive(Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
struct Http3ChainPluginConfig {
  #[serde(default)]
  upstreams: Vec<UpstreamConfig>,
  /// Tunnel idle timeout (not QUIC-level)
  #[serde(with = "humantime_serde", default)]
  max_idle_timeout: Option<Duration>,
  /// QUIC transport parameters
  #[serde(default)]
  quic: Option<QuicConfig>,
  #[serde(default)]
  user: Option<UserCredential>,
  #[serde(default)]
  tls: Option<ClientTlsConfig>,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
struct UpstreamConfig {
  name: String,
  #[serde(default)]
  addresses: Vec<UpstreamAddressConfig>,
  /// Tunnel idle timeout (not QUIC-level)
  #[serde(with = "humantime_serde", default)]
  max_idle_timeout: Option<Duration>,
  /// QUIC transport parameters (overrides plugin-level)
  #[serde(default)]
  quic: Option<QuicConfig>,
  #[serde(default)]
  user: Option<UserCredential>,
  #[serde(default)]
  tls: Option<ClientTlsConfig>,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
struct UpstreamAddressConfig {
  address: String,
  #[serde(default)]
  hostname: Option<String>,
  #[serde(default = "default_weight")]
  weight: usize,
  /// Tunnel idle timeout (not QUIC-level)
  #[serde(with = "humantime_serde", default)]
  max_idle_timeout: Option<Duration>,
  /// QUIC transport parameters (overrides upstream-level)
  #[serde(default)]
  quic: Option<QuicConfig>,
  #[serde(default)]
  user: Option<UserCredential>,
  #[serde(default)]
  tls: Option<ClientTlsConfig>,
}

fn default_weight() -> usize { 1 }
fn default_keep_alive_interval() -> Duration { Duration::from_secs(3) }

/// Resolved QUIC-layer config from three-level inheritance.
#[derive(Clone, Debug)]
struct QuicResolved {
  keep_alive_interval: Duration,
  max_idle_timeout: Option<Duration>,
}

/// Resolved config for a single upstream address after three-level
/// inheritance (Plugin → Upstream → Address).
#[derive(Clone, Debug)]
struct ResolvedAddress {
  address: String,
  hostname: Option<String>,
  weight: usize,
  current_weight: isize,
  max_idle_timeout: Duration,
  quic: QuicResolved,
  user_password_credential: UserPasswordCredential,
  client_cert_credential: ClientCertCredential,
  server_ca_path: Option<String>,
}

/// Resolved config for an upstream, containing all its addresses.
#[derive(Clone, Debug)]
struct ResolvedUpstream {
  addresses: Vec<ResolvedAddress>,
}

// ============================================================================
// Global Upstream Pool
// ============================================================================

struct UpstreamProxy {
  max_idle_timeout: Duration,
  user_password_credential: UserPasswordCredential,
  quinn_conn: Option<quinn::Connection>,
  requester: Option<h3_cli::SendRequest<h3_quinn::OpenStreams, Bytes>>,
  h3_conn: Option<h3_cli::Connection<h3_quinn::Connection, Bytes>>,
}

struct UpstreamRegistry {
  resolved: HashMap<String, ResolvedUpstream>,
  pool: HashMap<(String, String), Arc<Mutex<UpstreamProxy>>>,
}

static UPSTREAM_REGISTRY: std::sync::LazyLock<
  std::sync::Mutex<Option<UpstreamRegistry>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(None));

/// Global Notify — signals upstream thread when a new h3_conn is ready.
static UPSTREAM_NOTIFY: std::sync::LazyLock<Notify> =
  std::sync::LazyLock::new(Notify::new);

struct UpstreamThreadHandle {
  shutdown_tx: tokio::sync::mpsc::Sender<()>,
  join_handle: Option<std::thread::JoinHandle<()>>,
}

static UPSTREAM_THREAD_HANDLE: std::sync::LazyLock<
  std::sync::Mutex<Option<UpstreamThreadHandle>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(None));

// ============================================================================
// WRR Scheduling
// ============================================================================

/// Weighted Round-Robin: select an address index from the upstream's
/// resolved addresses.
fn schedule_wrr(addresses: &mut [ResolvedAddress]) -> Option<usize> {
  if addresses.is_empty() {
    return None;
  }
  let total = addresses.iter().fold(0, |t, a| t + a.weight) as isize;
  let mut selected_idx = 0usize;
  let mut selected_weight = 0isize;
  for (i, a) in addresses.iter_mut().enumerate() {
    a.current_weight += a.weight as isize;
    if a.current_weight > selected_weight {
      selected_weight = a.current_weight;
      selected_idx = i;
    }
  }
  addresses[selected_idx].current_weight -= total;
  Some(selected_idx)
}

// ============================================================================
// QUIC Connection Creation
// ============================================================================

async fn create_quic_connection(
  address: &str,
  hostname: Option<&str>,
  client_cert_credential: &ClientCertCredential,
  server_ca_path: Option<&str>,
  quic: &QuicResolved,
) -> Result<quinn::Connection> {
  let mut roots = rustls::RootCertStore::empty();
  let CertificateResult { certs, errors, .. } =
    rustls_native_certs::load_native_certs();
  for cert in certs {
    if let Err(e) = roots.add(cert) {
      error!("failed to parse trust anchor: {e}");
    }
  }
  for e in errors {
    error!("couldn't load default trust roots: {e}");
  }

  if let Some(ca_path_str) = server_ca_path {
    let ca_path = path::Path::new(ca_path_str);
    info!("Loading CA certificate from: {:?}", ca_path);
    let ca_file = fs::File::open(ca_path)?;
    let mut ca_reader = std::io::BufReader::new(ca_file);
    let ca_certs: Vec<CertificateDer> =
      rustls_pemfile::certs(&mut ca_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
          anyhow::anyhow!("failed to parse CA certificate: {e}")
        })?;
    info!("Loaded {} CA certificates", ca_certs.len());
    for cert in ca_certs {
      if let Err(e) = roots.add(cert) {
        error!("failed to add CA certificate to trust store: {e}");
      } else {
        info!("Successfully added CA certificate to trust store");
      }
    }
  }

  let mut tls_config =
    build_tls_client_config(roots, client_cert_credential)?;

  tls_config.enable_early_data = true;
  tls_config.alpn_protocols = vec![ALPN.into()];
  tls_config.key_log = Arc::new(rustls::KeyLogFile::new());

  let mut cli_endpoint =
    quinn::Endpoint::client("[::]:0".parse().unwrap())?;

  let mut cli_config = quinn::ClientConfig::new(Arc::new(
    quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)?,
  ));

  // Apply QUIC transport config
  let mut transport = quinn::TransportConfig::default();
  transport.keep_alive_interval(Some(quic.keep_alive_interval));
  if let Some(idle) = quic.max_idle_timeout {
    let ms = u64::try_from(idle.as_millis())
      .map_err(|_| anyhow!("quic max_idle_timeout too large"))?;
    transport.max_idle_timeout(Some(
      quinn::VarInt::from_u64(ms).context("quic max_idle_timeout overflow")?
        .into(),
    ));
  }
  cli_config.transport_config(Arc::new(transport));

  cli_endpoint.set_default_client_config(cli_config);

  let addr = resolve_address(address)?;
  let host: &str = hostname.unwrap_or_else(|| {
    panic!("hostname is required for SNI");
  });
  let conn = cli_endpoint.connect(addr, host)?.await?;

  info!("QUIC connection established to {}", address);
  Ok(conn)
}

// ============================================================================
// Upstream Handle Acquisition
// ============================================================================

struct UpstreamHandle {
  requester: h3_cli::SendRequest<h3_quinn::OpenStreams, Bytes>,
  user_password_credential: UserPasswordCredential,
  max_idle_timeout: Duration,
}

async fn get_upstream_handle(upstream_name: &str) -> Result<UpstreamHandle> {
  let (proxy_arc, address_str, hostname, client_cert_credential,
       server_ca_path, quic_resolved) =
  {
    let mut guard = UPSTREAM_REGISTRY.lock().unwrap();
    let registry = guard.as_mut()
      .ok_or_else(|| anyhow!("upstream registry not initialized"))?;

    // WRR: select an address from the upstream
    let upstream = registry.resolved.get_mut(upstream_name)
      .ok_or_else(|| anyhow!("upstream '{}' not found", upstream_name))?;
    let idx = schedule_wrr(&mut upstream.addresses)
      .ok_or_else(|| anyhow!("upstream '{}' has no addresses", upstream_name))?;
    let resolved = &upstream.addresses[idx];
    let address = resolved.address.clone();
    let key = (upstream_name.to_string(), address.clone());

    let proxy_arc = registry.pool.get(&key)
      .ok_or_else(|| anyhow!("upstream '{}' address '{}' not in pool", upstream_name, address))?
      .clone();

    let hostname = resolved.hostname.clone();
    let ccc = resolved.client_cert_credential.clone();
    let scp = resolved.server_ca_path.clone();
    let quic = resolved.quic.clone();

    (proxy_arc, address, hostname, ccc, scp, quic)
  };

  let mut proxy = proxy_arc.lock().await;

  // Check if existing connection is still usable
  if let Some(ref conn) = proxy.quinn_conn {
    if conn.close_reason().is_none() {
      return Ok(UpstreamHandle {
        requester: proxy.requester.as_ref().unwrap().clone(),
        user_password_credential: proxy.user_password_credential.clone(),
        max_idle_timeout: proxy.max_idle_timeout,
      });
    }
    // Connection is dead, clear it
    proxy.quinn_conn = None;
    proxy.requester = None;
    proxy.h3_conn = None;
  }

  // No usable connection — create one while holding the lock
  let quinn_conn = create_quic_connection(
    &address_str,
    hostname.as_deref(),
    &client_cert_credential,
    server_ca_path.as_deref(),
    &quic_resolved,
  ).await?;

  let (h3_conn, requester) =
    h3::client::new(h3_quinn::Connection::new(quinn_conn.clone())).await?;

  proxy.quinn_conn = Some(quinn_conn);
  proxy.requester = Some(requester.clone());
  proxy.h3_conn = Some(h3_conn);

  // Notify upstream thread to take over maintenance
  UPSTREAM_NOTIFY.notify_one();

  Ok(UpstreamHandle {
    requester,
    user_password_credential: proxy.user_password_credential.clone(),
    max_idle_timeout: proxy.max_idle_timeout,
  })
}

// ============================================================================
// Upstream Maintenance Thread
// ============================================================================

fn upstream_thread_main(
  mut shutdown_rx: tokio::sync::mpsc::Receiver<()>,
) {
  let rt = tokio::runtime::Builder::new_current_thread()
    .enable_all().build().unwrap();
  let local = Rc::new(tokio::task::LocalSet::new());
  let local_rc = local.clone();

  local.block_on(&rt, async move {
    loop {
      tokio::select! {
        _ = UPSTREAM_NOTIFY.notified() => {
          let guard = UPSTREAM_REGISTRY.lock().unwrap();
          if let Some(ref registry) = *guard {
            for ((upstream_name, address), proxy_arc) in &registry.pool {
              let mut proxy = proxy_arc.lock().await;
              if let Some(h3_conn) = proxy.h3_conn.take() {
                let name = upstream_name.clone();
                let addr = address.clone();
                local_rc.spawn_local(async move {
                  let _ = connection_maintaining(h3_conn).await;
                  info!("upstream {} addr {}: connection ended", name, addr);
                });
              }
            }
          }
        }
        _ = shutdown_rx.recv() => break,
      }
    }
  });
}

// ============================================================================
// Init / Uninstall
// ============================================================================

fn deep_merge_tls(
  addr_tls: &Option<ClientTlsConfig>,
  upstream_tls: &Option<ClientTlsConfig>,
  plugin_tls: &Option<ClientTlsConfig>,
) -> Option<ClientTlsConfig> {
  // Three-level merge: address > upstream > plugin
  let step1 = match (upstream_tls, plugin_tls) {
    (Some(u), Some(p)) => Some(u.deep_merge(p)),
    (Some(u), None) => Some(u.clone()),
    (None, Some(p)) => Some(p.clone()),
    (None, None) => None,
  };
  match (addr_tls, &step1) {
    (Some(a), Some(s)) => Some(a.deep_merge(s)),
    (Some(a), None) => Some(a.clone()),
    (None, Some(s)) => Some(s.clone()),
    (None, None) => None,
  }
}

fn resolve_three_level(
  plugin: &Http3ChainPluginConfig,
) -> Result<HashMap<String, ResolvedUpstream>> {
  let mut upstreams: HashMap<String, ResolvedUpstream> = HashMap::new();

  for upstream in &plugin.upstreams {
    let mut addresses = Vec::new();

    for addr in &upstream.addresses {
      // Resolve TLS: address > upstream > plugin
      let effective_tls = deep_merge_tls(
        &addr.tls, &upstream.tls, &plugin.tls,
      );
      if let Some(ref tls) = effective_tls {
        tls.validate_if_non_empty()
          .with_context(|| format!(
            "upstream '{}' address '{}' tls", upstream.name, addr.address))?;
      }

      // Resolve user: address > upstream > plugin
      let effective_user = addr.user.clone()
        .or_else(|| upstream.user.clone())
        .or_else(|| plugin.user.clone());

      let upc = match effective_user {
        Some(user) => UserPasswordCredential { user: Some(user) },
        None => UserPasswordCredential::none(),
      };

      let (ccc, server_ca_path) = match &effective_tls {
        None => (ClientCertCredential::none(), None),
        Some(tls_config) => {
          let ccc = match (&tls_config.client_cert_path, &tls_config.client_key_path) {
            (Some(cert), Some(key)) => ClientCertCredential {
              cert_path: Some(cert.into()),
              key_path: Some(key.into()),
            },
            _ => ClientCertCredential::none(),
          };
          (ccc, tls_config.server_ca_path.clone())
        }
      };

      // Resolve max_idle_timeout (tunnel layer): address > upstream > plugin > default
      let max_idle_timeout = addr.max_idle_timeout
        .or(upstream.max_idle_timeout)
        .or(plugin.max_idle_timeout)
        .unwrap_or_else(default_idle_timeout);

      // Resolve quic layer: address.quic > upstream.quic > plugin.quic
      let quic = {
        let q = addr.quic.as_ref()
          .or(upstream.quic.as_ref())
          .or(plugin.quic.as_ref());
        QuicResolved {
          keep_alive_interval: q.map(|c| c.keep_alive_interval)
            .unwrap_or_else(default_keep_alive_interval),
          max_idle_timeout: q.and_then(|c| c.max_idle_timeout),
        }
      };

      // Validate address format
      validate_address_format(&addr.address)?;

      addresses.push(ResolvedAddress {
        address: addr.address.clone(),
        hostname: addr.hostname.clone(),
        weight: addr.weight,
        current_weight: 0,
        max_idle_timeout,
        quic,
        user_password_credential: upc,
        client_cert_credential: ccc,
        server_ca_path,
      });
    }

    upstreams.insert(upstream.name.clone(), ResolvedUpstream {
      addresses,
    });
  }

  Ok(upstreams)
}

fn init_upstream_registry(config: &Http3ChainPluginConfig) -> Result<()> {
  let mut guard = UPSTREAM_REGISTRY.lock().unwrap();

  // Idempotent: if already initialized, skip
  if guard.is_some() {
    info!("upstream registry already initialized, skipping");
    return Ok(());
  }

  let resolved = resolve_three_level(config)?;

  // Build pool entries
  let mut pool: HashMap<(String, String), Arc<Mutex<UpstreamProxy>>> = HashMap::new();
  for (upstream_name, upstream) in &resolved {
    for addr in &upstream.addresses {
      let key = (upstream_name.clone(), addr.address.clone());
      pool.insert(key, Arc::new(Mutex::new(UpstreamProxy {
        max_idle_timeout: addr.max_idle_timeout,
        user_password_credential: addr.user_password_credential.clone(),
        quinn_conn: None,
        requester: None,
        h3_conn: None,
      })));
    }
  }

  *guard = Some(UpstreamRegistry { resolved, pool });

  // Start upstream maintenance thread
  let (shutdown_tx, shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);
  let join_handle = std::thread::Builder::new()
    .name("http3-upstream".into())
    .spawn(move || {
      upstream_thread_main(shutdown_rx);
    })?;

  let upstream_count = guard.as_ref().map(|r| r.resolved.len()).unwrap_or(0);
  drop(guard);

  let mut th_guard = UPSTREAM_THREAD_HANDLE.lock().unwrap();
  *th_guard = Some(UpstreamThreadHandle {
    shutdown_tx,
    join_handle: Some(join_handle),
  });
  drop(th_guard);

  info!("upstream registry initialized with {} upstream(s)", upstream_count);
  Ok(())
}

// ============================================================================
// Service Configuration
// ============================================================================

#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
struct Http3ChainServiceArgs {
  upstream: String,
}

impl Http3ChainServiceArgs {
  fn validate(&self) -> Result<()> {
    if self.upstream.is_empty() {
      bail!("upstream name cannot be empty");
    }
    Ok(())
  }
}

// ============================================================================
// Service
// ============================================================================

#[derive(Clone)]
struct Http3ChainService {
  upstream_name: String,
  stream_tracker: Rc<StreamTracker>,
}

impl Http3ChainService {
  #[allow(clippy::new_ret_no_self)]
  fn new(
    sargs: SerializedArgs,
    stream_tracker: Rc<StreamTracker>,
  ) -> Result<Service> {
    let args: Http3ChainServiceArgs = serde_yaml::from_value(sargs)?;
    args.validate()?;

    Ok(Service::new(Self {
      upstream_name: args.upstream,
      stream_tracker,
    }))
  }

  fn is_shutting_down(&self) -> bool {
    self.stream_tracker.shutdown_handle().is_shutdown()
  }
}

impl tower::Service<Request> for Http3ChainService {
  type Error = anyhow::Error;
  type Future = Pin<Box<dyn Future<Output = Result<Response>>>>;
  type Response = Response;

  fn poll_ready(
    &mut self,
    _cx: &mut TaskContext<'_>,
  ) -> Poll<Result<(), Self::Error>> {
    Poll::Ready(Ok(()))
  }

  fn call(&mut self, mut req: Request) -> Self::Future {
    let upstream_name = self.upstream_name.clone();
    let st = self.stream_tracker.clone();
    let is_shutting_down = self.is_shutting_down();

    let ctx = req
      .extensions()
      .get::<RequestContext>()
      .cloned()
      .expect("RequestContext should be present");

    let upgrade = crate::stream::extract_upgrade(&mut req);
    let (req_headers, _req_body) = req.into_parts();

    Box::pin(async move {
      if is_shutting_down {
        warn!("Http3ChainService: rejecting request during shutdown");
        return Ok(build_empty_response(
          http::StatusCode::SERVICE_UNAVAILABLE,
        ));
      }

      let (host, port) = match utils::parse_connect_target(&req_headers) {
        Ok(result) => result,
        Err(ConnectTargetError::NotConnectMethod) => {
          return Ok(build_error_response(
            http::StatusCode::METHOD_NOT_ALLOWED,
            "Only CONNECT method is supported",
          ));
        }
        Err(
          ConnectTargetError::NoAuthority
          | ConnectTargetError::NoPort
          | ConnectTargetError::PortZero,
        ) => {
          return Ok(build_error_response(
            http::StatusCode::BAD_REQUEST,
            "Invalid target address",
          ));
        }
      };

      let handle = match get_upstream_handle(&upstream_name).await {
        Ok(h) => h,
        Err(e) => {
          warn!(
            "Http3ChainService: failed to get upstream handle: {e}"
          );
          return Ok(build_empty_response(
            http::StatusCode::BAD_GATEWAY,
          ));
        }
      };

      send_connect_and_tunnel_with_credential(
        handle.requester,
        host,
        port,
        &handle.user_password_credential,
        &st,
        upgrade,
        &ctx,
        handle.max_idle_timeout,
      )
      .await
    })
  }
}

/// Send CONNECT request with credentials and tunnel data
async fn send_connect_and_tunnel_with_credential(
  mut requester: h3_cli::SendRequest<h3_quinn::OpenStreams, Bytes>,
  host: String,
  port: u16,
  user_password_credential: &UserPasswordCredential,
  st: &Rc<StreamTracker>,
  upgrade: Option<Pin<Box<dyn Future<Output = Result<Box<dyn Io>>>>>>,
  ctx: &RequestContext,
  max_idle_timeout: Duration,
) -> Result<Response> {
  let mut proxy_req = http::Request::builder()
    .method(http::Method::CONNECT)
    .uri(format!("{host}:{port}"))
    .body(())?;

  user_password_credential.apply(&mut proxy_req);

  info!("Http3ChainService: sending CONNECT request");
  let proxy_start = std::time::Instant::now();
  let mut proxy_stream = requester.send_request(proxy_req).await?;
  let proxy_resp = proxy_stream.recv_response().await?;
  let proxy_ms = proxy_start.elapsed().as_millis() as u64;
  info!(
    "Http3ChainService: received CONNECT response: status={}",
    proxy_resp.status()
  );

  if proxy_resp.status()
    == http::StatusCode::PROXY_AUTHENTICATION_REQUIRED
  {
    return Err(ProxyAuthRequiredError.into());
  }

  if !proxy_resp.status().is_success() {
    return Ok(build_empty_response(proxy_resp.status()));
  }

  info!("Http3ChainService: CONNECT succeeded, setting up tunnel");
  let (sending_stream, receiving_stream) = proxy_stream.split();
  complete_tunnel(
    sending_stream,
    receiving_stream,
    requester,
    st,
    upgrade,
    proxy_ms,
    ctx,
    max_idle_timeout,
  )
  .await
}

/// Complete the tunnel by setting up bidirectional transfer
async fn complete_tunnel(
  sending_stream: h3_cli::RequestStream<
    h3_quinn::SendStream<Bytes>,
    Bytes,
  >,
  receiving_stream: h3_cli::RequestStream<h3_quinn::RecvStream, Bytes>,
  requester: h3_cli::SendRequest<h3_quinn::OpenStreams, Bytes>,
  st: &Rc<StreamTracker>,
  upgrade: Option<Pin<Box<dyn Future<Output = Result<Box<dyn Io>>>>>>,
  connect_ms: u64,
  ctx: &RequestContext,
  max_idle_timeout: Duration,
) -> Result<Response> {
  ctx.insert(
    "http3_chain.connect_ms",
    connect_ms.to_string(),
  );

  let resp = build_tunnel_response();
  let shutdown_handle = st.shutdown_handle();
  let addr = "http3_chain".to_string();

  st.register(async move {
    // Hold requester alive for the tunnel's lifetime
    let _requester = requester;

    let client = match upgrade {
      Some(u) => match u.await {
        Ok(c) => c,
        Err(e) => {
          warn!("tunnel to {addr} upgrade failed: {e}");
          return;
        }
      },
      None => {
        warn!("tunnel to {addr}: no upgrade available");
        return;
      }
    };

    let h3_stream =
      H3ClientBidiStream::new(sending_stream, receiving_stream);

    crate::stream::run_tunnel(
      client,
      h3_stream,
      shutdown_handle,
      max_idle_timeout,
      &addr,
    )
    .await;
  });

  Ok(resp)
}

// ============================================================================
// Validation Helpers
// ============================================================================

/// Validate that an address string has host:port format without DNS resolution.
fn validate_address_format(s: &str) -> Result<()> {
  let colon_pos = s
    .rfind(':')
    .ok_or_else(|| anyhow!("address '{s}' missing port"))?;
  let port_str = &s[colon_pos + 1..];
  port_str
    .parse::<u16>()
    .with_context(|| format!("address '{s}' has invalid port"))?;
  let host = &s[..colon_pos];
  if host.is_empty() {
    anyhow::bail!("address '{s}' missing host");
  }
  Ok(())
}

/// Resolve an address string to a SocketAddr.
fn resolve_address(s: &str) -> Result<SocketAddr> {
  s.parse()
    .or_else(|_| {
      std::net::ToSocketAddrs::to_socket_addrs(s)
        .map_err(|e| anyhow!("address '{s}' is neither IP:port nor resolvable hostname: {e}"))
        .and_then(|mut addrs| {
          addrs.next().ok_or_else(|| anyhow!("address '{s}' resolved to no addresses"))
        })
    })
    .with_context(|| format!("address '{s}'"))
}

fn default_idle_timeout() -> Duration {
  Duration::from_secs(crate::stream::DEFAULT_IDLE_TIMEOUT_SECS)
}

// ============================================================================
// Plugin
// ============================================================================

struct Http3ChainPlugin {
  service_builders: HashMap<&'static str, Box<dyn BuildService>>,
  stream_tracker: Rc<StreamTracker>,
  is_uninstalled: Rc<AtomicBool>,
}

impl Http3ChainPlugin {
  fn new() -> Self {
    let stream_tracker = Rc::new(StreamTracker::new());
    let st_clone = stream_tracker.clone();
    let builder: Box<dyn BuildService> = Box::new(move |a| {
      Http3ChainService::new(a, st_clone.clone())
    });
    let service_builders = HashMap::from([("http3_chain", builder)]);
    Self {
      service_builders,
      stream_tracker,
      is_uninstalled: Rc::new(AtomicBool::new(false)),
    }
  }

  async fn do_graceful_shutdown(
    stream_tracker: &Rc<StreamTracker>,
  ) {
    stream_tracker.shutdown();
    info!("Http3ChainPlugin: shutdown notification sent");
    stream_tracker.wait_shutdown().await;
    info!("Http3ChainPlugin: all streams completed");
  }
}

impl Plugin for Http3ChainPlugin {
  fn service_builder(
    &self,
    name: &str,
  ) -> Option<&Box<dyn BuildService>> {
    self.service_builders.get(name)
  }

  fn uninstall(&self) -> Pin<Box<dyn Future<Output = ()>>> {
    if self.is_uninstalled.load(Ordering::SeqCst) {
      info!("Http3ChainPlugin: already uninstalled, skipping");
      return Box::pin(async {});
    }
    self.is_uninstalled.store(true, Ordering::SeqCst);

    let initial_stream_count = self.stream_tracker.active_count();
    let stream_tracker = self.stream_tracker.clone();

    Box::pin(async move {
      info!("Http3ChainPlugin: starting graceful shutdown");

      let shutdown_result = tokio::time::timeout(
        SHUTDOWN_TIMEOUT,
        Self::do_graceful_shutdown(&stream_tracker),
      )
      .await;

      match shutdown_result {
        Ok(()) => {
          info!("Http3ChainPlugin: graceful shutdown completed");
        }
        Err(_) => {
          warn!(
            "Http3ChainPlugin: shutdown timeout reached after {:?}, \
             forcefully aborting remaining tasks: {} streams",
            SHUTDOWN_TIMEOUT, initial_stream_count
          );
          stream_tracker.abort_all();
          stream_tracker.drain().await;
          info!("Http3ChainPlugin: forced shutdown completed");
        }
      }

      // Shutdown upstream thread
      let mut th_guard = UPSTREAM_THREAD_HANDLE.lock().unwrap();
      if let Some(mut handle) = th_guard.take() {
        // Send shutdown signal and drop tx
        let _ = handle.shutdown_tx.try_send(());
        drop(handle.shutdown_tx);

        // Join upstream thread
        if let Some(jh) = handle.join_handle.take() {
          let _ = jh.join();
          info!("Http3ChainPlugin: upstream maintenance thread joined");
        }
      }

      // Close all QUIC connections gracefully
      let mut reg_guard = UPSTREAM_REGISTRY.lock().unwrap();
      if let Some(ref registry) = *reg_guard {
        let mut closed = 0usize;
        for proxy_arc in registry.pool.values() {
          if let Ok(proxy) = proxy_arc.try_lock() {
            if let Some(ref conn) = proxy.quinn_conn {
              UpstreamConnection::new(conn.clone()).close();
              closed += 1;
            }
          }
        }
        info!("Http3ChainPlugin: closed {} upstream pool connections", closed);
      }
      // Clear entire registry, dropping all connection references
      *reg_guard = None;
    })
  }
}

pub fn plugin_name() -> &'static str {
  "http3_chain"
}

pub fn create_plugin(config: Option<&SerializedArgs>) -> Box<dyn Plugin> {
  // Parse plugin config and initialize upstream registry
  if let Some(config_value) = config {
    let plugin_config: Http3ChainPluginConfig =
      serde_yaml::from_value(config_value.clone())
        .unwrap_or_else(|e| panic!("http3_chain: failed to parse plugin config: {}", e));
    init_upstream_registry(&plugin_config)
      .unwrap_or_else(|e| panic!("http3_chain: failed to initialize upstream registry: {}", e));
  }
  Box::new(Http3ChainPlugin::new())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
  use std::cell::RefCell;
  use std::future::pending;

  use super::*;
  use crate::plugin::Plugin;

  // ============== ClientTlsConfig Tests ==============

  #[test]
  fn test_client_tls_config_deserialize_empty() {
    let yaml = r#"{}"#;
    let config: ClientTlsConfig = serde_yaml::from_str(yaml).unwrap();
    assert!(config.client_cert_path.is_none());
    assert!(config.client_key_path.is_none());
    assert!(config.server_ca_path.is_none());
  }

  #[test]
  fn test_client_tls_config_deserialize_with_server_ca_path() {
    let yaml = r#"
server_ca_path: /path/to/ca.pem
"#;
    let config: ClientTlsConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(
      config.server_ca_path,
      Some("/path/to/ca.pem".to_string())
    );
    assert!(config.client_cert_path.is_none());
  }

  #[test]
  fn test_client_tls_config_validate_cert_without_key_is_error() {
    let config = ClientTlsConfig {
      client_cert_path: Some("/path/to/cert.pem".to_string()),
      client_key_path: None,
      server_ca_path: None,
    };
    assert!(config.validate_if_non_empty().is_err());
  }

  #[test]
  fn test_user_password_credential_none() {
    let cred = UserPasswordCredential::none();
    assert!(cred.user.is_none());
  }

  #[test]
  fn test_user_password_credential_apply() {
    let cred = UserPasswordCredential {
      user: Some(UserCredential {
        username: "admin".to_string(),
        password: "secret".to_string(),
      }),
    };
    assert!(cred.user.is_some());
    let mut req = http::Request::builder()
      .method("CONNECT")
      .uri("example.com:443")
      .body(())
      .unwrap();
    cred.apply(&mut req);
    assert!(req.headers().contains_key("Proxy-Authorization"));
  }

  #[test]
  fn test_user_password_credential_apply_none_no_header() {
    let cred = UserPasswordCredential::none();
    let mut req = http::Request::builder()
      .method("CONNECT")
      .uri("example.com:443")
      .body(())
      .unwrap();
    cred.apply(&mut req);
    assert!(!req.headers().contains_key("Proxy-Authorization"));
  }

  #[test]
  fn test_client_cert_credential_none() {
    let cred = ClientCertCredential::none();
    assert!(cred.cert_path.is_none());
    assert!(cred.key_path.is_none());
  }

  // ============== deep_merge Tests ==============

  #[test]
  fn test_deep_merge_proxy_overrides_default_server_ca() {
    let default_tls = ClientTlsConfig {
      client_cert_path: None,
      client_key_path: None,
      server_ca_path: Some("/default/ca.pem".to_string()),
    };
    let proxy_tls = ClientTlsConfig {
      client_cert_path: None,
      client_key_path: None,
      server_ca_path: Some("/proxy/ca.pem".to_string()),
    };
    let merged = proxy_tls.deep_merge(&default_tls);
    assert_eq!(
      merged.server_ca_path,
      Some("/proxy/ca.pem".to_string())
    );
  }

  #[test]
  fn test_deep_merge_inherits_all_from_default() {
    let default_tls = ClientTlsConfig {
      client_cert_path: Some("/default/cert.pem".to_string()),
      client_key_path: Some("/default/key.pem".to_string()),
      server_ca_path: Some("/default/ca.pem".to_string()),
    };
    let proxy_tls = ClientTlsConfig {
      client_cert_path: None,
      client_key_path: None,
      server_ca_path: None,
    };
    let merged = proxy_tls.deep_merge(&default_tls);
    assert_eq!(
      merged.client_cert_path,
      Some("/default/cert.pem".to_string())
    );
    assert_eq!(
      merged.client_key_path,
      Some("/default/key.pem".to_string())
    );
    assert_eq!(
      merged.server_ca_path,
      Some("/default/ca.pem".to_string())
    );
  }

  #[test]
  fn test_deep_merge_proxy_overrides_all() {
    let default_tls = ClientTlsConfig {
      client_cert_path: Some("/default/cert.pem".to_string()),
      client_key_path: Some("/default/key.pem".to_string()),
      server_ca_path: Some("/default/ca.pem".to_string()),
    };
    let proxy_tls = ClientTlsConfig {
      client_cert_path: Some("/proxy/cert.pem".to_string()),
      client_key_path: Some("/proxy/key.pem".to_string()),
      server_ca_path: Some("/proxy/ca.pem".to_string()),
    };
    let merged = proxy_tls.deep_merge(&default_tls);
    assert_eq!(
      merged.client_cert_path,
      Some("/proxy/cert.pem".to_string())
    );
    assert_eq!(
      merged.client_key_path,
      Some("/proxy/key.pem".to_string())
    );
    assert_eq!(
      merged.server_ca_path,
      Some("/proxy/ca.pem".to_string())
    );
  }

  // ============== Three-level Config Resolution Tests ==============

  #[test]
  fn test_plugin_config_deserialize() {
    let yaml = r#"
upstreams:
  - name: hk_relay
    addresses:
      - address: "hk.fwcoding.tech:8443"
        hostname: "hk.fwcoding.tech"
        weight: 1
max_idle_timeout: "5m"
user:
  username: "np_proxy"
  password: "Tj4nW8bF3yHc"
tls:
  client_cert_path: "conf/certs/client.crt"
  client_key_path: "conf/certs/client.key"
  server_ca_path: "conf/certs/server-ca.crt"
"#;
    let config: Http3ChainPluginConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.upstreams.len(), 1);
    assert_eq!(config.upstreams[0].name, "hk_relay");
    assert_eq!(config.upstreams[0].addresses.len(), 1);
    assert_eq!(config.upstreams[0].addresses[0].address, "hk.fwcoding.tech:8443");
    assert!(config.max_idle_timeout.is_some());
    assert!(config.user.is_some());
    assert!(config.tls.is_some());
  }

  #[test]
  fn test_resolve_three_level_plugin_only() {
    let config = Http3ChainPluginConfig {
      upstreams: vec![UpstreamConfig {
        name: "test".into(),
        addresses: vec![UpstreamAddressConfig {
          address: "127.0.0.1:443".into(),
          hostname: Some("test.example.com".into()),
          weight: 1,
          max_idle_timeout: None,
          quic: None,
          user: None,
          tls: None,
        }],
        max_idle_timeout: None,
        quic: None,
        user: None,
        tls: None,
      }],
      max_idle_timeout: Some(Duration::from_secs(300)),
      quic: None,
      user: Some(UserCredential {
        username: "plugin_user".into(),
        password: "plugin_pass".into(),
      }),
      tls: Some(ClientTlsConfig {
        server_ca_path: Some("/plugin/ca.pem".into()),
        ..Default::default()
      }),
    };

    let resolved = resolve_three_level(&config).unwrap();
    let upstream = resolved.get("test").unwrap();
    assert_eq!(upstream.addresses.len(), 1);
    let addr = &upstream.addresses[0];
    assert_eq!(addr.max_idle_timeout, Duration::from_secs(300));
    assert!(addr.user_password_credential.user.is_some());
    assert_eq!(addr.server_ca_path, Some("/plugin/ca.pem".into()));
  }

  #[test]
  fn test_resolve_three_level_address_override() {
    let config = Http3ChainPluginConfig {
      upstreams: vec![UpstreamConfig {
        name: "test".into(),
        addresses: vec![UpstreamAddressConfig {
          address: "127.0.0.1:443".into(),
          hostname: Some("test.example.com".into()),
          weight: 1,
          max_idle_timeout: Some(Duration::from_secs(60)),
          quic: None,
          user: Some(UserCredential {
            username: "addr_user".into(),
            password: "addr_pass".into(),
          }),
          tls: None,
        }],
        max_idle_timeout: Some(Duration::from_secs(120)),
        quic: None,
        user: Some(UserCredential {
          username: "upstream_user".into(),
          password: "upstream_pass".into(),
        }),
        tls: None,
      }],
      max_idle_timeout: Some(Duration::from_secs(300)),
      quic: None,
      user: Some(UserCredential {
        username: "plugin_user".into(),
        password: "plugin_pass".into(),
      }),
      tls: None,
    };

    let resolved = resolve_three_level(&config).unwrap();
    let addr = &resolved.get("test").unwrap().addresses[0];
    // Address-level overrides upstream and plugin
    assert_eq!(addr.max_idle_timeout, Duration::from_secs(60));
    let user = addr.user_password_credential.user.as_ref().unwrap();
    assert_eq!(user.username, "addr_user");
  }

  #[test]
  fn test_resolve_three_level_upstream_override() {
    let config = Http3ChainPluginConfig {
      upstreams: vec![UpstreamConfig {
        name: "test".into(),
        addresses: vec![UpstreamAddressConfig {
          address: "127.0.0.1:443".into(),
          hostname: Some("test.example.com".into()),
          weight: 1,
          max_idle_timeout: None, // inherit from upstream
          quic: None,
          user: None, // inherit from upstream
          tls: None,
        }],
        max_idle_timeout: Some(Duration::from_secs(120)),
        quic: None,
        user: Some(UserCredential {
          username: "upstream_user".into(),
          password: "upstream_pass".into(),
        }),
        tls: None,
      }],
      max_idle_timeout: Some(Duration::from_secs(300)),
      quic: None,
      user: None,
      tls: None,
    };

    let resolved = resolve_three_level(&config).unwrap();
    let addr = &resolved.get("test").unwrap().addresses[0];
    // Inherits from upstream level
    assert_eq!(addr.max_idle_timeout, Duration::from_secs(120));
    let user = addr.user_password_credential.user.as_ref().unwrap();
    assert_eq!(user.username, "upstream_user");
  }

  #[test]
  fn test_resolve_three_level_inherits_default_idle_timeout() {
    let config = Http3ChainPluginConfig {
      upstreams: vec![UpstreamConfig {
        name: "test".into(),
        addresses: vec![UpstreamAddressConfig {
          address: "127.0.0.1:443".into(),
          hostname: Some("test.example.com".into()),
          weight: 1,
          max_idle_timeout: None,
          quic: None,
          user: None,
          tls: None,
        }],
        max_idle_timeout: None,
        quic: None,
        user: None,
        tls: None,
      }],
      ..Default::default()
    };

    let resolved = resolve_three_level(&config).unwrap();
    let addr = &resolved.get("test").unwrap().addresses[0];
    assert_eq!(addr.max_idle_timeout, default_idle_timeout());
  }

  // ============== Http3ChainServiceArgs Tests ==============

  #[test]
  fn test_service_args_deserialize() {
    let yaml = r#"
upstream: hk_relay
"#;
    let args: Http3ChainServiceArgs = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(args.upstream, "hk_relay");
  }

  #[test]
  fn test_service_args_empty_upstream_fails() {
    let args = Http3ChainServiceArgs { upstream: "".into() };
    assert!(args.validate().is_err());
  }

  // ============== WRR Tests ==============

  #[test]
  fn test_schedule_wrr_single() {
    let mut addresses = vec![ResolvedAddress {
      address: "127.0.0.1:8080".into(),
      hostname: Some("proxy.example.com".into()),
      weight: 1,
      current_weight: 0,
      max_idle_timeout: Duration::from_secs(300),
      quic: QuicResolved {
        keep_alive_interval: Duration::from_secs(3),
        max_idle_timeout: None,
      },
      user_password_credential: UserPasswordCredential::none(),
      client_cert_credential: ClientCertCredential::none(),
      server_ca_path: None,
    }];
    assert_eq!(schedule_wrr(&mut addresses), Some(0));
  }

  #[test]
  fn test_schedule_wrr_two_proxies_weight_2_to_1() {
    let mut addresses = vec![
      ResolvedAddress {
        address: "127.0.0.1:8080".into(),
        hostname: Some("p1.example.com".into()),
        weight: 2,
        current_weight: 0,
        max_idle_timeout: Duration::from_secs(300),
        quic: QuicResolved {
          keep_alive_interval: Duration::from_secs(3),
          max_idle_timeout: None,
        },
        user_password_credential: UserPasswordCredential::none(),
        client_cert_credential: ClientCertCredential::none(),
        server_ca_path: None,
      },
      ResolvedAddress {
        address: "127.0.0.1:8081".into(),
        hostname: Some("p2.example.com".into()),
        weight: 1,
        current_weight: 0,
        max_idle_timeout: Duration::from_secs(300),
        quic: QuicResolved {
          keep_alive_interval: Duration::from_secs(3),
          max_idle_timeout: None,
        },
        user_password_credential: UserPasswordCredential::none(),
        client_cert_credential: ClientCertCredential::none(),
        server_ca_path: None,
      },
    ];

    let selections: Vec<usize> =
      (0..6).map(|_| schedule_wrr(&mut addresses).unwrap()).collect();

    let count_0 = selections.iter().filter(|&&x| x == 0).count();
    let count_1 = selections.iter().filter(|&&x| x == 1).count();
    assert_eq!(count_0, 4);
    assert_eq!(count_1, 2);
  }

  #[test]
  fn test_schedule_wrr_empty_returns_none() {
    let mut addresses: Vec<ResolvedAddress> = vec![];
    assert_eq!(schedule_wrr(&mut addresses), None);
  }

  // ============== Address Resolution Tests ==============

  #[test]
  fn test_resolve_address_ip_port() {
    let addr = resolve_address("127.0.0.1:8080").unwrap();
    assert_eq!(addr, "127.0.0.1:8080".parse().unwrap());
  }

  #[test]
  fn test_resolve_address_localhost() {
    let addr = resolve_address("localhost:8080").unwrap();
    assert!(addr.is_ipv4() || addr.is_ipv6());
    assert_eq!(addr.port(), 8080);
  }

  #[test]
  fn test_resolve_address_unresolvable_fails() {
    let result = resolve_address("this.host.does.not.exist.invalid:8080");
    assert!(result.is_err());
  }

  #[test]
  fn test_resolve_address_missing_port_fails() {
    let result = resolve_address("127.0.0.1");
    assert!(result.is_err());
  }

  #[test]
  fn test_resolve_address_garbage_fails() {
    let result = resolve_address("not-a-valid-address");
    assert!(result.is_err());
  }

  // ============== Response Builder Tests ==============

  #[test]
  fn test_build_empty_response_ok() {
    let resp = build_empty_response(http::StatusCode::OK);
    assert_eq!(resp.status(), http::StatusCode::OK);
  }

  #[test]
  fn test_build_empty_response_bad_gateway() {
    let resp = build_empty_response(http::StatusCode::BAD_GATEWAY);
    assert_eq!(resp.status(), http::StatusCode::BAD_GATEWAY);
  }

  #[test]
  fn test_build_empty_response_service_unavailable() {
    let resp =
      build_empty_response(http::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(resp.status(), http::StatusCode::SERVICE_UNAVAILABLE);
  }

  #[test]
  fn test_build_error_response_method_not_allowed() {
    let resp = build_error_response(
      http::StatusCode::METHOD_NOT_ALLOWED,
      "Only CONNECT method is supported",
    );
    assert_eq!(resp.status(), http::StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(
      resp.headers().get(http::header::CONTENT_TYPE).unwrap(),
      "text/plain"
    );
  }

  #[test]
  fn test_build_tunnel_response() {
    let resp = build_tunnel_response();
    assert_eq!(resp.status(), http::StatusCode::OK);
  }

  // ============== CONNECT Validation Tests ==============

  #[test]
  fn test_non_connect_method_produces_405() {
    let req = http::Request::builder()
      .method(http::Method::GET)
      .uri("http://example.com/")
      .body(())
      .unwrap();
    let (parts, _) = req.into_parts();
    let result = utils::parse_connect_target(&parts);
    assert!(matches!(
      result,
      Err(ConnectTargetError::NotConnectMethod)
    ));
  }

  #[test]
  fn test_connect_missing_port_produces_400() {
    let req = http::Request::builder()
      .method(http::Method::CONNECT)
      .uri("example.com")
      .body(())
      .unwrap();
    let (parts, _) = req.into_parts();
    let result = utils::parse_connect_target(&parts);
    assert!(matches!(
      result,
      Err(ConnectTargetError::NoAuthority)
        | Err(ConnectTargetError::NoPort)
    ));
  }

  #[test]
  fn test_connect_port_zero_produces_400() {
    let req = http::Request::builder()
      .method(http::Method::CONNECT)
      .uri("example.com:0")
      .body(())
      .unwrap();
    let (parts, _) = req.into_parts();
    let result = utils::parse_connect_target(&parts);
    assert!(matches!(result, Err(ConnectTargetError::PortZero)));
  }

  // ============== RequestContext Integration Tests ==============

  #[test]
  fn test_request_context_insert_and_get_roundtrip() {
    use crate::context::RequestContext;

    let ctx = RequestContext::new();
    ctx.insert("http3_chain.connect_ms", "42".to_string());
    let connect_ms =
      ctx.get("http3_chain.connect_ms").unwrap();
    assert_eq!(connect_ms, "42");
  }

  // ============== Plugin Tests ==============

  #[test]
  fn test_plugin_new() {
    let plugin = Http3ChainPlugin::new();
    assert!(plugin.service_builder("http3_chain").is_some());
    assert!(plugin.service_builder("nonexistent").is_none());
  }

  #[test]
  fn test_create_plugin_no_config() {
    let plugin = create_plugin(None);
    assert!(plugin.service_builder("http3_chain").is_some());
  }

  #[tokio::test]
  async fn test_uninstall_empty_plugin() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let plugin = Http3ChainPlugin::new();

        let result = tokio::time::timeout(
          Duration::from_millis(100),
          plugin.uninstall(),
        )
        .await;
        assert!(
          result.is_ok(),
          "Uninstall should complete quickly with no streams"
        );
      })
      .await;
  }

  #[tokio::test]
  async fn test_uninstall_with_pending_stream() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let plugin = Http3ChainPlugin::new();

        plugin.stream_tracker.register(async {
          pending::<()>().await;
        });

        tokio::task::yield_now().await;

        let start = std::time::Instant::now();
        plugin.uninstall().await;
        let elapsed = start.elapsed();

        assert!(
          elapsed >= SHUTDOWN_TIMEOUT,
          "Uninstall should wait for timeout"
        );
        assert!(
          elapsed < SHUTDOWN_TIMEOUT + Duration::from_millis(500),
          "Uninstall should not take much longer than timeout"
        );

        assert_eq!(plugin.stream_tracker.active_count(), 0);
      })
      .await;
  }

  #[tokio::test]
  async fn test_uninstall_with_completing_stream() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let plugin = Http3ChainPlugin::new();

        let completed = Rc::new(RefCell::new(false));
        let completed_clone = completed.clone();

        plugin.stream_tracker.register(async move {
          tokio::time::sleep(Duration::from_millis(10)).await;
          completed_clone.replace(true);
        });

        tokio::task::yield_now().await;

        let start = std::time::Instant::now();
        plugin.uninstall().await;
        let elapsed = start.elapsed();

        assert!(
          elapsed < SHUTDOWN_TIMEOUT,
          "Uninstall should complete before timeout"
        );
        assert!(*completed.borrow(), "Stream should have completed");
      })
      .await;
  }

  #[tokio::test]
  async fn test_uninstall_multiple_times() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let plugin = Http3ChainPlugin::new();
        plugin.uninstall().await;
        plugin.uninstall().await;
        plugin.uninstall().await;
      })
      .await;
  }

  // ============== Service Args Rejects Unknown Fields ==============

  #[test]
  fn test_service_args_rejects_unknown_fields() {
    let yaml = r#"
upstream: hk_relay
old_field: value
"#;
    let result: Result<Http3ChainServiceArgs, _> =
      serde_yaml::from_str(yaml);
    assert!(result.is_err(), "Should reject unknown fields");
  }

  // ============== Plugin Config Rejects Unknown Fields ==============

  #[test]
  fn test_plugin_config_rejects_unknown_fields() {
    let yaml = r#"
upstreams:
  - name: hk_relay
    addresses:
      - address: "hk.fwcoding.tech:8443"
        hostname: "hk.fwcoding.tech"
        weight: 1
old_field: value
"#;
    let result: Result<Http3ChainPluginConfig, _> =
      serde_yaml::from_str(yaml);
    assert!(result.is_err(), "Should reject unknown fields");
  }

  // ============== Resolve Address Validation ==============

  #[test]
  fn test_resolve_three_level_invalid_address_fails() {
    let config = Http3ChainPluginConfig {
      upstreams: vec![UpstreamConfig {
        name: "test".into(),
        addresses: vec![UpstreamAddressConfig {
          address: "not-a-valid-address".into(),
          hostname: None,
          weight: 1,
          max_idle_timeout: None,
          quic: None,
          user: None,
          tls: None,
        }],
        max_idle_timeout: None,
        quic: None,
        user: None,
        tls: None,
      }],
      ..Default::default()
    };

    let result = resolve_three_level(&config);
    assert!(result.is_err());
  }
}
