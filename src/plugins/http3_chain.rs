use std::cell::RefCell;
use std::collections::HashMap;
use std::future::{self, Future};
use std::net::SocketAddr;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::Mutex;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use std::{fs, path};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use bytes::Bytes;
use h3::client as h3_cli;
use hyper_util::rt::TokioIo;
use rustls::pki_types::CertificateDer;
use rustls_native_certs::CertificateResult;
use rustls_pemfile;
use serde::Deserialize;
use tokio::task;
use tracing::{error, info, warn};

use crate::auth::UserCredential;
use crate::connect_utils::{self as utils, ConnectTargetError};
use crate::h3_stream::H3ClientBidiStream;
use crate::plugin;
use crate::plugin::ClientStream;
use crate::shutdown::StreamTracker;

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
/// See: https://www.rfc-editor.org/rfc/rfc9114.html#errors
/// Value 0x100 = 256, which fits in u32
const H3_NO_ERROR_CODE: u32 = 0x100;

// ============================================================================
// Active Connection Management
// ============================================================================

/// An active QUIC connection that can be closed gracefully.
/// This struct holds a reference to the underlying quinn::Connection
/// so that we can send CONNECTION_CLOSE frames during shutdown.
struct ActiveConnection {
  /// The underlying QUIC connection
  conn: quinn::Connection,
}

impl ActiveConnection {
  fn new(conn: quinn::Connection) -> Self {
    Self { conn }
  }

  /// Close the connection with H3_NO_ERROR code
  fn close(&self) {
    self.conn.close(
      quinn::VarInt::from_u32(H3_NO_ERROR_CODE),
      b"graceful shutdown",
    );
  }
}

/// Tracker for active QUIC connections.
///
/// This allows us to close all connections gracefully during shutdown.
/// The tracker maintains references to all active connections so they can
/// be properly closed with H3_NO_ERROR during graceful shutdown.
///
/// # Usage Pattern
///
/// The typical lifecycle is:
/// 1. `register()` - Add a new connection when established
/// 2. `close_all()` then `clear()` - During shutdown, close all then clear the tracker
///
/// # Important
///
/// Always call `close_all()` before `clear()`. Calling `clear()` without `close_all()`
/// will leave connections open but untracked, potentially causing resource leaks.
#[derive(Clone, Default)]
struct ActiveConnectionTracker {
  connections: Rc<RefCell<Vec<ActiveConnection>>>,
}

impl ActiveConnectionTracker {
  fn new() -> Self {
    Self::default()
  }

  /// Register a new active connection.
  ///
  /// Call this when a new QUIC connection is successfully established.
  fn register(&self, conn: quinn::Connection) {
    self.connections.borrow_mut().push(ActiveConnection::new(conn));
  }

  /// Close all registered connections with H3_NO_ERROR.
  ///
  /// Sends CONNECTION_CLOSE frames to all tracked connections.
  /// After calling this, the connections are still tracked but will be
  /// closed by the QUIC layer. Call `clear()` to remove the references.
  ///
  /// **Important**: Call this before `clear()` to ensure graceful shutdown.
  fn close_all(&self) {
    let connections = self.connections.borrow();
    for conn in connections.iter() {
      conn.close();
    }
    info!(
      "ActiveConnectionTracker: closed {} connections",
      connections.len()
    );
  }

  /// Get the count of active connections.
  fn count(&self) -> usize {
    self.connections.borrow().len()
  }

  /// Clear all connection references.
  ///
  /// **Important**: Call `close_all()` before this to ensure connections
  /// are gracefully closed. Calling `clear()` alone does NOT close the
  /// connections - it only removes them from tracking.
  fn clear(&self) {
    self.connections.borrow_mut().clear();
  }
}

// ============================================================================
// Client Credential Configuration Types
// ============================================================================

/// Client credential configuration for http3_chain.
#[derive(Deserialize, Clone, Debug, Default)]
struct ClientCredentialConfig {
  #[serde(default)]
  user: Option<UserCredential>,
  #[serde(default)]
  client_cert_path: Option<String>,
  #[serde(default)]
  client_key_path: Option<String>,
  #[serde(default)]
  server_ca_path: Option<String>,
}

impl ClientCredentialConfig {
  fn validate_if_non_empty(&self) -> Result<()> {
    let has_cert = self.client_cert_path.is_some();
    let has_key = self.client_key_path.is_some();
    if has_cert != has_key {
      bail!(
        "client_cert_path and client_key_path must both be present or both absent"
      );
    }
    Ok(())
  }

  fn is_empty(&self) -> bool {
    self.user.is_none()
      && self.client_cert_path.is_none()
      && self.client_key_path.is_none()
      && self.server_ca_path.is_none()
  }

  /// Deep merge with a default credential.
  /// Fields in `self` take priority; missing fields are inherited from `default`.
  fn deep_merge(&self, default: &ClientCredentialConfig) -> ClientCredentialConfig {
    ClientCredentialConfig {
      user: self.user.clone().or_else(|| default.user.clone()),
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
        // Load cert chain and key, build with_client_auth_cert
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

struct Proxy {
  address: SocketAddr,
  conn_handle: Option<task::JoinHandle<Result<()>>>,
  requester: Option<h3_cli::SendRequest<h3_quinn::OpenStreams, Bytes>>,
  weight: usize,
  current_weight: isize,
  user_password_credential: UserPasswordCredential,
  client_cert_credential: ClientCertCredential,
  server_ca_path: Option<String>,
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

struct ProxyGroup {
  proxies: Vec<Proxy>,
}

impl ProxyGroup {
  fn new(
    addresses: Vec<(
      SocketAddr,
      usize,
      UserPasswordCredential,
      ClientCertCredential,
      Option<String>,
    )>,
  ) -> Self {
    let mut proxies = vec![];
    for (addr, weight, upc, ccc, server_ca) in addresses {
      proxies.push(Proxy {
        address: addr,
        conn_handle: None,
        requester: None,
        weight,
        current_weight: 0,
        user_password_credential: upc,
        client_cert_credential: ccc,
        server_ca_path: server_ca,
      });
    }
    Self { proxies }
  }

  fn schedule_wrr(&mut self) -> usize {
    let total =
      self.proxies.iter().fold(0, |t, p| t + p.weight) as isize;
    let mut selected_idx = 0usize;
    let mut selected_weight = 0isize;
    for (i, p) in self.proxies.iter_mut().enumerate() {
      p.current_weight += p.weight as isize;
      if p.current_weight > selected_weight {
        selected_weight = p.current_weight;
        selected_idx = i;
      }
    }

    self.proxies[selected_idx].current_weight -= total;
    selected_idx
  }

  /// Establish a new QUIC connection with specific credentials
  async fn new_proxy_conn_with_credentials(
    &self,
    proxy_idx: usize,
    client_cert_credential: &ClientCertCredential,
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

    // Load custom CA certificate if provided (per-proxy)
    if let Some(ref ca_path_str) = self.proxies[proxy_idx].server_ca_path {
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

    // Build TLS config based on credentials
    let mut tls_config =
      build_tls_client_config(roots, client_cert_credential)?;

    // Apply common configuration
    tls_config.enable_early_data = true;
    tls_config.alpn_protocols = vec![ALPN.into()];
    tls_config.key_log = Arc::new(rustls::KeyLogFile::new());

    let mut cli_endpoint =
      quinn::Endpoint::client("[::]:0".parse().unwrap())?;

    let cli_config = quinn::ClientConfig::new(Arc::new(
      quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)?,
    ));
    cli_endpoint.set_default_client_config(cli_config);

    let addr = self.proxies[proxy_idx].address;
    // Use IP address as server name for TLS (without port)
    let host = addr.ip().to_string();
    let conn = cli_endpoint.connect(addr, host.as_str())?.await?;

    info!("QUIC connection established");
    Ok(conn)
  }

  async fn get_proxy_conn(
    &mut self,
    stream_tracker: &StreamTracker,
    conn_tracker: &ActiveConnectionTracker,
  ) -> Result<(
    h3_cli::SendRequest<h3_quinn::OpenStreams, Bytes>,
    usize,
    UserPasswordCredential,
    ClientCertCredential,
  )> {
    let idx = self.schedule_wrr();
    let proxy = &mut self.proxies[idx];

    // Get credentials for this proxy
    let user_password_credential =
      proxy.user_password_credential.clone();
    let client_cert_credential = proxy.client_cert_credential.clone();

    if let Some(h) = proxy.conn_handle.as_mut() {
      if h.is_finished() {
        match h.await {
          Err(e) => {
            info!(
              "join connection handle of {} failed: {e}",
              proxy.address
            );
          }
          Ok(res) => {
            if let Err(e) = res {
              info!("connection of {} finished: {e}", proxy.address);
            }
          }
        }
      } else {
        return Ok((
          proxy.requester.as_ref().unwrap().clone(),
          idx,
          user_password_credential,
          client_cert_credential,
        ));
      }
    }

    // Establish new connection with credentials
    let conn = self
      .new_proxy_conn_with_credentials(idx, &client_cert_credential)
      .await?;
    conn_tracker.register(conn.clone());
    let (h3_conn, requester) =
      h3::client::new(h3_quinn::Connection::new(conn)).await?;
    let conn_task = connection_maintaining(h3_conn);
    stream_tracker.register_connection(async move {
      let _ = conn_task.await;
    });
    let proxy = &mut self.proxies[idx];
    let _ = proxy.conn_handle.take();
    let _ = proxy.requester.insert(requester.clone());
    Ok((
      requester,
      idx,
      user_password_credential,
      client_cert_credential,
    ))
  }
}

fn build_empty_response(
  status_code: http::StatusCode,
) -> plugin::Response {
  let empty = http_body_util::Empty::new();
  let bytes_buf = plugin::BytesBufBodyWrapper::new(empty);
  let body = plugin::ResponseBody::new(bytes_buf);
  let mut resp = plugin::Response::new(body);
  *resp.status_mut() = status_code;
  resp
}

fn build_error_response(
  status_code: http::StatusCode,
  message: &str,
) -> plugin::Response {
  let full = http_body_util::Full::new(bytes::Bytes::from(message.to_string()));
  let bytes_buf = plugin::BytesBufBodyWrapper::new(full);
  let body = plugin::ResponseBody::new(bytes_buf);
  let mut resp = plugin::Response::new(body);
  *resp.status_mut() = status_code;
  resp.headers_mut().insert(
    http::header::CONTENT_TYPE,
    http::header::HeaderValue::from_static("text/plain"),
  );
  resp
}

/// Build a 200 OK tunnel response with ServiceMetrics attached.
///
/// Extracted to enable unit testing of the metrics insertion logic.
fn build_tunnel_response_with_metrics(
  connect_ms: u64,
) -> plugin::Response {
  let mut resp = build_empty_response(http::StatusCode::OK);
  let mut metrics = crate::access_log::ServiceMetrics::new();
  metrics.add("connect_ms", connect_ms);
  resp.extensions_mut().insert(metrics);
  resp
}

// ============================================================================
// HTTP/3 Chain Service Configuration
// ============================================================================

#[derive(Deserialize, Default, Clone, Debug)]
struct Http3ChainServiceArgsProxyGroup {
  address: String,
  weight: usize,
  #[serde(default)]
  credential: Option<ClientCredentialConfig>,
}

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(deny_unknown_fields)]
struct Http3ChainServiceArgs {
  proxy_group: Vec<Http3ChainServiceArgsProxyGroup>,
  #[serde(default)]
  default_credential: Option<ClientCredentialConfig>,
}

impl Http3ChainServiceArgs {
  fn validate(&self) -> Result<()> {
    if self.proxy_group.is_empty() {
      bail!("proxy_group cannot be empty");
    }
    for (idx, proxy) in self.proxy_group.iter().enumerate() {
      if proxy.weight == 0 {
        bail!("proxy_group[{}].weight must be > 0", idx);
      }
      if let Some(ref cred) = proxy.credential {
        cred.validate_if_non_empty().with_context(|| {
          format!("proxy_group[{}].credential", idx)
        })?;
      }
    }
    if let Some(ref default_cred) = self.default_credential {
      default_cred
        .validate_if_non_empty()
        .context("default_credential")?;
    }
    Ok(())
  }

  fn resolve_credential(
    &self,
    proxy_credential: &Option<ClientCredentialConfig>,
  ) -> (UserPasswordCredential, ClientCertCredential, Option<String>) {
    let effective = match (proxy_credential, &self.default_credential) {
      // If proxy credential is explicitly set but empty, it means "no auth credential"
      // - user and client_cert are NOT inherited from default_credential
      // - but server_ca_path IS inherited for TLS verification
      (Some(proxy), Some(default)) if proxy.is_empty() => {
        Some(ClientCredentialConfig {
          user: None,
          client_cert_path: None,
          client_key_path: None,
          server_ca_path: default.server_ca_path.clone(),
        })
      }
      (Some(proxy), None) if proxy.is_empty() => None,
      // Normal merge/inherit cases
      (Some(proxy), Some(default)) => Some(proxy.deep_merge(default)),
      (Some(proxy), None) => Some(proxy.clone()),
      (None, Some(default)) => Some(default.clone()),
      (None, None) => None,
    };

    match effective {
      None => {
        (UserPasswordCredential::none(), ClientCertCredential::none(), None)
      }
      Some(config) => {
        let upc = match &config.user {
          Some(user) => {
            UserPasswordCredential { user: Some(user.clone()) }
          }
          None => UserPasswordCredential::none(),
        };
        let ccc =
          match (&config.client_cert_path, &config.client_key_path) {
            (Some(cert), Some(key)) => ClientCertCredential {
              cert_path: Some(cert.into()),
              key_path: Some(key.into()),
            },
            _ => ClientCertCredential::none(),
          };
        let server_ca = config.server_ca_path.clone();
        (upc, ccc, server_ca)
      }
    }
  }
}

#[derive(Clone)]
struct Http3ChainService {
  proxy_group: Arc<Mutex<ProxyGroup>>,
  stream_tracker: Rc<StreamTracker>,
  conn_tracker: ActiveConnectionTracker,
}

impl Http3ChainService {
  #[allow(clippy::new_ret_no_self)]
  fn new(
    sargs: plugin::SerializedArgs,
    stream_tracker: Rc<StreamTracker>,
    conn_tracker: ActiveConnectionTracker,
  ) -> Result<plugin::Service> {
    let args: Http3ChainServiceArgs = serde_yaml::from_value(sargs)?;
    args.validate()?;

    // Resolve credentials for each proxy
    let proxy_addresses: Vec<(
      SocketAddr,
      usize,
      UserPasswordCredential,
      ClientCertCredential,
      Option<String>,
    )> = args
      .proxy_group
      .iter()
      .filter_map(|e| {
        let Http3ChainServiceArgsProxyGroup {
          address: s,
          weight: w,
          credential,
        } = e;

        let (upc, ccc, server_ca) = args.resolve_credential(credential);

        s.parse()
          .inspect_err(|e| error!("address '{s}' invalid: {e}"))
          .ok()
          .map(|a| (a, *w, upc, ccc, server_ca))
      })
      .collect();

    let proxy_group = ProxyGroup::new(proxy_addresses);

    Ok(plugin::Service::new(Self {
      proxy_group: Arc::new(Mutex::new(proxy_group)),
      stream_tracker,
      conn_tracker,
    }))
  }

  /// Check if the service is shutting down
  fn is_shutting_down(&self) -> bool {
    self.stream_tracker.shutdown_handle().is_shutdown()
  }
}

impl tower::Service<plugin::Request> for Http3ChainService {
  type Error = anyhow::Error;
  type Future = Pin<Box<dyn Future<Output = Result<plugin::Response>>>>;
  type Response = plugin::Response;

  fn poll_ready(
    &mut self,
    _cx: &mut TaskContext<'_>,
  ) -> Poll<Result<(), Self::Error>> {
    Poll::Ready(Ok(()))
  }

  fn call(&mut self, mut req: plugin::Request) -> Self::Future {
    let pg = self.proxy_group.clone();
    let st = self.stream_tracker.clone();
    let ct = self.conn_tracker.clone();
    let is_shutting_down = self.is_shutting_down();

    // Check for SOCKS5 upgrade
    let socks5_upgrade = plugin::Socks5OnUpgrade::on(&mut req);

    // Check for H3 upgrade
    let h3_upgrade = plugin::H3OnUpgrade::on(&mut req);

    // Check for HTTP upgrade (only if no SOCKS5 and no H3)
    let http_upgrade =
      if socks5_upgrade.is_none() && h3_upgrade.is_none() {
        Some(hyper::upgrade::on(&mut req))
      } else {
        None
      };

    let (req_headers, _req_body) = req.into_parts();

    Box::pin(async move {
      // Check if service is shutting down - reject new requests
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

      // Get proxy connection and credentials
      let (
        requester,
        _proxy_idx,
        user_password_credential,
        _client_cert_credential,
      ) = match pg.lock().await.get_proxy_conn(&st, &ct).await {
        Ok(r) => r,
        Err(e) => {
          warn!(
            "Http3ChainService: failed to connect to next hop proxy: {e}"
          );
          return Ok(build_empty_response(
            http::StatusCode::BAD_GATEWAY,
          ));
        }
      };

      // Send CONNECT request with credentials
      send_connect_and_tunnel_with_credential(
        requester,
        host,
        port,
        &user_password_credential,
        &st,
        socks5_upgrade,
        h3_upgrade,
        http_upgrade,
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
  socks5_upgrade: Option<plugin::Socks5OnUpgrade>,
  h3_upgrade: Option<plugin::H3OnUpgrade>,
  http_upgrade: Option<hyper::upgrade::OnUpgrade>,
) -> Result<plugin::Response> {
  // Build CONNECT request
  let mut proxy_req = http::Request::builder()
    .method(http::Method::CONNECT)
    .uri(format!("{host}:{port}"))
    .body(())?;

  // Add Proxy-Authorization header if credentials are set
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

  // Check for 407 error
  if proxy_resp.status()
    == http::StatusCode::PROXY_AUTHENTICATION_REQUIRED
  {
    return Err(ProxyAuthRequiredError.into());
  }

  if !proxy_resp.status().is_success() {
    return Ok(build_empty_response(proxy_resp.status()));
  }

  // Success - complete the tunnel
  info!("Http3ChainService: CONNECT succeeded, setting up tunnel");
  let (sending_stream, receiving_stream) = proxy_stream.split();
  complete_tunnel(
    sending_stream,
    receiving_stream,
    st,
    socks5_upgrade,
    h3_upgrade,
    http_upgrade,
    proxy_ms,
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
  st: &Rc<StreamTracker>,
  socks5_upgrade: Option<plugin::Socks5OnUpgrade>,
  h3_upgrade: Option<plugin::H3OnUpgrade>,
  http_upgrade: Option<hyper::upgrade::OnUpgrade>,
  connect_ms: u64,
) -> Result<plugin::Response> {
  let resp = build_tunnel_response_with_metrics(connect_ms);
  let shutdown_handle = st.shutdown_handle();

  st.register(async move {
    info!("Http3ChainService: tunnel background task started");

    // Check if shutdown is already triggered
    if shutdown_handle.is_shutdown() {
      warn!("Http3ChainService: shutdown already triggered, aborting tunnel");
      return;
    }

    let client_result: Result<ClientStream, String> =
      if let Some(socks5) = socks5_upgrade {
        info!("Http3ChainService: waiting for SOCKS5 upgrade");
        match socks5.await {
          Ok(stream) => {
            info!("Http3ChainService: SOCKS5 upgrade succeeded");
            Ok(ClientStream::Socks5(stream))
          },
          Err(e) => Err(format!("SOCKS5 upgrade failed: {e}")),
        }
      } else if let Some(h3) = h3_upgrade {
        info!("Http3ChainService: waiting for H3 upgrade");
        match h3.await {
          Ok(stream) => {
            info!("Http3ChainService: H3 upgrade succeeded");
            Ok(ClientStream::H3(stream))
          },
          Err(e) => Err(format!("H3 upgrade failed: {e}")),
        }
      } else if let Some(http) = http_upgrade {
        info!("Http3ChainService: waiting for HTTP upgrade");
        match http.await {
          Ok(upgraded) => {
            info!("Http3ChainService: HTTP upgrade succeeded");
            Ok(ClientStream::Http(TokioIo::new(upgraded)))
          },
          Err(e) => Err(format!("HTTP upgrade failed: {e}")),
        }
      } else {
        warn!("Http3ChainService: no upgrade available for tunnel");
        return;
      };

    let mut client = match client_result {
      Ok(c) => c,
      Err(e) => {
        warn!("Http3ChainService tunnel upgrade failed: {e}");
        return;
      }
    };

    info!("Http3ChainService: client upgrade complete, starting bidirectional transfer");
    let mut h3_stream = H3ClientBidiStream::new(sending_stream, receiving_stream);

    let result = tokio::select! {
      res = tokio::io::copy_bidirectional(&mut client, &mut h3_stream) => res,
      _shutdown = shutdown_handle.notified() => {
        warn!("Http3ChainService tunnel shutdown by notification");
        return;
      }
    };

    if let Err(e) = result {
      warn!("Http3ChainService tunnel transfer error: {e}");
    } else {
      info!("Http3ChainService: bidirectional transfer completed successfully");
    }
  });

  Ok(resp)
}

struct Http3ChainPlugin {
  service_builders:
    HashMap<&'static str, Box<dyn plugin::BuildService>>,
  stream_tracker: Rc<StreamTracker>,
  conn_tracker: ActiveConnectionTracker,
  /// Flag to ensure uninstall is idempotent
  is_uninstalled: Rc<AtomicBool>,
}

impl Http3ChainPlugin {
  fn new() -> Self {
    let stream_tracker = Rc::new(StreamTracker::new());
    let conn_tracker = ActiveConnectionTracker::new();
    let st_clone = stream_tracker.clone();
    let ct_clone = conn_tracker.clone();
    let builder: Box<dyn plugin::BuildService> = Box::new(move |a| {
      Http3ChainService::new(a, st_clone.clone(), ct_clone.clone())
    });
    let service_builders = HashMap::from([("http3_chain", builder)]);
    Self {
      service_builders,
      stream_tracker,
      conn_tracker,
      is_uninstalled: Rc::new(AtomicBool::new(false)),
    }
  }

  /// Perform graceful shutdown of all resources
  ///
  /// This method handles the actual shutdown logic and should be
  /// called within a timeout wrapper to ensure total shutdown time
  /// does not exceed 5 seconds.
  async fn do_graceful_shutdown(
    stream_tracker: &Rc<StreamTracker>,
    conn_tracker: &ActiveConnectionTracker,
  ) {
    // Trigger shutdown notification for streams
    stream_tracker.shutdown();
    info!("Http3ChainPlugin: shutdown notification sent");

    // Wait for all streams to complete
    stream_tracker.wait_shutdown().await;

    info!(
      "Http3ChainPlugin: all streams completed, \
       {} connections remaining",
      conn_tracker.count()
    );
  }
}

impl plugin::Plugin for Http3ChainPlugin {
  fn service_builder(
    &self,
    name: &str,
  ) -> Option<&Box<dyn plugin::BuildService>> {
    self.service_builders.get(name)
  }

  fn uninstall(&mut self) -> Pin<Box<dyn Future<Output = ()>>> {
    // Idempotency check: if already uninstalled, return immediately
    if self.is_uninstalled.load(Ordering::SeqCst) {
      info!("Http3ChainPlugin: already uninstalled, skipping");
      return Box::pin(async {});
    }

    // Mark as uninstalled
    self.is_uninstalled.store(true, Ordering::SeqCst);

    // Record initial counts BEFORE starting shutdown
    // This ensures accurate numbers in timeout logs
    let initial_stream_count = self.stream_tracker.active_count();
    let initial_conn_count = self.conn_tracker.count();

    let stream_tracker = self.stream_tracker.clone();
    let conn_tracker = self.conn_tracker.clone();

    Box::pin(async move {
      info!("Http3ChainPlugin: starting graceful shutdown");

      // Use a single unified timeout for the entire shutdown process
      // to ensure total time does not exceed 5 seconds as per architecture
      // document section 2.3.2
      let shutdown_result = tokio::time::timeout(
        SHUTDOWN_TIMEOUT,
        Self::do_graceful_shutdown(&stream_tracker, &conn_tracker),
      )
      .await;

      match shutdown_result {
        Ok(_initial_counts) => {
          info!("Http3ChainPlugin: graceful shutdown completed");
        }
        Err(_) => {
          // Use the initial counts recorded BEFORE shutdown started
          // This provides accurate numbers for timeout logging
          warn!(
            "Http3ChainPlugin: shutdown timeout reached after {:?}, \
             forcefully aborting remaining tasks: {} streams, {} connections",
            SHUTDOWN_TIMEOUT, initial_stream_count, initial_conn_count
          );
          // Forcefully abort all streams and connections
          // abort_all() is synchronous and immediately terminates tasks,
          // no additional waiting needed
          stream_tracker.abort_all();
          info!("Http3ChainPlugin: forced shutdown completed");
        }
      }

      // Close all QUIC connections with CONNECTION_CLOSE frame
      // This sends H3_NO_ERROR to indicate graceful shutdown
      info!(
        "Http3ChainPlugin: closing {} QUIC connections",
        conn_tracker.count()
      );
      conn_tracker.close_all();
      conn_tracker.clear();
    })
  }
}

pub fn plugin_name() -> &'static str {
  "http3_chain"
}

pub fn create_plugin() -> Box<dyn plugin::Plugin> {
  Box::new(Http3ChainPlugin::new())
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::plugin::Plugin;
  use std::future::pending;

  // ============== Http3ChainServiceArgs Tests (new format without service-level server_ca_path) ==============

  #[test]
  fn test_service_args_deserialize_new_format_no_service_level_ca() {
    let yaml = r#"
proxy_group:
  - address: "127.0.0.1:8080"
    weight: 1
default_credential:
  server_ca_path: "/tmp/ca.pem"
"#;
    let args: Http3ChainServiceArgs =
      serde_yaml::from_str(yaml).unwrap();
    assert_eq!(args.proxy_group.len(), 1);
    assert!(args.default_credential.is_some());
    let dc = args.default_credential.as_ref().unwrap();
    assert_eq!(dc.server_ca_path, Some("/tmp/ca.pem".to_string()));
  }

  #[test]
  fn test_service_args_rejects_unknown_fields() {
    // CR-002: After removing service-level server_ca_path, users with old configs
    // should get a clear error instead of silent ignore
    let yaml = r#"
proxy_group:
  - address: "127.0.0.1:8080"
    weight: 1
server_ca_path: "/tmp/ca.pem"
"#;
    let result: Result<Http3ChainServiceArgs, _> =
      serde_yaml::from_str(yaml);
    assert!(
      result.is_err(),
      "Should reject unknown field 'server_ca_path' with deny_unknown_fields"
    );
    let err = result.unwrap_err().to_string();
    assert!(
      err.contains("unknown field")
        || err.contains("server_ca_path"),
      "Error should mention unknown field, got: {}",
      err
    );
  }

  // ============== ClientCredentialConfig Tests ==============

  #[test]
  fn test_client_credential_config_deserialize_password_only() {
    let yaml = r#"
user:
  username: admin
  password: secret
"#;
    let config: ClientCredentialConfig =
      serde_yaml::from_str(yaml).unwrap();
    assert!(config.user.is_some());
    assert!(config.client_cert_path.is_none());
  }

  #[test]
  fn test_client_credential_config_deserialize_empty_object() {
    let yaml = r#"{}"#;
    let config: ClientCredentialConfig =
      serde_yaml::from_str(yaml).unwrap();
    assert!(config.user.is_none());
    assert!(config.client_cert_path.is_none());
  }

  #[test]
  fn test_client_credential_config_deserialize_with_server_ca_path() {
    let yaml = r#"
server_ca_path: /path/to/ca.pem
"#;
    let config: ClientCredentialConfig =
      serde_yaml::from_str(yaml).unwrap();
    assert_eq!(
      config.server_ca_path,
      Some("/path/to/ca.pem".to_string())
    );
    assert!(config.user.is_none());
    assert!(config.client_cert_path.is_none());
  }

  #[test]
  fn test_client_credential_config_validate_cert_without_key_is_error()
  {
    let config = ClientCredentialConfig {
      user: None,
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
    let default_cred = ClientCredentialConfig {
      user: Some(UserCredential {
        username: "default_user".to_string(),
        password: "default_pass".to_string(),
      }),
      client_cert_path: None,
      client_key_path: None,
      server_ca_path: Some("/default/ca.pem".to_string()),
    };
    let proxy_cred = ClientCredentialConfig {
      user: None,
      client_cert_path: None,
      client_key_path: None,
      server_ca_path: Some("/proxy/ca.pem".to_string()),
    };
    let merged = proxy_cred.deep_merge(&default_cred);
    // proxy's server_ca_path overrides default
    assert_eq!(merged.server_ca_path, Some("/proxy/ca.pem".to_string()));
    // user inherited from default
    assert!(merged.user.is_some());
    assert_eq!(merged.user.as_ref().unwrap().username, "default_user");
  }

  #[test]
  fn test_deep_merge_inherits_all_from_default() {
    let default_cred = ClientCredentialConfig {
      user: Some(UserCredential {
        username: "default_user".to_string(),
        password: "default_pass".to_string(),
      }),
      client_cert_path: Some("/default/cert.pem".to_string()),
      client_key_path: Some("/default/key.pem".to_string()),
      server_ca_path: Some("/default/ca.pem".to_string()),
    };
    let proxy_cred = ClientCredentialConfig {
      user: None,
      client_cert_path: None,
      client_key_path: None,
      server_ca_path: None,
    };
    let merged = proxy_cred.deep_merge(&default_cred);
    assert_eq!(merged.user.as_ref().unwrap().username, "default_user");
    assert_eq!(merged.client_cert_path, Some("/default/cert.pem".to_string()));
    assert_eq!(merged.client_key_path, Some("/default/key.pem".to_string()));
    assert_eq!(merged.server_ca_path, Some("/default/ca.pem".to_string()));
  }

  #[test]
  fn test_deep_merge_proxy_overrides_all() {
    let default_cred = ClientCredentialConfig {
      user: Some(UserCredential {
        username: "default_user".to_string(),
        password: "default_pass".to_string(),
      }),
      client_cert_path: Some("/default/cert.pem".to_string()),
      client_key_path: Some("/default/key.pem".to_string()),
      server_ca_path: Some("/default/ca.pem".to_string()),
    };
    let proxy_cred = ClientCredentialConfig {
      user: Some(UserCredential {
        username: "proxy_user".to_string(),
        password: "proxy_pass".to_string(),
      }),
      client_cert_path: Some("/proxy/cert.pem".to_string()),
      client_key_path: Some("/proxy/key.pem".to_string()),
      server_ca_path: Some("/proxy/ca.pem".to_string()),
    };
    let merged = proxy_cred.deep_merge(&default_cred);
    assert_eq!(merged.user.as_ref().unwrap().username, "proxy_user");
    assert_eq!(merged.client_cert_path, Some("/proxy/cert.pem".to_string()));
    assert_eq!(merged.client_key_path, Some("/proxy/key.pem".to_string()));
    assert_eq!(merged.server_ca_path, Some("/proxy/ca.pem".to_string()));
  }

  // ============== resolve_credential Tests ==============

  #[test]
  fn test_resolve_credential_deep_merges_with_default() {
    let args = Http3ChainServiceArgs {
      proxy_group: vec![],
      default_credential: Some(ClientCredentialConfig {
        user: Some(UserCredential {
          username: "default_user".to_string(),
          password: "default_pass".to_string(),
        }),
        client_cert_path: None,
        client_key_path: None,
        server_ca_path: Some("/default/ca.pem".to_string()),
      }),
    };
    // Proxy has only server_ca_path, should inherit user from default
    let proxy_cred = Some(ClientCredentialConfig {
      user: None,
      client_cert_path: None,
      client_key_path: None,
      server_ca_path: Some("/proxy/ca.pem".to_string()),
    });
    let (upc, _ccc, server_ca) = args.resolve_credential(&proxy_cred);
    // user should be inherited from default via deep merge
    assert!(
      upc.user.is_some(),
      "Should inherit user from default via deep merge"
    );
    // server_ca_path should be from proxy (override)
    assert_eq!(
      server_ca,
      Some("/proxy/ca.pem".to_string()),
      "server_ca_path should come from proxy credential"
    );
  }

  #[test]
  fn test_resolve_credential_none_inherits_default() {
    let args = Http3ChainServiceArgs {
      proxy_group: vec![],
      default_credential: Some(ClientCredentialConfig {
        user: Some(UserCredential {
          username: "default_user".to_string(),
          password: "default_pass".to_string(),
        }),
        client_cert_path: None,
        client_key_path: None,
        server_ca_path: None,
      }),
    };
    // None means inherit default_credential
    let (upc, ccc, _server_ca) = args.resolve_credential(&None);
    assert!(
      upc.user.is_some(),
      "Should inherit password credential from default"
    );
    assert!(
      ccc.cert_path.is_none(),
      "Default has no cert credential"
    );
  }

  #[test]
  fn test_resolve_credential_empty_object_inherits_from_default() {
    let args = Http3ChainServiceArgs {
      proxy_group: vec![],
      default_credential: Some(ClientCredentialConfig {
        user: Some(UserCredential {
          username: "default_user".to_string(),
          password: "default_pass".to_string(),
        }),
        client_cert_path: None,
        client_key_path: None,
        server_ca_path: Some("/path/to/ca.pem".to_string()),
      }),
    };
    // Some(empty) means "no auth" - user and client cert are NOT inherited
    // but server_ca_path IS inherited for TLS verification
    let empty = Some(ClientCredentialConfig {
      user: None,
      client_cert_path: None,
      client_key_path: None,
      server_ca_path: None,
    });
    let (upc, ccc, server_ca) = args.resolve_credential(&empty);
    assert!(
      upc.user.is_none(),
      "Empty proxy credential should NOT inherit user from default (no auth)"
    );
    assert!(
      ccc.cert_path.is_none(),
      "Empty proxy credential should NOT inherit client cert from default"
    );
    assert!(
      server_ca.is_some(),
      "Empty proxy credential should inherit server_ca_path from default for TLS verification"
    );
  }

  #[test]
  fn test_resolve_credential_explicit_overrides_default() {
    let args = Http3ChainServiceArgs {
      proxy_group: vec![],
      default_credential: Some(ClientCredentialConfig {
        user: Some(UserCredential {
          username: "default_user".to_string(),
          password: "default_pass".to_string(),
        }),
        client_cert_path: None,
        client_key_path: None,
        server_ca_path: None,
      }),
    };
    // Some(explicit) means use this credential, not default
    let explicit = Some(ClientCredentialConfig {
      user: Some(UserCredential {
        username: "explicit_user".to_string(),
        password: "explicit_pass".to_string(),
      }),
      client_cert_path: None,
      client_key_path: None,
      server_ca_path: None,
    });
    let (upc, ccc, _server_ca) = args.resolve_credential(&explicit);
    assert!(upc.user.is_some(), "Should use explicit password credential");
    assert!(ccc.cert_path.is_none(), "Explicit has no cert credential");
  }

  #[test]
  fn test_resolve_credential_none_with_no_default() {
    let args = Http3ChainServiceArgs {
      proxy_group: vec![],
      default_credential: None,
    };
    // None means inherit, but no default → no credential
    let (upc, ccc, _server_ca) = args.resolve_credential(&None);
    assert!(upc.user.is_none(), "No default means no password credential");
    assert!(ccc.cert_path.is_none(), "No default means no cert credential");
  }

  #[test]
  fn test_validate_credential_cert_without_key_in_default() {
    let args = Http3ChainServiceArgs {
      proxy_group: vec![Http3ChainServiceArgsProxyGroup {
        address: "127.0.0.1:443".to_string(),
        weight: 1,
        credential: None,
      }],
      default_credential: Some(ClientCredentialConfig {
        user: None,
        client_cert_path: Some("/path/to/cert.pem".to_string()),
        client_key_path: None,
        server_ca_path: None,
      }),
    };
    let result = args.validate();
    assert!(
      result.is_err(),
      "default_credential with cert but no key should fail validation"
    );
    let err = result.unwrap_err().to_string();
    assert!(
      err.contains("client_cert_path and client_key_path")
        || err.contains("default_credential"),
      "Error should be about cert/key pair or default_credential, got: {}",
      err
    );
  }

  // ============== Http3ChainPlugin Tests ==============

  #[test]
  fn test_plugin_new() {
    let plugin = Http3ChainPlugin::new();
    assert!(plugin.service_builder("http3_chain").is_some());
    assert!(plugin.service_builder("nonexistent").is_none());
  }

  #[test]
  fn test_plugin_new_no_transfering_set() {
    // After refactor, Http3ChainPlugin should not have transfering_set field
    // and should still work correctly
    let plugin = Http3ChainPlugin::new();
    assert!(plugin.service_builder("http3_chain").is_some());
  }

  #[test]
  fn test_plugin_service_builder_exists() {
    let plugin = Http3ChainPlugin::new();
    let builder = plugin.service_builder("http3_chain");
    assert!(builder.is_some());
  }

  #[test]
  fn test_create_plugin() {
    let plugin = create_plugin();
    assert!(plugin.service_builder("http3_chain").is_some());
  }

  #[tokio::test]
  async fn test_uninstall_empty_plugin() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let mut plugin = Http3ChainPlugin::new();

        // Uninstall with no active streams should complete quickly
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
        let mut plugin = Http3ChainPlugin::new();

        // Register a pending stream that never completes
        plugin.stream_tracker.register(async {
          pending::<()>().await;
        });

        // Give time for the task to be spawned
        tokio::task::yield_now().await;

        // Uninstall should timeout and force abort
        let start = std::time::Instant::now();
        plugin.uninstall().await;
        let elapsed = start.elapsed();

        // Should have waited for the timeout
        assert!(
          elapsed >= SHUTDOWN_TIMEOUT,
          "Uninstall should wait for timeout"
        );
        // Allow small margin (100ms) for test overhead since abort_all()
        // is synchronous and no additional waiting is needed
        assert!(
          elapsed < SHUTDOWN_TIMEOUT + Duration::from_millis(100),
          "Uninstall should not take much longer than timeout, took {:?}",
          elapsed
        );
      })
      .await;
  }

  #[tokio::test]
  async fn test_uninstall_with_completing_stream() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let mut plugin = Http3ChainPlugin::new();

        let completed = Rc::new(RefCell::new(false));
        let completed_clone = completed.clone();

        // Register a stream that completes quickly
        plugin.stream_tracker.register(async move {
          // Simulate some work
          tokio::time::sleep(Duration::from_millis(10)).await;
          completed_clone.replace(true);
        });

        // Give time for the task to be spawned
        tokio::task::yield_now().await;

        // Uninstall should complete gracefully
        let start = std::time::Instant::now();
        plugin.uninstall().await;
        let elapsed = start.elapsed();

        // Should complete quickly since stream finishes
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
        let mut plugin = Http3ChainPlugin::new();

        // First uninstall
        plugin.uninstall().await;

        // Second uninstall should also complete without error
        plugin.uninstall().await;

        // Third uninstall
        plugin.uninstall().await;
      })
      .await;
  }

  // ============== ProxyGroup Tests ==============

  #[test]
  fn test_proxy_group_new() {
    let addresses = vec![
      (
        "127.0.0.1:8080".parse().unwrap(),
        1,
        UserPasswordCredential::none(),
        ClientCertCredential::none(),
        None,
      ),
      (
        "127.0.0.1:8081".parse().unwrap(),
        2,
        UserPasswordCredential::none(),
        ClientCertCredential::none(),
        None,
      ),
    ];
    let group = ProxyGroup::new(addresses);

    assert_eq!(group.proxies.len(), 2);
    assert_eq!(group.proxies[0].weight, 1);
    assert_eq!(group.proxies[1].weight, 2);
  }

  #[test]
  fn test_proxy_group_schedule_wrr_single() {
    let addresses = vec![(
      "127.0.0.1:8080".parse().unwrap(),
      1,
      UserPasswordCredential::none(),
      ClientCertCredential::none(),
      None,
    )];
    let mut group = ProxyGroup::new(addresses);

    // With single proxy, should always select index 0
    assert_eq!(group.schedule_wrr(), 0);
  }

  #[test]
  fn test_proxy_group_schedule_wrr_two_proxies_weight_2_to_1() {
    // Test WRR with two proxies: weights 2:1
    // Expected distribution over 6 calls: 0, 1, 0, 0, 1, 0 (4:2 ratio = 2:1)
    let addresses = vec![
      (
        "127.0.0.1:8080".parse().unwrap(),
        2,
        UserPasswordCredential::none(),
        ClientCertCredential::none(),
        None,
      ), // weight 2
      (
        "127.0.0.1:8081".parse().unwrap(),
        1,
        UserPasswordCredential::none(),
        ClientCertCredential::none(),
        None,
      ), // weight 1
    ];
    let mut group = ProxyGroup::new(addresses);

    // Run 6 iterations (total weight = 3, so 6 = 2 full cycles)
    let selections: Vec<usize> =
      (0..6).map(|_| group.schedule_wrr()).collect();

    // Count selections per proxy
    let count_0 = selections.iter().filter(|&&x| x == 0).count();
    let count_1 = selections.iter().filter(|&&x| x == 1).count();

    // With weights 2:1, expect approximately 4:2 distribution
    assert_eq!(
      count_0, 4,
      "Proxy 0 (weight 2) should be selected 4 times"
    );
    assert_eq!(
      count_1, 2,
      "Proxy 1 (weight 1) should be selected 2 times"
    );
  }

  // ============== Http3ChainServiceArgs Tests ==============

  #[test]
  fn test_service_args_deserialize() {
    let yaml = r#"
proxy_group:
  - address: "127.0.0.1:8080"
    weight: 1
  - address: "127.0.0.1:8081"
    weight: 2
default_credential:
  server_ca_path: "/tmp/ca.pem"
"#;
    let args: Http3ChainServiceArgs =
      serde_yaml::from_str(yaml).unwrap();
    assert_eq!(args.proxy_group.len(), 2);
    assert!(args.default_credential.is_some());
    let dc = args.default_credential.as_ref().unwrap();
    assert_eq!(dc.server_ca_path, Some("/tmp/ca.pem".to_string()));
    assert_eq!(args.proxy_group[0].address, "127.0.0.1:8080");
    assert_eq!(args.proxy_group[0].weight, 1);
    assert_eq!(args.proxy_group[1].address, "127.0.0.1:8081");
    assert_eq!(args.proxy_group[1].weight, 2);
  }

  #[test]
  fn test_service_args_default() {
    let args = Http3ChainServiceArgs::default();
    assert!(args.proxy_group.is_empty());
    assert!(args.default_credential.is_none());
  }

  // ============== build_empty_response Tests ==============

  #[test]
  fn test_build_empty_response_ok() {
    let resp = build_empty_response(http::StatusCode::OK);
    assert_eq!(resp.status(), http::StatusCode::OK);
  }

  #[test]
  fn test_build_empty_response_not_found() {
    let resp = build_empty_response(http::StatusCode::NOT_FOUND);
    assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
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

  // ============== build_error_response Tests ==============

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
  fn test_build_error_response_bad_request() {
    let resp = build_error_response(
      http::StatusCode::BAD_REQUEST,
      "Invalid target address",
    );
    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    assert_eq!(
      resp.headers().get(http::header::CONTENT_TYPE).unwrap(),
      "text/plain"
    );
  }

  // ============== call() CONNECT validation Tests ==============

  #[test]
  fn test_non_connect_method_produces_405() {
    use crate::connect_utils::{self as utils, ConnectTargetError};

    // Build a GET request's header parts
    let req = http::Request::builder()
      .method(http::Method::GET)
      .uri("http://example.com/")
      .body(())
      .unwrap();
    let (parts, _) = req.into_parts();

    // Simulate the match logic from call()
    let result = utils::parse_connect_target(&parts);
    assert!(matches!(result, Err(ConnectTargetError::NotConnectMethod)));

    // Verify the response that would be built
    let resp = build_error_response(
      http::StatusCode::METHOD_NOT_ALLOWED,
      "Only CONNECT method is supported",
    );
    assert_eq!(resp.status(), http::StatusCode::METHOD_NOT_ALLOWED);
  }

  #[test]
  fn test_connect_missing_port_produces_400() {
    use crate::connect_utils::{self as utils, ConnectTargetError};

    // Build a CONNECT request with no port
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

    // Verify the response that would be built
    let resp = build_error_response(
      http::StatusCode::BAD_REQUEST,
      "Invalid target address",
    );
    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
  }

  #[test]
  fn test_connect_port_zero_produces_400() {
    use crate::connect_utils::{self as utils, ConnectTargetError};

    let req = http::Request::builder()
      .method(http::Method::CONNECT)
      .uri("example.com:0")
      .body(())
      .unwrap();
    let (parts, _) = req.into_parts();

    let result = utils::parse_connect_target(&parts);
    assert!(matches!(result, Err(ConnectTargetError::PortZero)));

    let resp = build_error_response(
      http::StatusCode::BAD_REQUEST,
      "Invalid target address",
    );
    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
  }

  // ============== ServiceMetrics Tests ==============

  #[test]
  fn test_build_tunnel_response_with_metrics() {
    let resp = build_tunnel_response_with_metrics(42);

    assert_eq!(resp.status(), http::StatusCode::OK);

    let metrics = resp
      .extensions()
      .get::<crate::access_log::ServiceMetrics>();
    assert!(
      metrics.is_some(),
      "Response should contain ServiceMetrics"
    );
    let metrics = metrics.unwrap();
    let has_connect = metrics
      .iter()
      .any(|(k, v)| k == "connect_ms" && v == "42");
    assert!(
      has_connect,
      "ServiceMetrics should contain connect_ms=42"
    );
  }
}
