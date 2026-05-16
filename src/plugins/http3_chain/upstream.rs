use std::collections::HashMap;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;
use std::{fs, path};

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use h3::client as h3_cli;
use rustls::pki_types::CertificateDer;
use rustls_native_certs::CertificateResult;
use tokio::sync::{Mutex, Notify};
use tracing::{error, info, warn};

use super::config::{
  ClientCertCredential, QuicResolved, ResolvedAddress, ResolvedUpstream,
  UserPasswordCredential,
};
use super::error::{classify_quic_error, DnsResolveError, UpstreamHandleError};
use super::ALPN;

// ============================================================================
// Upstream Connection (for graceful close)
// ============================================================================

pub(crate) struct UpstreamConnection {
  conn: quinn::Connection,
}

impl UpstreamConnection {
  pub(crate) fn new(conn: quinn::Connection) -> Self {
    Self { conn }
  }

  pub(crate) fn close(&self) {
    self.conn.close(
      quinn::VarInt::from_u32(super::H3_NO_ERROR_CODE),
      b"shutdown",
    );
  }
}

// ============================================================================
// TLS Client Config Builder
// ============================================================================

fn build_tls_client_config(
  roots: rustls::RootCertStore,
  client_cert_credential: &ClientCertCredential,
) -> Result<rustls::ClientConfig> {
  client_cert_credential.build_tls_config(roots)
}

// ============================================================================
// Global Upstream Pool
// ============================================================================

pub(crate) struct UpstreamProxy {
  pub(crate) max_idle_timeout: Duration,
  pub(crate) user_password_credential: UserPasswordCredential,
  pub(crate) quinn_conn: Option<quinn::Connection>,
  pub(crate) requester: Option<h3_cli::SendRequest<h3_quinn::OpenStreams, Bytes>>,
  pub(crate) h3_conn: Option<h3_cli::Connection<h3_quinn::Connection, Bytes>>,
}

pub(crate) struct UpstreamRegistry {
  pub(crate) resolved: HashMap<String, ResolvedUpstream>,
  pub(crate) pool: HashMap<(String, String), Arc<Mutex<UpstreamProxy>>>,
}

pub(crate) static UPSTREAM_REGISTRY: std::sync::LazyLock<
  std::sync::Mutex<Option<UpstreamRegistry>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(None));

pub(crate) static UPSTREAM_NOTIFY: std::sync::LazyLock<Notify> =
  std::sync::LazyLock::new(Notify::new);

pub(crate) struct UpstreamThreadHandle {
  pub(crate) shutdown_tx: tokio::sync::mpsc::Sender<()>,
  pub(crate) join_handle: Option<std::thread::JoinHandle<()>>,
}

pub(crate) static UPSTREAM_THREAD_HANDLE: std::sync::LazyLock<
  std::sync::Mutex<Option<UpstreamThreadHandle>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(None));

// ============================================================================
// WRR Scheduling
// ============================================================================

/// Weighted Round-Robin: select an address index from the upstream's
/// resolved addresses.
pub(crate) fn schedule_wrr(addresses: &mut [ResolvedAddress]) -> Option<usize> {
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

pub(crate) async fn create_quic_connection(
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
    // Use the host part of address as SNI when hostname is not configured
    address.split_at(address.rfind(':').unwrap_or(address.len())).0
  });
  let conn = cli_endpoint.connect(addr, host)?.await?;

  info!("QUIC connection established to {}", address);
  Ok(conn)
}

// ============================================================================
// Upstream Handle Acquisition
// ============================================================================

pub(crate) struct UpstreamHandle {
  pub(crate) requester: h3_cli::SendRequest<h3_quinn::OpenStreams, Bytes>,
  pub(crate) user_password_credential: UserPasswordCredential,
  pub(crate) max_idle_timeout: Duration,
}

pub(crate) async fn get_upstream_handle(
  upstream_name: &str,
) -> std::result::Result<UpstreamHandle, UpstreamHandleError> {
  let (proxy_arc, address_str, hostname, client_cert_credential,
       server_ca_path, quic_resolved) =
  {
    let mut guard = UPSTREAM_REGISTRY.lock().unwrap();
    let registry = guard.as_mut()
      .ok_or_else(|| UpstreamHandleError::ProxyInternalResponse(
        "upstream registry not initialized".into(),
      ))?;

    // WRR: select an address from the upstream
    let upstream = registry.resolved.get_mut(upstream_name)
      .ok_or_else(|| UpstreamHandleError::ProxyInternalResponse(
        format!("upstream '{upstream_name}' not found"),
      ))?;
    let idx = schedule_wrr(&mut upstream.addresses)
      .ok_or_else(|| UpstreamHandleError::ProxyInternalResponse(
        format!("upstream '{upstream_name}' has no addresses"),
      ))?;
    let resolved = &upstream.addresses[idx];
    let address = resolved.address.clone();
    let key = (upstream_name.to_string(), address.clone());

    let proxy_arc = registry.pool.get(&key)
      .ok_or_else(|| UpstreamHandleError::ProxyInternalResponse(
        format!("upstream '{upstream_name}' address '{address}' not in pool"),
      ))?
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
  ).await.map_err(classify_quic_error)?;

  let (h3_conn, requester) =
    h3::client::new(h3_quinn::Connection::new(quinn_conn.clone())).await
    .map_err(|e| UpstreamHandleError::DestinationUnavailable(
      format!("H3 connection setup failed: {e}"),
    ))?;

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

async fn connection_maintaining(
  mut h3_conn: h3_cli::Connection<h3_quinn::Connection, Bytes>,
) {
  let err = std::future::poll_fn(|cx| h3_conn.poll_close(cx)).await;
  if !err.is_h3_no_error() {
    warn!("upstream connection error: {err}");
  }
}

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
                  connection_maintaining(h3_conn).await;
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

pub(crate) fn init_upstream_registry(
  config: &super::config::Http3ChainPluginConfig,
) -> Result<()> {
  let mut guard = UPSTREAM_REGISTRY.lock().unwrap();

  // Idempotent: if already initialized, skip
  if guard.is_some() {
    info!("upstream registry already initialized, skipping");
    return Ok(());
  }

  let resolved = super::config::resolve_three_level(config)?;

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
// DNS Resolution
// ============================================================================

/// Resolve an address string to a SocketAddr.
pub(crate) fn resolve_address(s: &str) -> Result<SocketAddr> {
  s.parse()
    .or_else(|_| {
      std::net::ToSocketAddrs::to_socket_addrs(s)
        .map_err(|e| {
          anyhow::Error::from(DnsResolveError(e))
            .context(format!(
              "address '{s}' is neither IP:port nor resolvable \
               hostname"
            ))
        })
        .and_then(|mut addrs| {
          addrs.next().ok_or_else(|| {
            anyhow!("address '{s}' resolved to no addresses")
          })
        })
    })
    .with_context(|| format!("address '{s}'"))
}