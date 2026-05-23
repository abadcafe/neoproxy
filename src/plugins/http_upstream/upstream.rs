use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use std::io::BufReader;
use std::pin::Pin;
use std::future::Future;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use rustls::pki_types::CertificateDer;

use crate::context::RequestContext;
use crate::http_utils::{Response, RequestBody};
use crate::tracker::StreamTracker;

use super::config::{CertificateConfig, ClientCertCredential};
use super::error::UpstreamError;

// Sub-modules organized by protocol
mod http;
mod http3;
mod utils;
#[cfg(test)]
mod tests;

// Re-export client types from sub-modules for use by the registry
pub(crate) use self::http::{HttpClient, HttpsClient, ProxyConnector};
pub(crate) use self::http3::{Http3Client, Http3AddressState};

// ============================================================================
// Runtime Types (self-contained, no dependency on config types)
// ============================================================================

/// Runtime QUIC configuration, copied from config at construction time.
#[derive(Clone, Debug)]
pub(crate) struct QuicConfig {
  pub(crate) max_idle_timeout: Option<Duration>,
  pub(crate) keep_alive_interval: Duration,
  pub(crate) max_concurrent_bidi_streams: Option<u64>,
  pub(crate) initial_mtu: Option<u16>,
  pub(crate) send_window: Option<u64>,
  pub(crate) receive_window: Option<u64>,
}

// ============================================================================
// Client Protocol Trait — abstraction over HTTP/HTTPS/H3 upstream clients
// ============================================================================

/// Unified interface for forwarding requests and establishing tunnels,
/// implemented by each protocol variant (Http, Https, H3).
pub(crate) trait ClientProtocol {
  fn forward<'a>(
    &'a self,
    tls_config: &'a Option<Arc<rustls::ClientConfig>>,
    tracker: &'a Rc<StreamTracker>,
    req_headers: ::http::request::Parts,
    req_body: RequestBody,
    ctx: &'a RequestContext,
  ) -> Pin<Box<dyn Future<Output = Result<Response, UpstreamError>> + 'a>>;

  fn connect_for_tunnel<'a>(
    &'a self,
    target: &'a str,
    tls_config: &'a Option<Arc<rustls::ClientConfig>>,
    tracker: &'a Rc<StreamTracker>,
  ) -> Pin<Box<dyn Future<Output = Result<ConnectResult, UpstreamError>> + 'a>>;

  /// Close any held connections (QUIC, etc.). Default is no-op.
  fn close(&self) {}
}

// ============================================================================
// Address
// ============================================================================

/// A single upstream address with its pre-built client.
/// Only routing fields; protocol parameters live in `client`.
pub(crate) struct Address {
  pub(crate) weight: usize,
  pub(crate) current_weight: std::cell::Cell<isize>,
  pub(crate) client: Box<dyn ClientProtocol>,
}

// ============================================================================
// WRR Scheduling
// ============================================================================

fn schedule_wrr(addresses: &[Address]) -> Option<usize> {
  if addresses.is_empty() {
    return None;
  }
  let total = addresses.iter().fold(0, |t, a| t + a.weight) as isize;
  let mut selected_idx = 0usize;
  let mut selected_weight = 0isize;
  for (i, a) in addresses.iter().enumerate() {
    let new_cw = a.current_weight.get() + a.weight as isize;
    a.current_weight.set(new_cw);
    if new_cw > selected_weight {
      selected_weight = new_cw;
      selected_idx = i;
    }
  }
  let new_cw = addresses[selected_idx].current_weight.get() - total;
  addresses[selected_idx].current_weight.set(new_cw);
  Some(selected_idx)
}

// ============================================================================
// Upstream
// ============================================================================

/// A resolved upstream with its addresses and optional direct-client fallback.
pub(crate) struct Upstream {
  pub(crate) addresses: Vec<Address>,
  direct_client: Option<Box<dyn ClientProtocol>>,
}

impl Upstream {
  /// Pick a client from WRR-scheduled addresses, falling back to direct_client.
  fn client(&self) -> Result<&dyn ClientProtocol, UpstreamError> {
    schedule_wrr(&self.addresses)
      .map(|idx| &*self.addresses[idx].client)
      .or_else(|| self.direct_client.as_deref())
      .ok_or_else(|| UpstreamError::ProxyInternalError("no addresses".into()))
  }

  pub(crate) async fn forward(
    &self,
    tls_config: &Option<Arc<rustls::ClientConfig>>,
    tracker: &Rc<StreamTracker>,
    req_headers: ::http::request::Parts,
    req_body: RequestBody,
    ctx: &RequestContext,
  ) -> Result<Response, UpstreamError> {
    self.client()?.forward(tls_config, tracker, req_headers, req_body, ctx).await
  }

  pub(crate) async fn connect_for_tunnel(
    &self,
    target: &str,
    tls_config: &Option<Arc<rustls::ClientConfig>>,
    tracker: &Rc<StreamTracker>,
  ) -> Result<ConnectResult, UpstreamError> {
    self.client()?.connect_for_tunnel(target, tls_config, tracker).await
  }
}

// ============================================================================
// Connect Result & Tunnel Transport
// ============================================================================

pub(crate) struct ConnectResult {
  pub(crate) transport: Box<dyn crate::stream::Io>,
  pub(crate) upstream_addr: Option<std::net::SocketAddr>,
  pub(crate) upstream_proxy_status: Option<::http::HeaderValue>,
  pub(crate) tunnel_idle_timeout: Duration,
}

// ============================================================================
// TLS Config Builder
// ============================================================================

fn build_root_cert_store(server_ca_path: Option<&str>) -> Result<rustls::RootCertStore> {
  let mut roots = rustls::RootCertStore::empty();
  let rustls_native_certs::CertificateResult { certs, errors, .. } =
    rustls_native_certs::load_native_certs();
  for cert in certs {
    if let Err(e) = roots.add(cert) {
      tracing::error!("failed to parse trust anchor: {e}");
    }
  }
  for e in errors {
    tracing::error!("couldn't load default trust roots: {e}");
  }
  if let Some(path) = server_ca_path {
    let file = fs::File::open(path)
      .with_context(|| format!("opening server CA file: {path}"))?;
    let mut reader = BufReader::new(file);
    let certs: Vec<CertificateDer> =
      rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    for cert in certs {
      roots.add(cert)?;
    }
  }
  Ok(roots)
}

fn build_tls_config(
  ccc: &ClientCertCredential,
  roots: rustls::RootCertStore,
) -> Result<rustls::ClientConfig> {
  match (&ccc.cert_path, &ccc.key_path) {
    (Some(cert_path), Some(key_path)) => {
      let cert_file = fs::File::open(cert_path)?;
      let mut cert_reader = BufReader::new(cert_file);
      let cert_chain: Vec<CertificateDer> =
        rustls_pemfile::certs(&mut cert_reader)
          .collect::<Result<Vec<_>, _>>()?;
      let key_file = fs::File::open(key_path)?;
      let mut key_reader = BufReader::new(key_file);
      let key = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or_else(|| anyhow!("no private key found"))?;
      Ok(
        rustls::ClientConfig::builder()
          .with_root_certificates(roots)
          .with_client_auth_cert(cert_chain, key)?,
      )
    }
    (None, None) => Ok(
      rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth(),
    ),
    _ => bail!(
      "client_cert_path and client_key_path must both be present or both absent"
    ),
  }
}

// ============================================================================
// Upstream Registry
// ============================================================================

pub(crate) struct UpstreamRegistry {
  pub(crate) entries: HashMap<String, Upstream>,
  tls_config: Option<Arc<rustls::ClientConfig>>,
  tracker: Rc<StreamTracker>,
}

impl UpstreamRegistry {
  pub(crate) fn new(
    upstreams: HashMap<String, super::config::Upstream>,
    certificates: Option<&CertificateConfig>,
    tracker: Rc<StreamTracker>,
  ) -> Result<Self> {
    let tls_config = if let Some(certs) = certificates {
      let roots = build_root_cert_store(certs.server_ca_path.as_deref())?;
      let ccc = ClientCertCredential {
        cert_path: certs.client_cert_path.as_ref().map(Into::into),
        key_path: certs.client_key_path.as_ref().map(Into::into),
      };
      let mut https_config = build_tls_config(&ccc, roots)?;
      https_config.alpn_protocols = vec![b"http/1.1".to_vec()];
      https_config.key_log = Arc::new(rustls::KeyLogFile::new());
      Some(Arc::new(https_config))
    } else {
      None
    };

    let mut entries: HashMap<String, Upstream> = HashMap::new();

    for (upstream_name, upstream) in upstreams {
      if upstream.addresses.is_empty() {
        // Direct mode: no proxy addresses, HttpClient connects to origin directly
        let connector = HttpConnector::new();
        let mut builder = Client::builder(hyper_util::rt::TokioExecutor::new());
        builder.pool_max_idle_per_host(upstream.pool_config.max_idle_per_host);
        builder.pool_idle_timeout(upstream.pool_config.idle_timeout);
        let client = builder.build(connector);

        entries.insert(upstream_name, Upstream {
          addresses: vec![],
          direct_client: Some(Box::new(HttpClient::<HttpConnector> {
            client,
            proxy_addr: None,
            connect_timeout: upstream.connect_timeout,
            tunnel_idle_timeout: upstream.tunnel_idle_timeout,
            user: None,
          })),
        });
        continue;
      }

      // Chain mode: build an Address per ResolvedAddress with pre-built client
      let mut addresses = Vec::new();

      for addr in &upstream.addresses {
        match &addr.protocol {
          super::config::Protocol::Http { connect_timeout } => {
            let connector = ProxyConnector::new(addr.address.clone(), *connect_timeout);
            let client = Client::builder(hyper_util::rt::TokioExecutor::new())
              .pool_max_idle_per_host(upstream.pool_config.max_idle_per_host)
              .pool_idle_timeout(upstream.pool_config.idle_timeout)
              .build(connector);

            addresses.push(Address {
              weight: addr.weight,
              current_weight: std::cell::Cell::new(0),
              client: Box::new(HttpClient::<ProxyConnector> {
                client,
                proxy_addr: Some(addr.address.clone()),
                connect_timeout: *connect_timeout,
                tunnel_idle_timeout: addr.tunnel_idle_timeout,
                user: addr.user.clone(),
              }),
            });
          }
          super::config::Protocol::Https { connect_timeout, tls_handshake_timeout } => {
            let tls = tls_config.clone()
              .ok_or_else(|| anyhow!("no TLS configuration for HTTPS upstream '{upstream_name}'"))?;
            let host = addr.hostname.as_deref().unwrap_or_else(|| {
              addr.address.split_at(addr.address.rfind(':').unwrap_or(addr.address.len())).0
            });
            let inner = ProxyConnector::new(addr.address.clone(), *connect_timeout);
            let connector = http::TlsProxyConnector::new(inner, tls, host.to_string(), *tls_handshake_timeout);
            let client = Client::builder(hyper_util::rt::TokioExecutor::new())
              .pool_max_idle_per_host(upstream.pool_config.max_idle_per_host)
              .pool_idle_timeout(upstream.pool_config.idle_timeout)
              .build(connector);

            addresses.push(Address {
              weight: addr.weight,
              current_weight: std::cell::Cell::new(0),
              client: Box::new(HttpsClient {
                client,
                proxy_addr: addr.address.clone(),
                hostname: host.to_string(),
                connect_timeout: *connect_timeout,
                tls_handshake_timeout: *tls_handshake_timeout,
                tunnel_idle_timeout: addr.tunnel_idle_timeout,
                user: addr.user.clone(),
              }),
            });
          }
          super::config::Protocol::Http3 { tls_handshake_timeout, quic } => {
            addresses.push(Address {
              weight: addr.weight,
              current_weight: std::cell::Cell::new(0),
              client: Box::new(Http3Client {
                state: Rc::new(RefCell::new(Http3AddressState::new())),
                proxy_addr: addr.address.clone(),
                hostname: addr.hostname.clone(),
                tls_handshake_timeout: *tls_handshake_timeout,
                tunnel_idle_timeout: addr.tunnel_idle_timeout,
                quic: QuicConfig {
                  max_idle_timeout: quic.max_idle_timeout,
                  keep_alive_interval: quic.keep_alive_interval,
                  max_concurrent_bidi_streams: quic.max_concurrent_bidi_streams,
                  initial_mtu: quic.initial_mtu,
                  send_window: quic.send_window,
                  receive_window: quic.receive_window,
                },
                user: addr.user.clone(),
              }),
            });
          }
        }
      }

      entries.insert(upstream_name, Upstream { addresses, direct_client: None });
    }

    Ok(Self { entries, tls_config, tracker })
  }

  pub(crate) fn get_upstream(&self, name: &str) -> Result<&Upstream, UpstreamError> {
    self.entries.get(name).ok_or_else(|| UpstreamError::ProxyInternalError(
      format!("upstream '{name}' not found"),
    ))
  }

  pub(crate) fn tls_config(&self) -> Option<Arc<rustls::ClientConfig>> {
    self.tls_config.clone()
  }

  pub(crate) fn tracker(&self) -> Rc<StreamTracker> {
    self.tracker.clone()
  }

  pub(crate) fn close_all(&self) {
    for upstream in self.entries.values() {
      for addr in &upstream.addresses {
        addr.client.close();
      }
      if let Some(ref dc) = upstream.direct_client {
        dc.close();
      }
    }
  }
}
