//! module: plugins::http_upstream::upstream
//! responsibility: construct and own configured upstream transport
//! pools
//! public operations: Upstream, forward, connect_for_tunnel,
//! UpstreamRegistry, new, get_upstream, contains_upstream, len,
//! tls_config, tracker, close_all
//! data entities: ScheduledClient, Upstream, UpstreamRegistry
//! tests: upstream_tests.rs

use std::collections::HashMap;
use std::fs;
use std::io::BufReader;
use std::rc::Rc;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use rustls::pki_types::CertificateDer;

use self::protocol::{ClientProtocol, ConnectResult, QuicConfig};
use super::config::{CertificateConfig, ClientCertCredential};
use super::error::UpstreamError;
use super::target_parser::{ConnectTarget, ForwardTarget};
use crate::context::RequestContext;
use crate::http_message::{RequestBody, Response};
use crate::tracker::StreamTracker;

// Sub-modules organized by protocol
mod address_resolution;
#[cfg(test)]
mod address_resolution_tests;
mod connect_request;
#[cfg(test)]
mod connect_request_tests;
mod direct;
#[cfg(test)]
mod direct_tests;
mod forward;
#[cfg(test)]
mod forward_tests;
mod http;
mod http3;
#[cfg(test)]
mod http3_tests;
mod http_pool;
#[cfg(test)]
mod http_tests;
mod origin_connector;
#[cfg(test)]
mod origin_connector_tests;
pub(super) mod protocol;
mod proxy_auth;
#[cfg(test)]
mod proxy_auth_tests;
mod response;
#[cfg(test)]
mod response_tests;
mod scheduler;
#[cfg(test)]
mod scheduler_tests;
mod tcp_connect;
#[cfg(test)]
mod tcp_connect_tests;

use self::direct::DirectClient;
use self::http::{HttpProxyClient, HttpsClient, ProxyConnector};
use self::http3::{Http3Client, SessionPool};
use self::scheduler::WeightedItem;

// ============================================================================
// Runtime Types (self-contained, no dependency on config types)
// ============================================================================

type ScheduledClient = WeightedItem<Box<dyn ClientProtocol>>;

// ============================================================================
// Upstream
// ============================================================================

/// A resolved upstream with its addresses and optional direct-client
/// fallback.
pub(crate) struct Upstream {
  clients: Vec<ScheduledClient>,
  request_timeout: std::time::Duration,
}

impl Upstream {
  /// Select an explicitly constructed transport from the weighted pool.
  fn client(&self) -> Result<&dyn ClientProtocol, UpstreamError> {
    scheduler::select(&self.clients)
      .map(|client| client.as_ref())
      .ok_or_else(|| {
        UpstreamError::ProxyInternalError("no addresses".into())
      })
  }

  pub(crate) async fn forward(
    &self,
    tls_config: &Option<Arc<rustls::ClientConfig>>,
    tracker: &Rc<StreamTracker>,
    target: &ForwardTarget,
    req_headers: ::http::request::Parts,
    req_body: RequestBody,
    ctx: &RequestContext,
  ) -> Result<Response, UpstreamError> {
    tokio::time::timeout(
      self.request_timeout,
      self.client()?.forward(
        tls_config,
        tracker,
        target,
        req_headers,
        req_body,
        ctx,
      ),
    )
    .await
    .map_err(|_| {
      UpstreamError::ConnectionTimeout(
        "upstream response header deadline exceeded".into(),
      )
    })?
  }

  pub(crate) async fn connect_for_tunnel(
    &self,
    target: &ConnectTarget,
    tls_config: &Option<Arc<rustls::ClientConfig>>,
    tracker: &Rc<StreamTracker>,
  ) -> Result<ConnectResult, UpstreamError> {
    tokio::time::timeout(
      self.request_timeout,
      self.client()?.connect_for_tunnel(target, tls_config, tracker),
    )
    .await
    .map_err(|_| {
      UpstreamError::ConnectionTimeout(
        "upstream tunnel establishment deadline exceeded".into(),
      )
    })?
  }
}

// ============================================================================
// Connect Result & Tunnel Transport
// ============================================================================

// ============================================================================
// TLS Config Builder
// ============================================================================

fn build_root_cert_store(
  server_ca_path: Option<&str>,
) -> Result<rustls::RootCertStore> {
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
    let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut reader)
      .collect::<Result<Vec<_>, _>>()?;
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
      "client_cert_path and client_key_path must both be present or \
       both absent"
    ),
  }
}

// ============================================================================
// Upstream Registry
// ============================================================================

pub(crate) struct UpstreamRegistry {
  entries: HashMap<String, Rc<Upstream>>,
  tls_config: Option<Arc<rustls::ClientConfig>>,
  tracker: Rc<StreamTracker>,
}

impl UpstreamRegistry {
  pub(crate) fn new(
    upstreams: HashMap<String, super::config::Upstream>,
    certificates: Option<&CertificateConfig>,
    tracker: Rc<StreamTracker>,
  ) -> Result<Self> {
    let requires_tls = upstreams.values().any(|upstream| {
      upstream.addresses.is_empty()
        || upstream.addresses.iter().any(|address| {
          !matches!(
            address.protocol,
            super::config::Protocol::Http { .. }
          )
        })
    });
    let tls_config = if !requires_tls && certificates.is_none() {
      None
    } else {
      let server_ca =
        certificates.and_then(|c| c.server_ca_path.as_deref());
      let roots = build_root_cert_store(server_ca)?;
      let ccc = match certificates {
        Some(certs) => {
          // Also validate certs to catch misconfigured client auth
          // early
          certs.validate()?;
          ClientCertCredential {
            cert_path: certs.client_cert_path.as_ref().map(Into::into),
            key_path: certs.client_key_path.as_ref().map(Into::into),
          }
        }
        None => {
          ClientCertCredential { cert_path: None, key_path: None }
        }
      };
      let mut client_config = build_tls_config(&ccc, roots)?;
      client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
      client_config.key_log = Arc::new(rustls::KeyLogFile::new());
      Some(Arc::new(client_config))
    };

    let mut entries: HashMap<String, Rc<Upstream>> = HashMap::new();

    for (upstream_name, upstream) in upstreams {
      if upstream.addresses.is_empty() {
        entries.insert(
          upstream_name,
          Rc::new(Upstream {
            request_timeout: upstream.request_timeout,
            clients: vec![ScheduledClient::new(
              1,
              Box::new(DirectClient::new(
                &upstream,
                tls_config.clone().ok_or_else(|| {
                  anyhow!("direct upstream requires TLS configuration")
                })?,
              )?),
            )],
          }),
        );
        continue;
      }

      // Chain mode: build an Address per ResolvedAddress with pre-built
      // client
      let mut addresses = Vec::new();

      for addr in &upstream.addresses {
        match &addr.protocol {
          super::config::Protocol::Http { connect_timeout } => {
            let connector = ProxyConnector::new(
              addr.address.clone(),
              *connect_timeout,
              upstream.dns_resolve_timeout,
            );
            let client = http_pool::ProxyPool::new(
              connector,
              upstream.pool_config.max_idle_per_host,
              upstream.pool_config.idle_timeout,
              tracker.clone(),
            );

            addresses.push(ScheduledClient::new(
              addr.weight,
              Box::new(HttpProxyClient::<ProxyConnector> {
                client,
                proxy_addr: addr.address.clone(),
                connect_timeout: *connect_timeout,
                tunnel_idle_timeout: addr.tunnel_idle_timeout,
                dns_resolve_timeout: upstream.dns_resolve_timeout,
                user: addr.user.clone(),
              }),
            ));
          }
          super::config::Protocol::Https {
            connect_timeout,
            tls_handshake_timeout,
          } => {
            let tls = tls_config.clone().ok_or_else(|| {
              anyhow!(
                "no TLS configuration for HTTPS upstream \
                 '{upstream_name}'"
              )
            })?;
            let host = addr.hostname.as_deref().unwrap_or_else(|| {
              addr
                .address
                .split_at(
                  addr.address.rfind(':').unwrap_or(addr.address.len()),
                )
                .0
            });
            let host =
              host.trim_start_matches('[').trim_end_matches(']');
            let inner = ProxyConnector::new(
              addr.address.clone(),
              *connect_timeout,
              upstream.dns_resolve_timeout,
            );
            let connector = http::TlsProxyConnector::new(
              inner,
              tls,
              host.to_string(),
              *tls_handshake_timeout,
            );
            let client = http_pool::ProxyPool::new(
              connector,
              upstream.pool_config.max_idle_per_host,
              upstream.pool_config.idle_timeout,
              tracker.clone(),
            );

            addresses.push(ScheduledClient::new(
              addr.weight,
              Box::new(HttpsClient {
                client,
                proxy_addr: addr.address.clone(),
                hostname: host.to_string(),
                connect_timeout: *connect_timeout,
                tls_handshake_timeout: *tls_handshake_timeout,
                tunnel_idle_timeout: addr.tunnel_idle_timeout,
                dns_resolve_timeout: upstream.dns_resolve_timeout,
                user: addr.user.clone(),
              }),
            ));
          }
          super::config::Protocol::Http3 {
            tls_handshake_timeout,
            quic,
          } => {
            addresses.push(ScheduledClient::new(
              addr.weight,
              Box::new(Http3Client {
                session: SessionPool::new(
                  addr.address.clone(),
                  addr.hostname.clone(),
                  QuicConfig {
                    max_idle_timeout: quic.max_idle_timeout,
                    keep_alive_interval: quic.keep_alive_interval,
                    max_concurrent_bidi_streams: quic
                      .max_concurrent_bidi_streams,
                    initial_mtu: quic.initial_mtu,
                    send_window: quic.send_window,
                    receive_window: quic.receive_window,
                  },
                  *tls_handshake_timeout,
                  upstream.dns_resolve_timeout,
                ),
                tunnel_idle_timeout: addr.tunnel_idle_timeout,
                user: addr.user.clone(),
              }),
            ));
          }
        }
      }

      entries.insert(
        upstream_name,
        Rc::new(Upstream {
          clients: addresses,
          request_timeout: upstream.request_timeout,
        }),
      );
    }

    Ok(Self { entries, tls_config, tracker })
  }

  pub(crate) fn get_upstream(
    &self,
    name: &str,
  ) -> Result<Rc<Upstream>, UpstreamError> {
    self
      .entries
      .get(name)
      .ok_or_else(|| {
        UpstreamError::ProxyInternalError(format!(
          "upstream '{name}' not found"
        ))
      })
      .cloned()
  }

  pub(crate) fn contains_upstream(&self, name: &str) -> bool {
    self.entries.contains_key(name)
  }

  pub(crate) fn len(&self) -> usize {
    self.entries.len()
  }

  pub(crate) fn tls_config(&self) -> Option<Arc<rustls::ClientConfig>> {
    self.tls_config.clone()
  }

  pub(crate) fn tracker(&self) -> Rc<StreamTracker> {
    self.tracker.clone()
  }

  pub(crate) fn close_all(&self) {
    for upstream in self.entries.values() {
      for client in &upstream.clients {
        client.item().close();
      }
    }
  }
}
