//! module: listeners::https
//! responsibility: serve routed HTTP connections over authenticated
//! TLS
//! public operations: listener_name, props, create_listener_builder
//! data entities: HttpsListenerArgs, HttpsListener
//! tests: https_tests.rs

//! HTTPS listener implementation.
//!
//! This listener handles HTTPS (HTTP/1.1 over TLS) connections.
//! TLS configuration is provided at the server level via routing table.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;
use tokio::time::timeout;
use tracing::warn;

use crate::config::{ListenerPropertyValues, SerializedArgs};
use crate::listener::{
  BuildListener, Listener, Listening, TransportLayer,
};
use crate::listeners::http_service::HttpService;
use crate::listeners::tcp_accept::AcceptRetryDelay;
use crate::listeners::tcp_listener_base::TcpListenerBase;
use crate::server::{Server, ServerRouter};
use crate::tls::build_tls_server_config;

/// Default TLS handshake timeout.
const DEFAULT_TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// HTTPS Listener configuration arguments.
#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
struct HttpsListenerArgs {
  #[serde(flatten)]
  tcp_options: crate::tcp_options::TcpOptions,
  /// TLS handshake timeout (default: 5s).
  /// Protects against slow clients holding connections during TLS
  /// negotiation.
  #[serde(
    with = "humantime_serde",
    default = "default_tls_handshake_timeout"
  )]
  tls_handshake_timeout: Duration,
  #[serde(default = "super::http_connection::default_keep_alive")]
  keep_alive: bool,
  #[serde(default)]
  header_read_timeout: super::header_deadline::HeaderDeadline,
  #[serde(default)]
  tcp_accept_retry_delay: AcceptRetryDelay,
}

impl Default for HttpsListenerArgs {
  fn default() -> Self {
    Self {
      tcp_options: Default::default(),
      tls_handshake_timeout: DEFAULT_TLS_HANDSHAKE_TIMEOUT,
      header_read_timeout: Default::default(),
      keep_alive: true,
      tcp_accept_retry_delay: Default::default(),
    }
  }
}

fn default_tls_handshake_timeout() -> Duration {
  DEFAULT_TLS_HANDSHAKE_TIMEOUT
}

/// Load TLS server configuration from server routing table.
///
/// This function builds a TLS config that includes certificates from
/// all servers in the routing table, enabling SNI-based certificate
/// selection.
fn load_tls_config_from_servers(
  servers: &[Server],
) -> Result<Arc<rustls::ServerConfig>> {
  // Use HTTP/1.1 ALPN
  build_tls_server_config(servers, vec![b"http/1.1".to_vec()])
}

/// HTTPS Listener with shared-address routing support.
struct HttpsListener {
  /// Listening addresses
  addresses: Vec<SocketAddr>,
  /// TLS configuration
  tls_config: Arc<rustls::ServerConfig>,
  /// Routing table for hostname-based routing
  server_router: ServerRouter,
  /// TLS handshake timeout
  tls_handshake_timeout: Duration,
  header_deadline: super::header_deadline::HeaderDeadline,
  keep_alive: bool,
  tcp_accept_retry_delay: AcceptRetryDelay,
  /// Shared TCP listener base for lifecycle management
  base: TcpListenerBase,
}

impl HttpsListener {
  fn build(
    addresses: Vec<String>,
    sargs: SerializedArgs,
    server_routing_table: Vec<Server>,
  ) -> Result<Listener> {
    let _args: HttpsListenerArgs = serde_yaml::from_value(sargs)?;

    let tls_handshake_timeout = _args.tls_handshake_timeout;
    anyhow::ensure!(
      !tls_handshake_timeout.is_zero()
        && std::time::Instant::now()
          .checked_add(tls_handshake_timeout)
          .is_some(),
      "tls_handshake_timeout must be positive and representable"
    );

    // Build TLS config from all servers' certificates (SNI-based
    // selection)
    let tls_config =
      load_tls_config_from_servers(&server_routing_table)?;

    // Parse addresses - any invalid address is an error
    let addresses: Vec<SocketAddr> = addresses
      .iter()
      .map(|addr| {
        addr
          .parse::<SocketAddr>()
          .with_context(|| format!("Invalid address: {}", addr))
      })
      .collect::<Result<Vec<_>>>()?;

    Ok(Listener::new(Self {
      addresses,
      tls_config,
      server_router: ServerRouter::build(server_routing_table),
      tls_handshake_timeout,
      header_deadline: _args.header_read_timeout,
      keep_alive: _args.keep_alive,
      tcp_accept_retry_delay: _args.tcp_accept_retry_delay,
      base: TcpListenerBase::new().with_tcp_options(_args.tcp_options),
    }))
  }
}

impl Listening for HttpsListener {
  fn start(&self) -> Result<Pin<Box<dyn Future<Output = Result<()>>>>> {
    let tls_acceptor =
      tokio_rustls::TlsAcceptor::from(self.tls_config.clone());
    let router = self.server_router.clone();
    let handshake_timeout = self.tls_handshake_timeout;
    let header_deadline = self.header_deadline;
    let keep_alive = self.keep_alive;
    self.base.start(
      &self.addresses,
      "HTTPS",
      self.tcp_accept_retry_delay,
      move |connection| {
        let tls_acceptor = tls_acceptor.clone();
        let router = router.clone();
        async move {
          let peer = connection.peer_addr;
          match timeout(
            handshake_timeout,
            tls_acceptor.accept(connection.stream),
          )
          .await
          {
            Ok(Ok(stream)) => {
              // TLS has already verified any presented certificate
              // against the listener's combined CA roots;
              // routing enforces presence.
              let presented = stream
                .get_ref()
                .1
                .peer_certificates()
                .is_some_and(|certificates| !certificates.is_empty());
              let service = HttpService::new_tls(
                router,
                peer,
                connection.local_addr,
                presented,
              );
              if let Err(error) = super::http_connection::serve(
                stream,
                service,
                header_deadline,
                keep_alive,
                connection.shutdown,
              )
              .await
              {
                warn!(
                  "connection from {peer} on {}: {error}",
                  connection.local_addr
                );
              }
            }
            Ok(Err(error)) => {
              warn!("TLS handshake failed from {peer}: {error}")
            }
            Err(_) => warn!("TLS handshake timeout from {peer}"),
          }
        }
      },
    )
  }

  fn stop(&self) {
    self.base.stop();
  }
}

/// Get the listener name
pub(crate) fn listener_name() -> &'static str {
  "https"
}

/// Get listener properties for conflict detection.
pub(crate) fn props() -> ListenerPropertyValues {
  ListenerPropertyValues::new(TransportLayer::Tcp, true, true)
}

/// Create a listener builder
pub(crate) fn create_listener_builder() -> Box<dyn BuildListener> {
  Box::new(HttpsListener::build)
}
