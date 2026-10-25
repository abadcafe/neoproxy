//! HTTPS listener implementation.
//!
//! This listener handles HTTPS (HTTP/1.1 over TLS) connections.
//! TLS configuration is provided at the server level via routing table.

use std::future;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use hyper_util::rt as rt_util;
use serde::Deserialize;
use tokio::time::timeout;
use tracing::{info, warn};

use crate::config::SerializedArgs;
use crate::listener::{
  BuildListener, Listener, ListenerProps, Listening, TransportLayer,
};
use crate::listeners::http_service::HttpServiceAdaptor;
use crate::listeners::tcp_accept::{self, AcceptRetryDelay};
use crate::listeners::tcp_listener_base::TcpListenerBase;
use crate::server::Server;
use crate::tls::build_tls_server_config;

/// Default TLS handshake timeout.
const DEFAULT_TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// HTTPS Listener configuration arguments.
#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
struct HttpsListenerArgs {
  /// TLS handshake timeout (default: 5s).
  /// Protects against slow clients holding connections during TLS
  /// negotiation.
  #[serde(
    with = "humantime_serde",
    default = "default_tls_handshake_timeout"
  )]
  tls_handshake_timeout: Duration,
  #[serde(default)]
  header_read_timeout: super::http_connection::HeaderDeadline,
  #[serde(default)]
  accept_retry_delay: AcceptRetryDelay,
}

impl Default for HttpsListenerArgs {
  fn default() -> Self {
    Self {
      tls_handshake_timeout: DEFAULT_TLS_HANDSHAKE_TIMEOUT,
      header_read_timeout: Default::default(),
      accept_retry_delay: Default::default(),
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
  server_routing_table: Vec<Server>,
  /// TLS handshake timeout
  tls_handshake_timeout: Duration,
  header_deadline: super::http_connection::HeaderDeadline,
  accept_retry_delay: AcceptRetryDelay,
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

    // TLS config is required for https listener
    // Check that at least one server has TLS configured
    let has_tls = server_routing_table.iter().any(|e| e.tls.is_some());
    if !has_tls {
      bail!("https listener requires server-level tls configuration");
    }

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
      server_routing_table,
      tls_handshake_timeout,
      header_deadline: _args.header_read_timeout,
      accept_retry_delay: _args.accept_retry_delay,
      base: TcpListenerBase::new(),
    }))
  }

  fn serve_addr(
    &self,
    addr: SocketAddr,
  ) -> Result<Pin<Box<dyn Future<Output = Result<()>>>>> {
    let listener = super::tcp_bind::create_tcp_listener(addr)?;

    let tls_config = self.tls_config.clone();
    let stream_tracker = self.base.stream_tracker();
    let shutdown_handle = self.base.shutdown_handle();
    let server_routing_table = self.server_routing_table.clone();
    let tls_handshake_timeout = self.tls_handshake_timeout;
    let header_deadline = self.header_deadline;
    let accept_retry_delay = self.accept_retry_delay;

    let accepting_fut = async move {
      info!("HTTPS listener started on {}", addr);

      let shutdown = || shutdown_handle.notified();
      let accepting = || async {
        match tcp_accept::accept(addr, accept_retry_delay, || {
          listener.accept()
        })
        .await
        {
          Err(error) => return Err(error),
          Ok((stream, raddr)) => {
            let local_addr = match stream.local_addr() {
              Ok(addr) => addr,
              Err(e) => {
                warn!("failed to get local addr from {}: {}", raddr, e);
                return Ok(());
              }
            };
            let tls_acceptor =
              tokio_rustls::TlsAcceptor::from(tls_config.clone());
            let io = rt_util::TokioIo::new(stream);

            let server_routing_table = server_routing_table.clone();
            let connection_shutdown = shutdown_handle.clone();
            stream_tracker.register(async move {
              match timeout(
                tls_handshake_timeout,
                tls_acceptor.accept(io.into_inner()),
              )
              .await
              {
                Ok(Ok(tls_stream)) => {
                  // Successful TLS authentication already verified
                  // any client certificate against this listener's
                  // combined CA roots. Requests only need the presence
                  // bit to enforce a routed server's mTLS requirement.
                  let client_cert_presented = tls_stream
                    .get_ref()
                    .1
                    .peer_certificates()
                    .is_some_and(|certificates| {
                      !certificates.is_empty()
                    });

                  let svc = HttpServiceAdaptor::new_https(
                    server_routing_table.clone(),
                    Some(raddr),
                    Some(local_addr),
                    client_cert_presented,
                  );
                  if let Err(error) = super::http_connection::serve(
                    tls_stream,
                    svc,
                    header_deadline,
                    connection_shutdown,
                  )
                  .await
                  {
                    warn!(
                      "connection from {raddr} on {local_addr}: \
                       {error}"
                    );
                  }
                }
                Ok(Err(e)) => {
                  warn!("TLS handshake failed from {}: {}", raddr, e);
                }
                Err(_elapsed) => {
                  warn!("TLS handshake timeout from {}", raddr);
                }
              }
            });
          }
        }
        Ok::<(), std::io::Error>(())
      };

      loop {
        tokio::select! {
            result = accepting() => result.with_context(|| format!("HTTPS accept failed on {addr}"))?,
            _ = shutdown() => {
                info!("HTTPS listener on {} shutting down", addr);
                break;
            },
        }
      }

      Ok(())
    };

    Ok(Box::pin(accepting_fut))
  }
}

impl Listening for HttpsListener {
  fn start(&self) -> Pin<Box<dyn Future<Output = Result<()>>>> {
    let mut tasks = Vec::new();
    for addr in &self.addresses {
      let addr = *addr;
      match self.serve_addr(addr) {
        Ok(f) => tasks.push(f),
        Err(e) => return Box::pin(future::ready(Err(e))),
      }
    }
    self.base.start_with_tasks(tasks)
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
pub(crate) fn props() -> ListenerProps {
  ListenerProps::new(TransportLayer::Tcp, true)
}

/// Create a listener builder
pub(crate) fn create_listener_builder() -> Box<dyn BuildListener> {
  Box::new(HttpsListener::build)
}
