//! HTTPS listener implementation.
//!
//! This listener handles HTTPS (HTTP/1.1 over TLS) connections.
//! TLS configuration is provided at the server level via routing table.

#![allow(clippy::await_holding_refcell_ref)]

use std::future;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use hyper_util::rt as rt_util;
use hyper_util::server::conn::auto as conn_util;
use serde::Deserialize;
use tokio::time::timeout;
use tracing::{error, info, warn};

use crate::config::SerializedArgs;
use crate::listener::{
  BuildListener, Listener, ListenerProps, Listening, TransportLayer,
};
use crate::listeners::http_service::HttpServiceAdaptor;
use crate::listeners::tcp_listener_base::TcpListenerBase;
use crate::server::Server;
use crate::tls::build_tls_server_config;

/// Executor for spawning tasks on the current tokio LocalSet.
#[derive(Clone)]
struct TokioLocalExecutor;

impl<F> hyper::rt::Executor<F> for TokioLocalExecutor
where
  F: Future + 'static,
{
  fn execute(&self, fut: F) {
    tokio::task::spawn_local(fut);
  }
}

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
}

impl Default for HttpsListenerArgs {
  fn default() -> Self {
    Self { tls_handshake_timeout: DEFAULT_TLS_HANDSHAKE_TIMEOUT }
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

/// Check whether the client presented a certificate during TLS
/// handshake.
fn get_client_cert_presented(
  conn: &tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> bool {
  let (_, session) = conn.get_ref();
  session.peer_certificates().is_some()
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
  /// Shared TCP listener base for lifecycle management
  base: TcpListenerBase,
}

impl HttpsListener {
  #[allow(clippy::new_ret_no_self)]
  fn new(
    addresses: Vec<String>,
    sargs: SerializedArgs,
    server_routing_table: Vec<Server>,
  ) -> Result<Listener> {
    let _args: HttpsListenerArgs = serde_yaml::from_value(sargs)?;

    let tls_handshake_timeout = _args.tls_handshake_timeout;

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

    let accepting_fut = async move {
      info!("HTTPS listener started on {}", addr);

      let shutdown = async move || shutdown_handle.notified().await;
      let accepting = || async {
        match listener.accept().await {
          Err(e) => {
            error!("accepting new connection failed: {}", e);
          }
          Ok((stream, raddr)) => {
            let local_addr = match stream.local_addr() {
              Ok(addr) => addr,
              Err(e) => {
                warn!("failed to get local addr from {}: {}", raddr, e);
                return;
              }
            };
            let tls_acceptor =
              tokio_rustls::TlsAcceptor::from(tls_config.clone());
            let io = rt_util::TokioIo::new(stream);

            match timeout(
              tls_handshake_timeout,
              tls_acceptor.accept(io.into_inner()),
            )
            .await
            {
              Ok(Ok(tls_stream)) => {
                // Extract client cert info from TLS connection
                let client_cert_presented =
                  get_client_cert_presented(&tls_stream);

                let io = rt_util::TokioIo::new(tls_stream);
                let svc = HttpServiceAdaptor::new_https(
                  server_routing_table.clone(),
                  Some(raddr),
                  Some(local_addr),
                  client_cert_presented,
                );
                let builder =
                  conn_util::Builder::new(TokioLocalExecutor);
                stream_tracker.register(async move {
                  let conn =
                    builder.serve_connection_with_upgrades(io, svc);
                  if let Err(e) = conn.await {
                    warn!(
                      "connection from {raddr} on {local_addr}: {e}"
                    );
                  }
                });
              }
              Ok(Err(e)) => {
                warn!("TLS handshake failed from {}: {}", raddr, e);
              }
              Err(_elapsed) => {
                warn!("TLS handshake timeout from {}", raddr);
              }
            }
          }
        }
      };

      loop {
        tokio::select! {
            _ = accepting() => {},
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
pub fn listener_name() -> &'static str {
  "https"
}

/// Get listener properties for conflict detection.
pub fn props() -> ListenerProps {
  ListenerProps::new(TransportLayer::Tcp, true)
}

/// Create a listener builder
pub fn create_listener_builder() -> Box<dyn BuildListener> {
  Box::new(HttpsListener::new)
}
