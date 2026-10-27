//! module: listeners::http3
//! responsibility: own HTTP/3 listener admission and draining
//! public operations: listener_name, props, create_listener_builder
//! data entities: Http3Listener
//! tests: http3_tests.rs

use crate::config::ListenerPropertyValues;
mod accepting_connection;
mod body_boundary;
#[cfg(test)]
mod body_boundary_tests;
mod connection;
mod quic_bind;
mod quic_config;
mod recv_body;
mod request_stream;
mod stream_handler;
mod transport;
mod upgrade;

#[cfg(test)]
mod quic_bind_tests;
#[cfg(test)]
mod quic_config_tests;
#[cfg(test)]
mod recv_body_tests;
#[cfg(test)]
mod stream_handler_tests;

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;

use anyhow::{Context as AnyhowContext, Result, anyhow};
use connection::handle_h3_connection;
use quic_config::{Http3ListenerArgs, QuicConfig};
use quinn::crypto::rustls::QuicServerConfig;
use tracing::{info, warn};
use transport::Transport;

use crate::config::SerializedArgs;
use crate::listener::{
  BuildListener, Listener, Listening, TransportLayer,
};
use crate::shutdown::{LISTENER_SHUTDOWN_TIMEOUT, ShutdownHandle};
use crate::tls::build_tls_server_config;
use crate::tracker::{ABORT_DRAIN_TIMEOUT, StreamTracker};

/// ALPN protocol for HTTP/3
const H3_ALPN: &[u8] = b"h3";

// ============================================================================
// HTTP/3 Listener
// ============================================================================

/// HTTP/3 Listener implementation with shared-address routing support.
struct Http3Listener {
  /// Listening addresses
  addresses: Vec<SocketAddr>,
  /// TLS configuration
  tls_config: Arc<rustls::ServerConfig>,
  /// QUIC configuration
  quic_config: QuicConfig,
  header_deadline: super::header_deadline::HeaderDeadline,
  /// Routing table for hostname-based routing
  server_router: crate::server::ServerRouter,
  /// Stream tracker
  stream_tracker: Rc<StreamTracker>,
  /// Transport survives request draining and plugin uninstall.
  transport: Rc<Transport>,
  /// Shutdown handle
  shutdown_handle: ShutdownHandle,
}

impl Http3Listener {
  /// Create a new HTTP/3 Listener
  fn build(
    addresses: Vec<String>,
    sargs: SerializedArgs,
    server_routing_table: Vec<crate::server::Server>,
  ) -> Result<Listener> {
    let args: Http3ListenerArgs = serde_yaml::from_value(sargs)?;

    // Parse addresses
    let addresses: Vec<SocketAddr> = addresses
      .iter()
      .map(|addr| {
        addr
          .parse::<SocketAddr>()
          .with_context(|| format!("Invalid address: {}", addr))
      })
      .collect::<Result<Vec<_>>>()?;

    // Validate and apply QUIC config defaults
    let quic_config = match &args.quic {
      Some(quic_args) => quic_args.validate_and_apply_defaults()?,
      None => QuicConfig::default(),
    };

    // TLS config is required for HTTP/3 listener
    // Check that at least one server has TLS configured
    let has_tls = server_routing_table.iter().any(|e| e.tls.is_some());
    if !has_tls {
      anyhow::bail!(
        "http3 listener requires server-level tls configuration"
      );
    }

    // Build TLS config from all servers' certificates (SNI-based
    // selection)
    let tls_config = build_tls_server_config(
      &server_routing_table,
      vec![H3_ALPN.to_vec()],
    )?;

    Ok(Listener::new(Self {
      addresses,
      tls_config,
      quic_config,
      header_deadline: args.header_read_timeout,
      server_router: crate::server::ServerRouter::build(
        server_routing_table,
      ),
      stream_tracker: Rc::new(StreamTracker::new()),
      transport: Rc::new(Transport::new()),
      shutdown_handle: ShutdownHandle::new(),
    }))
  }
}

impl Listening for Http3Listener {
  fn start(&self) -> Result<Pin<Box<dyn Future<Output = Result<()>>>>> {
    let addresses = self.addresses.clone();
    let tls_config = self.tls_config.clone();
    let quic_config = self.quic_config.clone();
    let header_deadline = self.header_deadline;
    let stream_tracker = self.stream_tracker.clone();
    let transport = self.transport.clone();
    let shutdown_handle = self.shutdown_handle.clone();
    let server_router = self.server_router.clone();

    // Create Quinn server config
    let quic_server_config =
      QuicServerConfig::try_from(tls_config.as_ref().clone())?;
    let mut server_config =
      quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));

    // Apply QUIC parameters
    let mut transport_config = quinn::TransportConfig::default();
    transport_config
      .max_concurrent_bidi_streams(
        quinn::VarInt::try_from(
          quic_config.max_concurrent_bidi_streams,
        )
        .map_err(|e| {
          anyhow!("Invalid max_concurrent_bidi_streams: {}", e)
        })?,
      )
      .max_idle_timeout(Some(
        quinn::VarInt::try_from(quic_config.max_idle_timeout_ms)
          .map_err(|e| anyhow!("Invalid max_idle_timeout_ms: {}", e))?
          .into(),
      ))
      .initial_mtu(quic_config.initial_mtu)
      .send_window(quic_config.send_window)
      .receive_window(
        quinn::VarInt::try_from(quic_config.receive_window)
          .map_err(|e| anyhow!("Invalid receive_window: {}", e))?,
      );

    server_config.transport_config(Arc::new(transport_config));

    // Create endpoints for all addresses
    let mut endpoints: Vec<quinn::Endpoint> = Vec::new();
    for address in &addresses {
      let endpoint = transport.bind(*address, server_config.clone())?;
      endpoints.push(endpoint);
    }

    // Log all bound addresses
    let addrs_str: Vec<String> =
      addresses.iter().map(|a| a.to_string()).collect();
    info!("HTTP/3 Listener started on {}", addrs_str.join(", "));

    // Channel to receive incoming connections from all endpoints
    let (conn_tx, mut conn_rx) =
      tokio::sync::mpsc::channel::<(SocketAddr, quinn::Incoming)>(32);

    // Spawn accept task for each endpoint
    // These clones stay within this worker. Other workers bind
    // independent sockets and own independent endpoint drivers.
    let endpoints: Vec<Arc<quinn::Endpoint>> =
      endpoints.into_iter().map(Arc::new).collect();
    for endpoint in endpoints.clone() {
      let conn_tx = conn_tx.clone();
      let shutdown_handle = shutdown_handle.clone();
      let local_addr = endpoint.local_addr()?;
      transport.spawn(async move {
          loop {
            tokio::select! {
              biased;
              _ = shutdown_handle.notified() => break,
              conn = endpoint.accept() => {
                match conn {
                  Some(incoming) => {
                    if conn_tx.send((local_addr, incoming)).await.is_err() {
                      break;
                    }
                  }
                  None => break,
                }
              }
            }
          }
        });
    }
    // Drop the original sender so conn_rx will end when all spawn
    // tasks end
    drop(conn_tx);

    Ok(Box::pin(async move {
      // Accept connections loop
      loop {
        let accept_result = tokio::select! {
          biased;
          _ = shutdown_handle.notified() => {
            break;
          }
          res = conn_rx.recv() => res,
        };

        match accept_result {
          Some((local_addr, conn)) => {
            let server_router = server_router.clone();
            let tracker_for_handler = stream_tracker.clone();
            let stream_shutdown = tracker_for_handler.shutdown_handle();

            transport.spawn(async move {
              let handshake = tokio::select! {
                biased;
                _ = stream_shutdown.notified() => return,
                result = conn => result,
              };
              match handshake {
                Ok(quinn_conn) => {
                  let local_addr =
                    quinn_conn.local_ip().map_or(local_addr, |ip| {
                      SocketAddr::new(ip, local_addr.port())
                    });
                  handle_h3_connection(
                    quinn_conn,
                    server_router,
                    tracker_for_handler,
                    stream_shutdown,
                    local_addr,
                    header_deadline,
                  )
                  .await;
                }
                Err(e) => {
                  warn!("Connection failed: {e}");
                }
              }
            });
          }
          None => {
            // All endpoints closed
            break;
          }
        }
      }

      // Stop new QUIC handshakes without closing established
      // connections or removing sockets from the reuseport group.
      for endpoint in &endpoints {
        endpoint.set_server_config(None);
      }
      conn_rx.close();
      while conn_rx.try_recv().is_ok() {}

      // Wait for active streams with timeout
      let wait_result = tokio::time::timeout(
        LISTENER_SHUTDOWN_TIMEOUT,
        stream_tracker.wait_shutdown(),
      )
      .await;

      if wait_result.is_err() {
        warn!(
          "HTTP/3 Listener shutdown timeout ({:?}) expired, aborting \
           {} remaining streams",
          LISTENER_SHUTDOWN_TIMEOUT,
          stream_tracker.active_count()
        );
        stream_tracker.abort_all();
        // Use the same cancellation cleanup budget as TCP listeners
        // and upstream tasks.
        if stream_tracker
          .wait_shutdown_with_timeout(ABORT_DRAIN_TIMEOUT)
          .await
          .is_err()
        {
          warn!(
            "Some tasks did not terminate after abort within {:?}",
            ABORT_DRAIN_TIMEOUT
          );
        }
      }

      info!("HTTP/3 Listener requests drained");
      Ok(())
    }))
  }

  fn stop(&self) {
    // Stop new connections and tell H3 drivers to send GOAWAY. Ordinary
    // request handlers keep running within the listener budget;
    // established tunnels are stopped later by their Service owner.
    self.shutdown_handle.shutdown();
    self.stream_tracker.shutdown();
  }

  fn finish(&self) -> Pin<Box<dyn Future<Output = ()>>> {
    let transport = self.transport.clone();
    Box::pin(async move { transport.drain().await })
  }
}

// ============================================================================
// Plugin Registration
// ============================================================================

/// Get the listener name
pub(crate) fn listener_name() -> &'static str {
  "http3"
}

/// Get listener properties for conflict detection.
pub(crate) fn props() -> ListenerPropertyValues {
  ListenerPropertyValues::new(TransportLayer::Udp, true)
}

/// Create a listener builder
pub(crate) fn create_listener_builder() -> Box<dyn BuildListener> {
  Box::new(Http3Listener::build)
}
