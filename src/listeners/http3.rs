#![allow(clippy::await_holding_refcell_ref)]
mod quic_config;
mod recv_body;
mod stream_handler;

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
use std::time::Duration;

use anyhow::{Context as AnyhowContext, Result, anyhow};
use quic_config::{H3_NO_ERROR_CODE, Http3ListenerArgs, QuicConfig};
use quinn::crypto::rustls::QuicServerConfig;
use stream_handler::handle_h3_connection;
use tracing::{info, warn};

use super::LISTENER_SHUTDOWN_TIMEOUT;
use crate::config::SerializedArgs;
use crate::listener::{
  BuildListener, Listener, ListenerProps, Listening, TransportLayer,
};
use crate::shutdown::ShutdownHandle;
use crate::tls::build_tls_server_config;
use crate::tracker::StreamTracker;

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
  /// Routing table for hostname-based routing
  server_routing_table: Vec<crate::server::Server>,
  /// Stream tracker
  stream_tracker: Rc<StreamTracker>,
  /// Shutdown handle
  shutdown_handle: ShutdownHandle,
}

impl Http3Listener {
  /// Create a new HTTP/3 Listener
  #[allow(clippy::new_ret_no_self)]
  fn new(
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
      server_routing_table,
      stream_tracker: Rc::new(StreamTracker::new()),
      shutdown_handle: ShutdownHandle::new(),
    }))
  }
}

impl Listening for Http3Listener {
  fn start(&self) -> Pin<Box<dyn Future<Output = Result<()>>>> {
    let addresses = self.addresses.clone();
    let tls_config = self.tls_config.clone();
    let quic_config = self.quic_config.clone();
    let stream_tracker = self.stream_tracker.clone();
    let shutdown_handle = self.shutdown_handle.clone();
    let server_routing_table = self.server_routing_table.clone();

    Box::pin(async move {
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
        let endpoint =
          quinn::Endpoint::server(server_config.clone(), *address)?;
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
      // Note: We share endpoints with Arc for concurrent access
      let endpoints: Vec<Arc<quinn::Endpoint>> =
        endpoints.into_iter().map(Arc::new).collect();
      for endpoint in endpoints.clone() {
        let conn_tx = conn_tx.clone();
        let shutdown_handle = shutdown_handle.clone();
        tokio::spawn(async move {
          loop {
            tokio::select! {
              conn = endpoint.accept() => {
                match conn {
                  Some(incoming) => {
                    let local_addr = endpoint
                      .local_addr()
                      .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
                    if conn_tx.send((local_addr, incoming)).await.is_err() {
                      break;
                    }
                  }
                  None => break,
                }
              }
              _ = shutdown_handle.notified() => {
                break;
              }
            }
          }
        });
      }
      // Drop the original sender so conn_rx will end when all spawn
      // tasks end
      drop(conn_tx);

      // Accept connections loop
      loop {
        let accept_result = tokio::select! {
          res = conn_rx.recv() => res,
          _ = shutdown_handle.notified() => {
            // Graceful shutdown
            break;
          }
        };

        match accept_result {
          Some((local_addr, conn)) => {
            let server_routing_table = server_routing_table.clone();
            let tracker_for_register = stream_tracker.clone();
            let tracker_for_handler = stream_tracker.clone();
            let stream_shutdown = tracker_for_handler.shutdown_handle();

            tracker_for_register.register_connection(async move {
              match conn.await {
                Ok(quinn_conn) => {
                  let local_addr =
                    quinn_conn.local_ip().map_or(local_addr, |ip| {
                      SocketAddr::new(ip, local_addr.port())
                    });
                  handle_h3_connection(
                    quinn_conn,
                    server_routing_table,
                    tracker_for_handler,
                    stream_shutdown,
                    local_addr,
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
        // Wait for aborted tasks to be cleaned up with a short timeout
        // Aborted tasks should finish quickly, but we add a safety
        // timeout
        const ABORT_WAIT_TIMEOUT: Duration = Duration::from_millis(100);
        if stream_tracker
          .wait_shutdown_with_timeout(ABORT_WAIT_TIMEOUT)
          .await
          .is_err()
        {
          warn!(
            "Some tasks did not terminate after abort within {:?}",
            ABORT_WAIT_TIMEOUT
          );
        }
      }

      // Close all endpoints with H3_NO_ERROR code for graceful shutdown
      for endpoint in &endpoints {
        endpoint.close(
          quinn::VarInt::from_u32(H3_NO_ERROR_CODE),
          b"listener shutdown",
        );
      }

      info!("HTTP/3 Listener stopped");
      Ok(())
    })
  }

  fn stop(&self) {
    // Step 1: Trigger shutdown notification to stop accepting new
    // connections
    self.shutdown_handle.shutdown();

    // Step 2: Notify all active streams to stop
    // This is required per architecture doc section 2.3.1
    self.stream_tracker.shutdown();
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
pub(crate) fn props() -> ListenerProps {
  ListenerProps::new(TransportLayer::Udp, true)
}

/// Create a listener builder
pub(crate) fn create_listener_builder() -> Box<dyn BuildListener> {
  Box::new(Http3Listener::new)
}
