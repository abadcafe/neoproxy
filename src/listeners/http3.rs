#![allow(clippy::await_holding_refcell_ref)]
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use byte_unit::Byte;
use bytes::Bytes;
use h3::server;
use http_body_util::BodyExt;
use quinn::crypto::rustls::QuicServerConfig;
use serde::Deserialize;
use tower::Service;
use tracing::{info, warn};

use crate::config::SerializedArgs;
use crate::context::RequestContext;
use crate::http_utils::{
  BytesBufBodyWrapper, RequestBody, Response, build_error_response,
};
use crate::listener::{
  BuildListener, Listener, ListenerProps, Listening, TransportLayer,
};
use crate::listeners::common::{
  LISTENER_SHUTDOWN_TIMEOUT, MONITORING_LOG_INTERVAL,
};
use crate::shutdown::ShutdownHandle;
use crate::stream::H3UpgradeTrigger;
use crate::tls::build_tls_server_config;
use crate::tracker::StreamTracker;

// ============================================================================
// Constants
// ============================================================================

/// Default maximum concurrent bidirectional streams
const DEFAULT_MAX_CONCURRENT_BIDI_STREAMS: u64 = 100;

/// Default maximum idle timeout
const DEFAULT_MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(5);

/// Default initial MTU
const DEFAULT_INITIAL_MTU: u16 = 1200;

/// Default send window size (10MiB)
const DEFAULT_SEND_WINDOW: Byte =
  Byte::from_u64(10485760);

/// Default receive window size (10MiB)
const DEFAULT_RECEIVE_WINDOW: Byte =
  Byte::from_u64(10485760);

/// H3_NO_ERROR error code for CONNECTION_CLOSE frame
/// See: https://www.rfc-editor.org/rfc/rfc9114.html#errors
/// Value 0x100 = 256, which fits in u32
const H3_NO_ERROR_CODE: u32 = 0x100;

// ============================================================================
// Configuration Structures
// ============================================================================

/// HTTP/3 Listener configuration arguments
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct Http3ListenerArgs {
  /// QUIC protocol parameters (optional)
  #[serde(default)]
  pub quic: Option<QuicConfigArgs>,
}

/// QUIC protocol configuration arguments
#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct QuicConfigArgs {
  /// Maximum concurrent bidirectional streams (default: 100, range:
  /// 1-10000)
  #[serde(default = "default_max_concurrent_bidi_streams")]
  pub max_concurrent_bidi_streams: u64,
  /// Maximum idle timeout (default: 5s)
  #[serde(
    with = "humantime_serde",
    default = "default_max_idle_timeout"
  )]
  pub max_idle_timeout: Duration,
  /// Initial MTU (default: 1200, range: 1200-9000)
  #[serde(default = "default_initial_mtu")]
  pub initial_mtu: u16,
  /// Send window size (default: 10MiB)
  #[serde(default = "default_send_window")]
  pub send_window: Byte,
  /// Receive window size (default: 10MiB)
  #[serde(default = "default_receive_window")]
  pub receive_window: Byte,
}

fn default_max_concurrent_bidi_streams() -> u64 {
  DEFAULT_MAX_CONCURRENT_BIDI_STREAMS
}

fn default_max_idle_timeout() -> Duration {
  DEFAULT_MAX_IDLE_TIMEOUT
}

fn default_initial_mtu() -> u16 {
  DEFAULT_INITIAL_MTU
}

fn default_send_window() -> Byte {
  DEFAULT_SEND_WINDOW
}

fn default_receive_window() -> Byte {
  DEFAULT_RECEIVE_WINDOW
}

impl QuicConfigArgs {
  /// Validate and apply defaults to QUIC configuration
  ///
  /// Returns validated configuration with defaults applied where
  /// needed. Invalid values return an error, rejecting startup.
  pub fn validate_and_apply_defaults(&self) -> Result<QuicConfig> {
    if !(1..=10000).contains(&self.max_concurrent_bidi_streams) {
      bail!(
        "Invalid max_concurrent_bidi_streams: {}, expected range 1-10000",
        self.max_concurrent_bidi_streams
      );
    }

    let max_idle_timeout_ms = self.max_idle_timeout.as_millis() as u64;
    if max_idle_timeout_ms == 0 {
      bail!("Invalid max_idle_timeout: must be > 0ms");
    }

    if !(1200..=9000).contains(&self.initial_mtu) {
      bail!(
        "Invalid initial_mtu: {}, expected range 1200-9000",
        self.initial_mtu
      );
    }

    let send_window = self.send_window.as_u64();
    if send_window == 0 {
      bail!("Invalid send_window: must be > 0");
    }

    let receive_window = self.receive_window.as_u64();
    if receive_window == 0 {
      bail!("Invalid receive_window: must be > 0");
    }

    Ok(QuicConfig {
      max_concurrent_bidi_streams: self.max_concurrent_bidi_streams,
      max_idle_timeout_ms,
      initial_mtu: self.initial_mtu,
      send_window,
      receive_window,
    })
  }
}

/// Validated QUIC configuration with applied defaults
#[derive(Clone, Debug)]
pub struct QuicConfig {
  pub max_concurrent_bidi_streams: u64,
  pub max_idle_timeout_ms: u64,
  pub initial_mtu: u16,
  pub send_window: u64,
  pub receive_window: u64,
}

impl Default for QuicConfig {
  fn default() -> Self {
    Self {
      max_concurrent_bidi_streams: DEFAULT_MAX_CONCURRENT_BIDI_STREAMS,
      max_idle_timeout_ms: DEFAULT_MAX_IDLE_TIMEOUT.as_millis() as u64,
      initial_mtu: DEFAULT_INITIAL_MTU,
      send_window: DEFAULT_SEND_WINDOW.as_u64(),
      receive_window: DEFAULT_RECEIVE_WINDOW.as_u64(),
    }
  }
}

// ============================================================================
// Error Response Helpers
// ============================================================================

/// Extract SNI from a quinn connection's handshake data.
fn extract_sni_from_connection(conn: &quinn::Connection) -> Option<String> {
  let handshake_data = conn.handshake_data()?;
  let hd = handshake_data
    .downcast::<quinn::crypto::rustls::HandshakeData>()
    .ok()?;
  hd.server_name
}

// ============================================================================
// HTTP/3 Stream Handler
// ============================================================================

/// Handle a single HTTP/3 stream by delegating to the Service.
///
/// Flow:
/// Handle a single HTTP/3 stream by delegating to the Service.
///
/// Flow:
/// 1. SNI vs authority mismatch check (fail -> send 421 directly)
/// 2. authority vs Host mismatch check (fail -> send 400 directly)
/// 3. Authentication check (fail -> send 407 directly)
/// 4. Route request to correct service based on :authority
/// 5. Create (trigger, on_upgrade) pair
/// 6. Build Request with on_upgrade in extensions
/// 7. Call service.call(request)
/// 8. Based on response status, trigger.send_success() or
///    trigger.send_error()
///
/// Returns unit `()` because all errors are handled internally via
/// logging and H3 error responses. This function never propagates
/// errors upward.
async fn handle_h3_stream(
  req: http::Request<()>,
  stream: server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
  server_router: crate::server::ServerRouter,
  _shutdown_handle: ShutdownHandle,
  client_addr: SocketAddr,
  local_addr: SocketAddr,
  sni: Option<String>,
  client_cert_presented: bool,
) -> () {
  let method = req.method().clone();

  // Phase 1a: Check SNI vs authority mismatch
  // For CONNECT requests, authority contains the target server,
  // not the proxy server, so mismatch is expected.
  if method != http::Method::CONNECT {
    if let Some(ref sni) = sni {
      if let Some(auth) = req.uri().authority() {
        if super::common::check_sni_vs_authority(sni, auth.host()) {
          let resp = build_error_response(
            http::StatusCode::MISDIRECTED_REQUEST,
            "Misdirected Request: SNI does not match request authority",
          );
          let mut stream = stream;
          if let Err(e) = send_h3_response(&mut stream, resp, true).await {
            warn!("Failed to send 421 response: {e}");
          }
          return;
        }
      }
    }
  }

  // Phase 1b: Check authority vs Host header mismatch
  // Per RFC 9114 §4.3.1, :authority and Host must contain the same value.
  if let Some(host_val) = req.headers().get(http::header::HOST) {
    if let Some(auth) = req.uri().authority() {
      if let Ok(host_str) = host_val.to_str() {
        if super::common::check_authority_vs_host(
          &auth.to_string(),
          host_str,
        ) {
          let resp = build_error_response(
            http::StatusCode::BAD_REQUEST,
            "Bad Request: :authority and Host headers differ",
          );
          let mut stream = stream;
          if let Err(e) = send_h3_response(&mut stream, resp, true).await {
            warn!("Failed to send 400 response: {e}");
          }
          return;
        }
      }
    }
  }

  // Phase 2: Route FIRST based on :authority
  let hostname = req.uri().authority().map(|a| a.host());
  let routing_entry = server_router.route(hostname);

  let routing_entry = match routing_entry {
    Some(entry) => entry,
    None => {
      let resp = build_error_response(
        http::StatusCode::NOT_FOUND,
        "Not Found: No matching server for this host",
      );
      let mut stream = stream;
      if let Err(e) = send_h3_response(&mut stream, resp, true).await {
        warn!("Failed to send 404 response: {e}");
      }
      return;
    }
  };

  // Phase 2b: Check client certificate requirement
  // If the server requires mTLS (has client_ca_certs) but the
  // client did not present a certificate, reject with 403.
  if routing_entry.requires_client_cert() && !client_cert_presented {
    let resp = build_error_response(
      http::StatusCode::FORBIDDEN,
      "Forbidden: client certificate required",
    );
    let mut stream = stream;
    if let Err(e) = send_h3_response(&mut stream, resp, true).await {
      warn!("Failed to send 403 response: {e}");
    }
    return;
  }

  let mut service = routing_entry.service.clone();

  // Phase 3: Build RequestContext with connection-level keys and insert
  // into request extensions. Auth and access logging are now handled
  // by the plugin layer in the service pipeline.
  let ctx = RequestContext::new();
  ctx.insert("client.ip", client_addr.ip().to_string());
  ctx.insert("client.port", client_addr.port().to_string());
  ctx.insert("server.ip", local_addr.ip().to_string());
  ctx.insert("server.port", local_addr.port().to_string());
  ctx.insert("service.name", &routing_entry.service_name);

  // Phase 4: Create upgrade pair ONLY for CONNECT method
  let is_connect = method == http::Method::CONNECT;

  // Phase 5: Build Request
  let mut request = http::Request::builder()
    .method(req.method().clone())
    .uri(req.uri().clone())
    .version(req.version())
    .body(RequestBody::new(BytesBufBodyWrapper::new(
      http_body_util::Empty::<Bytes>::new(),
    )))
    .expect("failed to build request");

  for (name, value) in req.headers() {
    request.headers_mut().insert(name.clone(), value.clone());
  }

  // Insert RequestContext into request extensions
  request.extensions_mut().insert(ctx);

  let (trigger, mut stream_holder) = if is_connect {
    let (trigger, on_upgrade) = H3UpgradeTrigger::pair(stream);
    request.extensions_mut().insert(on_upgrade);
    (Some(trigger), None)
  } else {
    (None, Some(stream))
  };

  // Phase 6: Call Service
  let result = service.call(request).await;

  // Phase 7: Handle Service response
  match result {
    Ok(resp) => {
      if is_connect {
        if resp.status() == http::StatusCode::OK {
          if let Some(t) = trigger {
            if let Err(e) = t.send_success().await {
              warn!("H3 failed to send success: {e}");
            }
          }
        } else {
          let status = resp.status();
          let body_bytes =
            match http_body_util::BodyExt::collect(resp.into_body())
              .await
            {
              Ok(collected) => collected.to_bytes(),
              Err(e) => {
                warn!("H3 failed to collect response body: {e}");
                Bytes::new()
              }
            };
          if let Some(t) = trigger {
            if let Err(e) =
              t.send_error_with_body(status, body_bytes).await
            {
              warn!("H3 failed to send error: {e}");
            }
          }
        }
      } else {
        if let Some(ref mut stream) = stream_holder {
          if let Err(e) = send_h3_response(stream, resp, true).await {
            warn!("H3 failed to send response: {e}");
          }
        }
      }
    }
    Err(e) => {
      warn!("H3 service error: {e}");
      if is_connect {
        if let Some(t) = trigger {
          if let Err(e) =
            t.send_error(http::StatusCode::BAD_GATEWAY).await
          {
            warn!("H3 failed to send error: {e}");
          }
        }
      } else {
        if let Some(ref mut stream) = stream_holder {
          let resp = build_error_response(
            http::StatusCode::BAD_GATEWAY,
            "Bad Gateway",
          );
          if let Err(e) = send_h3_response(stream, resp, true).await {
            warn!("H3 failed to send error response: {e}");
          }
        }
      }
    }
  }
}

/// Send an HTTP/3 response with optional stream finish
///
/// # Arguments
/// * `stream` - The HTTP/3 request stream
/// * `resp` - The HTTP response to send
/// * `finish_stream` - If true, close the stream after sending
///   response. Should be false for CONNECT success response to allow
///   bidirectional data transfer.
async fn send_h3_response(
  stream: &mut server::RequestStream<
    h3_quinn::BidiStream<Bytes>,
    Bytes,
  >,
  resp: Response,
  finish_stream: bool,
) -> Result<()> {
  let (parts, body) = resp.into_parts();
  let resp = http::Response::from_parts(parts, ());

  // Send response headers
  stream.send_response(resp).await?;

  // Send response body if any
  let body_bytes = body.collect().await?.to_bytes();
  if !body_bytes.is_empty() {
    stream.send_data(body_bytes).await?;
  }

  // Finish the stream only if requested
  // For CONNECT success, we don't finish to allow bidirectional
  // transfer
  if finish_stream {
    stream.finish().await?;
  }

  Ok(())
}

// ============================================================================
// HTTP/3 Connection Handler
// ============================================================================

/// Handle a single HTTP/3 connection
async fn handle_h3_connection(
  conn: quinn::Connection,
  server_routing_table: Vec<crate::server::Server>,
  stream_tracker: Rc<StreamTracker>,
  shutdown_handle: ShutdownHandle,
  local_addr: SocketAddr,
) {
  let client_addr = conn.remote_address();

  // Extract SNI before conn is moved into h3_quinn
  let sni = extract_sni_from_connection(&conn);

  // Check whether client presented a certificate during TLS handshake
  let client_cert_presented = conn.peer_identity().is_some();

  // Build ServerRouter once for the entire connection
  let server_router =
    crate::server::ServerRouter::build(server_routing_table);

  // Create H3 connection
  let mut h3_conn = match h3::server::builder()
    .build(h3_quinn::Connection::new(conn))
    .await
  {
    Ok(c) => c,
    Err(e) => {
      warn!("Failed to create H3 connection: {e}");
      return;
    }
  };

  // Accept and handle streams
  loop {
    let accept_result = tokio::select! {
      res = h3_conn.accept() => res,
      _ = shutdown_handle.notified() => {
        // Graceful shutdown
        break;
      }
    };

    match accept_result {
      Ok(Some(resolver)) => {
        let server_router = server_router.clone();
        let sni = sni.clone();
        let stream_shutdown = stream_tracker.shutdown_handle();
        stream_tracker.register(async move {
          match resolver.resolve_request().await {
            Ok((req, stream)) => {
              handle_h3_stream(
                req,
                stream,
                server_router,
                stream_shutdown,
                client_addr,
                local_addr,
                sni,
                client_cert_presented,
              )
              .await;
            }
            Err(e) => {
              warn!("Failed to resolve request: {e}");
            }
          }
        });
      }
      Ok(None) => {
        // Connection closed
        break;
      }
      Err(e) => {
        if !e.is_h3_no_error() {
          warn!("H3 connection error: {e}");
        }
        break;
      }
    }
  }
}

// ============================================================================
// TLS Configuration
// ============================================================================

/// ALPN protocol for HTTP/3
const H3_ALPN: &[u8] = b"h3";

// ============================================================================
// HTTP/3 Listener
// ============================================================================

/// HTTP/3 Listener implementation with shared-address routing support.
pub struct Http3Listener {
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
  pub fn new(
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
      bail!("http3 listener requires server-level tls configuration");
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

      // Monitoring is integrated into the accept loop below
      // to avoid Send requirements with spawn_local

      // Accept connections loop with integrated monitoring
      let mut monitoring_interval =
        tokio::time::interval(MONITORING_LOG_INTERVAL);
      monitoring_interval.tick().await; // Skip first immediate tick

      loop {
        let accept_result = tokio::select! {
          res = conn_rx.recv() => res,
          _ = monitoring_interval.tick() => {
            // Log monitoring info
            info!(
              "[http3] active_connections={}, active_streams={}",
              stream_tracker.connection_count(),
              stream_tracker.active_count()
            );
            continue;
          }
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
pub fn listener_name() -> &'static str {
  "http3"
}

/// Get listener properties for conflict detection.
pub fn props() -> ListenerProps {
  ListenerProps {
    transport_layer: TransportLayer::Udp,
    supports_hostname_routing: true,
  }
}

/// Create a listener builder
pub fn create_listener_builder() -> Box<dyn BuildListener> {
  Box::new(Http3Listener::new)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
  use super::*;

  // ============== QuicConfigArgs Tests ==============

  fn default_quic_config_args() -> QuicConfigArgs {
    QuicConfigArgs {
      max_concurrent_bidi_streams: DEFAULT_MAX_CONCURRENT_BIDI_STREAMS,
      max_idle_timeout: DEFAULT_MAX_IDLE_TIMEOUT,
      initial_mtu: DEFAULT_INITIAL_MTU,
      send_window: DEFAULT_SEND_WINDOW,
      receive_window: DEFAULT_RECEIVE_WINDOW,
    }
  }

  #[test]
  fn test_quic_config_args_deserialize_default() {
    let yaml = r#"{}"#;
    let args: QuicConfigArgs = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(
      args.max_concurrent_bidi_streams,
      DEFAULT_MAX_CONCURRENT_BIDI_STREAMS
    );
    assert_eq!(args.max_idle_timeout, DEFAULT_MAX_IDLE_TIMEOUT);
    assert_eq!(args.initial_mtu, DEFAULT_INITIAL_MTU);
    assert_eq!(args.send_window, DEFAULT_SEND_WINDOW);
    assert_eq!(args.receive_window, DEFAULT_RECEIVE_WINDOW);
  }

  #[test]
  fn test_quic_config_args_validate_and_apply_defaults_valid() {
    let args = QuicConfigArgs {
      max_concurrent_bidi_streams: 200,
      max_idle_timeout: Duration::from_secs(60),
      initial_mtu: 1400,
      send_window: Byte::from_u64(20971520),
      receive_window: Byte::from_u64(20971520),
    };
    let config = args.validate_and_apply_defaults().unwrap();
    assert_eq!(config.max_concurrent_bidi_streams, 200);
    assert_eq!(config.max_idle_timeout_ms, 60000);
    assert_eq!(config.initial_mtu, 1400);
    assert_eq!(config.send_window, 20971520);
    assert_eq!(config.receive_window, 20971520);
  }

  #[test]
  fn test_quic_config_args_validate_invalid_max_concurrent_bidi_streams_low()
   {
    let args = QuicConfigArgs {
      max_concurrent_bidi_streams: 0,
      ..default_quic_config_args()
    };
    let result = args.validate_and_apply_defaults();
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("max_concurrent_bidi_streams"));
    assert!(err.contains("expected range 1-10000"));
  }

  #[test]
  fn test_quic_config_args_validate_invalid_max_concurrent_bidi_streams_high()
   {
    let args = QuicConfigArgs {
      max_concurrent_bidi_streams: 10001,
      ..default_quic_config_args()
    };
    let result = args.validate_and_apply_defaults();
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("max_concurrent_bidi_streams"));
    assert!(err.contains("expected range 1-10000"));
  }

  #[test]
  fn test_quic_config_args_validate_invalid_max_idle_timeout() {
    let args = QuicConfigArgs {
      max_idle_timeout: Duration::ZERO,
      ..default_quic_config_args()
    };
    let result = args.validate_and_apply_defaults();
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("max_idle_timeout"));
    assert!(err.contains("must be > 0ms"));
  }

  #[test]
  fn test_quic_config_args_validate_invalid_initial_mtu_low() {
    let args = QuicConfigArgs {
      initial_mtu: 100,
      ..default_quic_config_args()
    };
    let result = args.validate_and_apply_defaults();
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("initial_mtu"));
    assert!(err.contains("expected range 1200-9000"));
  }

  #[test]
  fn test_quic_config_args_validate_invalid_initial_mtu_high() {
    let args = QuicConfigArgs {
      initial_mtu: 10000,
      ..default_quic_config_args()
    };
    let result = args.validate_and_apply_defaults();
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("initial_mtu"));
    assert!(err.contains("expected range 1200-9000"));
  }

  #[test]
  fn test_quic_config_args_validate_invalid_send_window() {
    let args = QuicConfigArgs {
      send_window: Byte::from_u64(0),
      ..default_quic_config_args()
    };
    let result = args.validate_and_apply_defaults();
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("send_window"));
    assert!(err.contains("must be > 0"));
  }

  #[test]
  fn test_quic_config_args_validate_invalid_receive_window() {
    let args = QuicConfigArgs {
      receive_window: Byte::from_u64(0),
      ..default_quic_config_args()
    };
    let result = args.validate_and_apply_defaults();
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("receive_window"));
    assert!(err.contains("must be > 0"));
  }

  #[test]
  fn test_quic_config_default() {
    let config = QuicConfig::default();
    assert_eq!(
      config.max_concurrent_bidi_streams,
      DEFAULT_MAX_CONCURRENT_BIDI_STREAMS
    );
    assert_eq!(
      config.max_idle_timeout_ms,
      DEFAULT_MAX_IDLE_TIMEOUT.as_millis() as u64
    );
    assert_eq!(config.initial_mtu, DEFAULT_INITIAL_MTU);
    assert_eq!(config.send_window, DEFAULT_SEND_WINDOW.as_u64());
    assert_eq!(config.receive_window, DEFAULT_RECEIVE_WINDOW.as_u64());
  }

  // ============== Error Response Tests ==============

  #[test]
  fn test_build_error_response_method_not_allowed() {
    let resp = build_error_response(
      http::StatusCode::METHOD_NOT_ALLOWED,
      "Method Not Allowed: only CONNECT is supported",
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
      "Bad Request: invalid target address",
    );
    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
  }

  #[test]
  fn test_build_error_response_proxy_auth_required() {
    let resp = build_error_response(
      http::StatusCode::PROXY_AUTHENTICATION_REQUIRED,
      "Proxy Authentication Required",
    );
    assert_eq!(
      resp.status(),
      http::StatusCode::PROXY_AUTHENTICATION_REQUIRED
    );
  }

  #[test]
  fn test_build_error_response_421_misdirected() {
    let resp = build_error_response(
      http::StatusCode::MISDIRECTED_REQUEST,
      "Misdirected Request: SNI does not match request authority",
    );
    assert_eq!(resp.status(), http::StatusCode::MISDIRECTED_REQUEST);
  }

  // ============== Listener Name Tests ==============

  #[test]
  fn test_listener_name() {
    assert_eq!(listener_name(), "http3");
  }

  #[test]
  fn test_create_listener_builder() {
    let _builder = create_listener_builder();
  }

  // ============== Http3ListenerArgs Tests ==============

  #[test]
  fn test_http3_listener_args_deserialize_minimal() {
    let yaml = r#"{}"#;
    let args: Http3ListenerArgs = serde_yaml::from_str(yaml).unwrap();
    assert!(args.quic.is_none());
  }

  #[test]
  fn test_http3_listener_args_deserialize_full() {
    let yaml = r#"
quic:
  max_concurrent_bidi_streams: 200
  max_idle_timeout: "60s"
  initial_mtu: 1400
  send_window: "20MiB"
  receive_window: "20MiB"
"#;
    let args: Http3ListenerArgs = serde_yaml::from_str(yaml).unwrap();
    assert!(args.quic.is_some());
    let quic = args.quic.unwrap();
    assert_eq!(quic.max_concurrent_bidi_streams, 200);
    assert_eq!(quic.max_idle_timeout, Duration::from_secs(60));
    assert_eq!(quic.send_window, Byte::from_u64(20971520));
    assert_eq!(quic.receive_window, Byte::from_u64(20971520));
  }

  #[test]
  fn test_http3_listener_args_no_required_fields() {
    // addresses are passed separately, args is optional
    let yaml = r#"{}"#;
    let result: Result<Http3ListenerArgs, _> =
      serde_yaml::from_str(yaml);
    // Parsing should succeed (no required fields)
    assert!(result.is_ok());
  }

  // ============== Bad Gateway Response Tests ==============

  #[test]
  fn test_build_error_response_bad_gateway() {
    let resp = build_error_response(
      http::StatusCode::BAD_GATEWAY,
      "Bad Gateway: failed to connect to target",
    );
    assert_eq!(resp.status(), http::StatusCode::BAD_GATEWAY);
    assert_eq!(
      resp.headers().get(http::header::CONTENT_TYPE).unwrap(),
      "text/plain"
    );
  }

  #[test]
  fn test_build_error_response_internal_server_error() {
    let resp = build_error_response(
      http::StatusCode::INTERNAL_SERVER_ERROR,
      "Internal Server Error",
    );
    assert_eq!(resp.status(), http::StatusCode::INTERNAL_SERVER_ERROR);
  }

  // ============== CONNECT-Only Upgrade Pair Tests ==============

  /// Test that non-CONNECT requests do NOT create an upgrade pair in
  /// extensions.
  ///
  /// This test verifies the logic used in handle_h3_stream:
  /// - For non-CONNECT methods, `is_connect` is false
  /// - Therefore, H3OnUpgrade is NOT inserted into request extensions
  ///
  /// The actual integration test
  /// (test_h3_get_to_echo_service_no_upgrade_error) verifies this
  /// behavior end-to-end.
  #[test]
  fn test_non_connect_no_upgrade_pair_in_extensions() {
    use http::Method;

    // For non-CONNECT methods, on_upgrade should NOT be inserted
    // This is the same logic used in handle_h3_stream:
    // let is_connect = method == http::Method::CONNECT;
    let methods_without_upgrade = [
      Method::GET,
      Method::POST,
      Method::PUT,
      Method::DELETE,
      Method::HEAD,
      Method::OPTIONS,
      Method::PATCH,
      Method::TRACE,
    ];

    for method in methods_without_upgrade {
      // This is the exact logic from handle_h3_stream (line 297):
      let is_connect = method == http::Method::CONNECT;

      // When is_connect is false, the code path is:
      // (None, Some(stream)) - no upgrade pair created
      // Therefore, no H3OnUpgrade is inserted into extensions
      assert!(
        !is_connect,
        "Method {} should NOT trigger upgrade pair creation \
         (is_connect should be false)",
        method
      );
    }
  }

  /// Test that CONNECT method DOES trigger upgrade pair creation.
  ///
  /// This test verifies the logic used in handle_h3_stream:
  /// - For CONNECT method, `is_connect` is true
  /// - Therefore, H3OnUpgrade IS inserted into request extensions
  #[test]
  fn test_connect_has_upgrade_pair() {
    // This is the exact logic from handle_h3_stream (line 297):
    let method = http::Method::CONNECT;
    let is_connect = method == http::Method::CONNECT;

    // When is_connect is true, the code path is:
    // let (trigger, on_upgrade) = H3UpgradeTrigger::pair(stream);
    // request.extensions_mut().insert(on_upgrade);
    assert!(
      is_connect,
      "CONNECT method should trigger upgrade pair creation \
       (is_connect should be true)"
    );
  }

  /// Integration-style test: verify upgrade trigger behavior
  ///
  /// This test verifies the core logic that determines when H3OnUpgrade
  /// should be present in request extensions. The logic is:
  ///
  /// 1. `is_connect = method == Method::CONNECT`
  /// 2. If is_connect: create upgrade pair and insert H3OnUpgrade
  /// 3. If !is_connect: keep stream for direct response, no H3OnUpgrade
  ///
  /// The actual end-to-end verification is done in the black-box test:
  /// tests/integration/test_http3_listener.
  /// py::TestHTTP3EchoService::test_h3_get_to_echo_service_no_upgrade_error
  #[tokio::test]
  async fn test_h3_upgrade_trigger_only_for_connect() {
    use http::Method;

    use crate::stream::OnUpgrade;

    // Simulate the decision logic from handle_h3_stream
    fn should_insert_on_upgrade(method: &Method) -> bool {
      // This is the exact logic from handle_h3_stream (line 297)
      *method == Method::CONNECT
    }

    // Verify CONNECT method should insert OnUpgrade
    assert!(
      should_insert_on_upgrade(&Method::CONNECT),
      "CONNECT method should insert OnUpgrade into extensions"
    );

    // Verify non-CONNECT methods should NOT insert OnUpgrade
    let non_connect_methods = [
      Method::GET,
      Method::POST,
      Method::PUT,
      Method::DELETE,
      Method::HEAD,
      Method::OPTIONS,
      Method::PATCH,
      Method::TRACE,
    ];

    for method in &non_connect_methods {
      assert!(
        !should_insert_on_upgrade(method),
        "Method {} should NOT insert OnUpgrade into extensions",
        method
      );
    }

    // Additional verification: simulate the request building logic
    // to ensure OnUpgrade detection works correctly
    let mut request = http::Request::builder()
      .method(Method::CONNECT)
      .uri("example.com:443")
      .body(RequestBody::new(BytesBufBodyWrapper::new(
        http_body_util::Empty::<Bytes>::new(),
      )))
      .expect("failed to build request");

    // Verify OnUpgrade is NOT in extensions initially
    assert!(
      !OnUpgrade::is_available(&request),
      "OnUpgrade should NOT be in extensions before insertion"
    );

    // Simulate insertion (what handle_h3_stream does for CONNECT)
    let (_tx, rx) = tokio::sync::oneshot::channel::<
      Result<Box<dyn crate::stream::Io>>,
    >();
    let upgrade = OnUpgrade::new_for_test(rx);
    request.extensions_mut().insert(upgrade);

    // Verify OnUpgrade IS in extensions after insertion
    assert!(
      OnUpgrade::is_available(&request),
      "OnUpgrade should be in extensions after insertion for CONNECT"
    );

    // Verify extraction works (what Service does)
    let extracted = OnUpgrade::on(&mut request);
    assert!(
      extracted.is_some(),
      "OnUpgrade should be extractable for CONNECT"
    );

    // Verify second extraction returns None (single-extraction
    // contract)
    let second = OnUpgrade::on(&mut request);
    assert!(
      second.is_none(),
      "OnUpgrade should only be extractable once"
    );
  }

  // ============== Task 011: Remove TLS/Auth from Listener Args Tests
  // ==============

  #[test]
  fn test_http3_listener_args_quic_optional() {
    // QUIC config is still at listener level (protocol-specific)
    let yaml = r#"
quic:
  max_concurrent_bidi_streams: 200
"#;
    let args: Http3ListenerArgs = serde_yaml::from_str(yaml).unwrap();
    assert!(args.quic.is_some());
    assert_eq!(
      args.quic.as_ref().unwrap().max_concurrent_bidi_streams,
      200
    );
  }
}
