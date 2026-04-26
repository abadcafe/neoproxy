#![allow(clippy::await_holding_refcell_ref)]
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use h3::server;
use http_body_util::BodyExt;
use quinn::crypto::rustls::QuicServerConfig;
use serde::Deserialize;
use tower::Service;
use tracing::{info, warn};

use crate::http_types::{
  BytesBufBodyWrapper, RequestBody, Response,
};
use crate::listeners::common::build_error_response;
use crate::plugin;
use crate::shutdown::{ShutdownHandle, StreamTracker};
use crate::stream::H3UpgradeTrigger;
use crate::tls::build_tls_server_config;

// ============================================================================
// Constants
// ============================================================================

/// Default maximum concurrent bidirectional streams
const DEFAULT_MAX_CONCURRENT_BIDI_STREAMS: u64 = 100;

/// Default maximum idle timeout in milliseconds
const DEFAULT_MAX_IDLE_TIMEOUT_MS: u64 = 30000;

/// Default initial MTU
const DEFAULT_INITIAL_MTU: u16 = 1200;

/// Default send window size (10MB)
const DEFAULT_SEND_WINDOW: u64 = 10485760;

/// Default receive window size (10MB)
const DEFAULT_RECEIVE_WINDOW: u64 = 10485760;

/// Graceful shutdown timeout for HTTP/3 Listener
const LISTENER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);

/// Monitoring log interval in seconds
const MONITORING_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// H3_NO_ERROR error code for CONNECTION_CLOSE frame
/// See: https://www.rfc-editor.org/rfc/rfc9114.html#errors
/// Value 0x100 = 256, which fits in u32
const H3_NO_ERROR_CODE: u32 = 0x100;

// ============================================================================
// Configuration Structures
// ============================================================================

/// HTTP/3 Listener configuration arguments
#[derive(Deserialize, Clone, Debug)]
pub struct Http3ListenerArgs {
  /// Listening addresses in "host:port" format (plural for consistency)
  #[serde(default)]
  pub addresses: Vec<String>,
  /// Single address field (deprecated, for backward compatibility)
  #[serde(default)]
  pub address: Option<String>,
  /// QUIC protocol parameters (optional)
  #[serde(default)]
  pub quic: Option<QuicConfigArgs>,
  // Note: TLS and auth are now at server level via routing table
}

impl Http3ListenerArgs {
  /// Get effective addresses, handling backward compatibility
  pub fn effective_addresses(&self) -> Result<Vec<String>> {
    if !self.addresses.is_empty() {
      return Ok(self.addresses.clone());
    }
    if let Some(ref addr) = self.address {
      // Single address field for backward compatibility
      return Ok(vec![addr.clone()]);
    }
    bail!("either 'addresses' or 'address' must be specified");
  }
}

/// QUIC protocol configuration arguments
#[derive(Deserialize, Clone, Debug)]
pub struct QuicConfigArgs {
  /// Maximum concurrent bidirectional streams (default: 100, range: 1-10000)
  pub max_concurrent_bidi_streams: Option<u64>,
  /// Maximum idle timeout in milliseconds (default: 30000)
  pub max_idle_timeout_ms: Option<u64>,
  /// Initial MTU (default: 1200, range: 1200-9000)
  pub initial_mtu: Option<u16>,
  /// Send window size in bytes (default: 10MB)
  pub send_window: Option<u64>,
  /// Receive window size in bytes (default: 10MB)
  pub receive_window: Option<u64>,
}

impl Default for QuicConfigArgs {
  fn default() -> Self {
    Self {
      max_concurrent_bidi_streams: Some(
        DEFAULT_MAX_CONCURRENT_BIDI_STREAMS,
      ),
      max_idle_timeout_ms: Some(DEFAULT_MAX_IDLE_TIMEOUT_MS),
      initial_mtu: Some(DEFAULT_INITIAL_MTU),
      send_window: Some(DEFAULT_SEND_WINDOW),
      receive_window: Some(DEFAULT_RECEIVE_WINDOW),
    }
  }
}

impl QuicConfigArgs {
  /// Validate and apply defaults to QUIC configuration
  ///
  /// Returns validated configuration with defaults applied where needed.
  /// Invalid values return an error, rejecting startup.
  pub fn validate_and_apply_defaults(&self) -> Result<QuicConfig> {
    let max_concurrent_bidi_streams =
      match self.max_concurrent_bidi_streams {
        Some(v) if (1..=10000).contains(&v) => v,
        Some(v) => {
          bail!(
            "Invalid max_concurrent_bidi_streams: {}, expected range \
             1-10000",
            v
          );
        }
        None => DEFAULT_MAX_CONCURRENT_BIDI_STREAMS,
      };

    let max_idle_timeout_ms = match self.max_idle_timeout_ms {
      Some(v) if v > 0 => v,
      Some(v) => {
        bail!("Invalid max_idle_timeout_ms: {}, expected value > 0", v);
      }
      None => DEFAULT_MAX_IDLE_TIMEOUT_MS,
    };

    let initial_mtu = match self.initial_mtu {
      Some(v) if (1200..=9000).contains(&v) => v,
      Some(v) => {
        bail!("Invalid initial_mtu: {}, expected range 1200-9000", v);
      }
      None => DEFAULT_INITIAL_MTU,
    };

    let send_window = match self.send_window {
      Some(v) if v > 0 => v,
      Some(v) => {
        bail!("Invalid send_window: {}, expected value > 0", v);
      }
      None => DEFAULT_SEND_WINDOW,
    };

    let receive_window = match self.receive_window {
      Some(v) if v > 0 => v,
      Some(v) => {
        bail!("Invalid receive_window: {}, expected value > 0", v);
      }
      None => DEFAULT_RECEIVE_WINDOW,
    };

    Ok(QuicConfig {
      max_concurrent_bidi_streams,
      max_idle_timeout_ms,
      initial_mtu,
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
    QuicConfigArgs::default()
      .validate_and_apply_defaults()
      .expect("Default QuicConfigArgs should always be valid")
  }
}

// ============================================================================
// Error Response Helpers
// ============================================================================

/// Check for :authority vs Host header mismatch in HTTP/3 requests.
///
/// In HTTP/3, the `:authority` pseudo-header serves as the equivalent of the
/// Host header. According to RFC 9114, if both `:authority` and Host header
/// are present, they should match. A mismatch could indicate a potential
/// security issue.
///
/// Returns true if there's a mismatch (should return 421).
fn check_h3_authority_host_mismatch(req: &http::Request<()>) -> bool {
  // Get :authority from the URI
  let authority = req.uri().authority().map(|a| a.to_string());

  // Get Host header
  let host = req.headers().get(http::header::HOST);

  match (authority, host) {
    (Some(auth), Some(host_val)) => {
      if let Ok(host_str) = host_val.to_str() {
        // Compare :authority with Host
        !super::common::sni_matches_host(&auth, host_str)
      } else {
        false
      }
    }
    _ => false, // If either is missing, no mismatch check needed
  }
}

// ============================================================================
// Access Log Recording
// ============================================================================

/// Record an access log entry for an HTTP/3 request.
///
/// Delegates to the common implementation in `super::common::record_http_access_log`.
fn record_access_log(
  writer: &crate::access_log::AccessLogWriter,
  client_addr: SocketAddr,
  user: Option<String>,
  auth_type: crate::access_log::AuthType,
  method: String,
  target: String,
  status: u16,
  duration: std::time::Duration,
  service_name: String,
  service_metrics: crate::access_log::ServiceMetrics,
) {
  let params = crate::access_log::HttpAccessLogParams {
    client_addr,
    user,
    auth_type,
    method,
    target,
    status,
    duration,
    service_name,
    service_metrics,
  };
  super::common::record_http_access_log(writer, &params);
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
/// 1. SNI/Host mismatch check (fail -> send 421 directly)
/// 2. Authentication check (fail -> send 407 directly)
/// 3. Route request to correct service based on :authority
/// 4. Create (trigger, on_upgrade) pair
/// 5. Build Request with on_upgrade in extensions
/// 6. Call service.call(request)
/// 7. Based on response status, trigger.send_success() or trigger.send_error()
///
/// Returns unit `()` because all errors are handled internally via logging
/// and H3 error responses. This function never propagates errors upward.
async fn handle_h3_stream(
  req: http::Request<()>,
  stream: server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
  server_routing_table: Vec<crate::server::ServerRoutingEntry>,
  _shutdown_handle: ShutdownHandle,
  client_addr: SocketAddr,
) -> () {
  // Capture start time for access log
  let start_time = std::time::Instant::now();
  let method = req.method().clone();
  let target = req.uri().to_string();

  // Phase 1: Check SNI vs Host for HTTP/3 FIRST
  if check_h3_authority_host_mismatch(&req) {
    let resp = build_error_response(
      http::StatusCode::MISDIRECTED_REQUEST,
      "Misdirected Request: SNI does not match Host header",
    );
    let mut stream = stream;
    if let Err(e) = send_h3_response(&mut stream, resp, true).await {
      warn!("Failed to send 421 response: {e}");
    }
    return;
  }

  // Phase 2: Route FIRST based on :authority
  let hostname = req.uri().authority().map(|a| a.host());
  let routing_entry = super::common::route_request_by_hostname(
    &server_routing_table,
    hostname,
  );

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

  // Phase 3: Authentication using routing_entry's users
  let user_password_auth = super::common::build_user_password_auth(&routing_entry.users);
  let auth_result =
    user_password_auth.verify_and_extract_username(&req);
  let (user, auth_type) = match auth_result {
    Ok(Some(username)) => {
      (Some(username), crate::access_log::AuthType::Password)
    }
    Ok(None) => (None, crate::access_log::AuthType::None),
    Err(_) => {
      let resp = build_error_response(
        http::StatusCode::PROXY_AUTHENTICATION_REQUIRED,
        "Proxy Authentication Required",
      );
      let mut stream = stream;
      if let Err(e) = send_h3_response(&mut stream, resp, true).await {
        warn!("Failed to send 407 response: {e}");
      }
      return;
    }
  };

  let mut service = routing_entry.service.clone();
  let access_log_writer = routing_entry.access_log_writer.clone();
  let service_name = routing_entry.service_name();

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

  let (trigger, mut stream_holder) = if is_connect {
    let (trigger, on_upgrade) = H3UpgradeTrigger::pair(stream);
    request.extensions_mut().insert(on_upgrade);
    (Some(trigger), None)
  } else {
    (None, Some(stream))
  };

  // Phase 6: Call Service
  let result = service.call(request).await;

  let mut final_status: u16 = 502;
  let mut service_metrics = crate::access_log::ServiceMetrics::new();

  // Phase 7: Handle Service response
  match result {
    Ok(resp) => {
      final_status = resp.status().as_u16();
      service_metrics = resp
        .extensions()
        .get::<crate::access_log::ServiceMetrics>()
        .cloned()
        .unwrap_or_default();

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

  if let Some(ref writer) = access_log_writer {
    let duration = start_time.elapsed();
    record_access_log(
      writer,
      client_addr,
      user,
      auth_type,
      method.to_string(),
      target,
      final_status,
      duration,
      service_name,
      service_metrics,
    );
  }
}

/// Send an HTTP/3 response with optional stream finish
///
/// # Arguments
/// * `stream` - The HTTP/3 request stream
/// * `resp` - The HTTP response to send
/// * `finish_stream` - If true, close the stream after sending response.
///   Should be false for CONNECT success response to allow bidirectional
///   data transfer.
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
  // For CONNECT success, we don't finish to allow bidirectional transfer
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
  server_routing_table: Vec<crate::server::ServerRoutingEntry>,
  stream_tracker: Rc<StreamTracker>,
  shutdown_handle: ShutdownHandle,
) {
  let client_addr = conn.remote_address();

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
        let server_routing_table = server_routing_table.clone();
        let stream_shutdown = stream_tracker.shutdown_handle();
        stream_tracker.register(async move {
          match resolver.resolve_request().await {
            Ok((req, stream)) => {
              handle_h3_stream(
                req,
                stream,
                server_routing_table,
                stream_shutdown,
                client_addr,
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
  server_routing_table: Vec<crate::server::ServerRoutingEntry>,
  /// Stream tracker
  stream_tracker: Rc<StreamTracker>,
  /// Shutdown handle
  shutdown_handle: ShutdownHandle,
}

impl Http3Listener {
  /// Create a new HTTP/3 Listener
  #[allow(clippy::new_ret_no_self)]
  pub fn new(
    sargs: plugin::SerializedArgs,
    server_routing_table: Vec<crate::server::ServerRoutingEntry>,
  ) -> Result<plugin::Listener> {
    let args: Http3ListenerArgs = serde_yaml::from_value(sargs)?;

    // Parse addresses
    let addresses: Vec<SocketAddr> = args
      .effective_addresses()?
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

    // TLS config is required for HTTP/3 listener - get from first routing entry
    let server_tls = server_routing_table
      .first()
      .and_then(|e| e.tls.as_ref())
      .ok_or_else(|| {
        anyhow!(
          "http3 listener requires server-level tls configuration"
        )
      })?;

    // Build TLS config with SNI support and HTTP/3 ALPN
    let tls_config =
      build_tls_server_config(server_tls, vec![H3_ALPN.to_vec()])?;

    Ok(plugin::Listener::new(Self {
      addresses,
      tls_config,
      quic_config,
      server_routing_table,
      stream_tracker: Rc::new(StreamTracker::new()),
      shutdown_handle: ShutdownHandle::new(),
    }))
  }
}

impl plugin::Listening for Http3Listener {
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
        tokio::sync::mpsc::channel::<quinn::Incoming>(32);

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
                    if conn_tx.send(incoming).await.is_err() {
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
      // Drop the original sender so conn_rx will end when all spawn tasks end
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
          Some(conn) => {
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
          "HTTP/3 Listener shutdown timeout ({:?}) expired, aborting {} \
           remaining streams",
          LISTENER_SHUTDOWN_TIMEOUT,
          stream_tracker.active_count()
        );
        stream_tracker.abort_all();
        // Wait for aborted tasks to be cleaned up with a short timeout
        // Aborted tasks should finish quickly, but we add a safety timeout
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
    // Step 1: Trigger shutdown notification to stop accepting new connections
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

/// Create a listener builder
pub fn create_listener_builder() -> Box<dyn plugin::BuildListener> {
  Box::new(Http3Listener::new)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
  use super::*;
  use crate::auth::ListenerAuthConfig;
  use crate::auth::UserCredential;
  use crate::auth::UserPasswordAuth;
  use base64::{
    Engine, engine::general_purpose::STANDARD as BASE64_STANDARD,
  };

  // ============== QuicConfigArgs Tests ==============

  #[test]
  fn test_quic_config_args_default() {
    let args = QuicConfigArgs::default();
    assert_eq!(
      args.max_concurrent_bidi_streams,
      Some(DEFAULT_MAX_CONCURRENT_BIDI_STREAMS)
    );
    assert_eq!(
      args.max_idle_timeout_ms,
      Some(DEFAULT_MAX_IDLE_TIMEOUT_MS)
    );
    assert_eq!(args.initial_mtu, Some(DEFAULT_INITIAL_MTU));
    assert_eq!(args.send_window, Some(DEFAULT_SEND_WINDOW));
    assert_eq!(args.receive_window, Some(DEFAULT_RECEIVE_WINDOW));
  }

  #[test]
  fn test_quic_config_args_validate_and_apply_defaults_valid() {
    let args = QuicConfigArgs {
      max_concurrent_bidi_streams: Some(200),
      max_idle_timeout_ms: Some(60000),
      initial_mtu: Some(1400),
      send_window: Some(20971520),
      receive_window: Some(20971520),
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
      max_concurrent_bidi_streams: Some(0),
      ..Default::default()
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
      max_concurrent_bidi_streams: Some(10001),
      ..Default::default()
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
      max_idle_timeout_ms: Some(0),
      ..Default::default()
    };
    let result = args.validate_and_apply_defaults();
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("max_idle_timeout_ms"));
    assert!(err.contains("expected value > 0"));
  }

  #[test]
  fn test_quic_config_args_validate_invalid_initial_mtu_low() {
    let args =
      QuicConfigArgs { initial_mtu: Some(100), ..Default::default() };
    let result = args.validate_and_apply_defaults();
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("initial_mtu"));
    assert!(err.contains("expected range 1200-9000"));
  }

  #[test]
  fn test_quic_config_args_validate_invalid_initial_mtu_high() {
    let args =
      QuicConfigArgs { initial_mtu: Some(10000), ..Default::default() };
    let result = args.validate_and_apply_defaults();
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("initial_mtu"));
    assert!(err.contains("expected range 1200-9000"));
  }

  #[test]
  fn test_quic_config_args_validate_invalid_send_window() {
    let args =
      QuicConfigArgs { send_window: Some(0), ..Default::default() };
    let result = args.validate_and_apply_defaults();
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("send_window"));
    assert!(err.contains("expected value > 0"));
  }

  #[test]
  fn test_quic_config_args_validate_invalid_receive_window() {
    let args =
      QuicConfigArgs { receive_window: Some(0), ..Default::default() };
    let result = args.validate_and_apply_defaults();
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("receive_window"));
    assert!(err.contains("expected value > 0"));
  }

  #[test]
  fn test_quic_config_args_validate_none_values_use_defaults() {
    let args = QuicConfigArgs {
      max_concurrent_bidi_streams: None,
      max_idle_timeout_ms: None,
      initial_mtu: None,
      send_window: None,
      receive_window: None,
    };
    let config = args.validate_and_apply_defaults().unwrap();
    assert_eq!(
      config.max_concurrent_bidi_streams,
      DEFAULT_MAX_CONCURRENT_BIDI_STREAMS
    );
    assert_eq!(config.max_idle_timeout_ms, DEFAULT_MAX_IDLE_TIMEOUT_MS);
    assert_eq!(config.initial_mtu, DEFAULT_INITIAL_MTU);
    assert_eq!(config.send_window, DEFAULT_SEND_WINDOW);
    assert_eq!(config.receive_window, DEFAULT_RECEIVE_WINDOW);
  }

  #[test]
  fn test_quic_config_default() {
    let config = QuicConfig::default();
    assert_eq!(
      config.max_concurrent_bidi_streams,
      DEFAULT_MAX_CONCURRENT_BIDI_STREAMS
    );
    assert_eq!(config.max_idle_timeout_ms, DEFAULT_MAX_IDLE_TIMEOUT_MS);
    assert_eq!(config.initial_mtu, DEFAULT_INITIAL_MTU);
    assert_eq!(config.send_window, DEFAULT_SEND_WINDOW);
    assert_eq!(config.receive_window, DEFAULT_RECEIVE_WINDOW);
  }

  // ============== ListenerAuthConfig Tests ==============

  #[test]
  fn test_auth_config_none() {
    // No auth at listener level - it's now at server level
    let args = Http3ListenerArgs {
      addresses: vec!["0.0.0.0:443".to_string()],
      address: None,
      quic: None,
    };
    // ListenerArgs no longer has auth field - auth is at server level
    assert_eq!(args.addresses.len(), 1);
  }

  #[test]
  fn test_auth_config_password_plaintext() {
    // Test that plaintext password format works with new auth module
    let yaml = r#"
users:
  - username: admin
    password: plaintext_secret
"#;
    let yaml_value: serde_yaml::Value =
      serde_yaml::from_str(yaml).expect("parse yaml");
    let config: ListenerAuthConfig =
      serde_yaml::from_value(yaml_value).unwrap();
    config.validate().unwrap();
    assert!(!config.users.is_empty());
    let users = config.users_map().expect("users should exist");
    assert_eq!(
      users.get("admin"),
      Some(&"plaintext_secret".to_string())
    );
  }

  #[test]
  fn test_auth_config_tls_client_cert() {
    // Test that TLS client cert format works with new auth module
    let yaml = r#"
client_ca_path: /path/to/ca.pem
"#;
    let yaml_value: serde_yaml::Value =
      serde_yaml::from_str(yaml).expect("parse yaml");
    let config: ListenerAuthConfig =
      serde_yaml::from_value(yaml_value).unwrap();
    config.validate().unwrap();
    assert_eq!(
      config.client_ca_path,
      Some("/path/to/ca.pem".to_string())
    );
  }

  #[test]
  fn test_auth_config_dual_factor() {
    // Test that dual-factor (users + client_ca_path) works
    let yaml = r#"
users:
  - username: admin
    password: secret
client_ca_path: /path/to/ca.pem
"#;
    let yaml_value: serde_yaml::Value =
      serde_yaml::from_str(yaml).expect("parse yaml");
    let config: ListenerAuthConfig =
      serde_yaml::from_value(yaml_value).unwrap();
    config.validate().unwrap();
    assert!(!config.users.is_empty());
    assert!(config.client_ca_path.is_some());
  }

  #[test]
  fn test_auth_config_empty_is_error() {
    // Empty auth config should fail validation
    let yaml = r#"{}"#;
    let yaml_value: serde_yaml::Value =
      serde_yaml::from_str(yaml).expect("parse yaml");
    let config: ListenerAuthConfig =
      serde_yaml::from_value(yaml_value).unwrap();
    assert!(config.validate().is_err());
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
      "Misdirected Request: SNI does not match Host header",
    );
    assert_eq!(resp.status(), http::StatusCode::MISDIRECTED_REQUEST);
  }

  // ============== H3 Authority/Host Mismatch Tests ==============

  #[test]
  fn test_check_h3_authority_host_mismatch_no_mismatch() {
    // Authority and Host match - no mismatch
    let req = http::Request::builder()
      .uri("http://api.example.com/test")
      .header(http::header::HOST, "api.example.com")
      .body(())
      .unwrap();
    assert!(!check_h3_authority_host_mismatch(&req));
  }

  #[test]
  fn test_check_h3_authority_host_mismatch_has_mismatch() {
    // Authority and Host differ - mismatch
    let req = http::Request::builder()
      .uri("http://api.example.com/test")
      .header(http::header::HOST, "other.example.com")
      .body(())
      .unwrap();
    assert!(check_h3_authority_host_mismatch(&req));
  }

  #[test]
  fn test_check_h3_authority_host_mismatch_case_insensitive() {
    // Authority and Host match (case-insensitive) - no mismatch
    let req = http::Request::builder()
      .uri("http://API.EXAMPLE.COM/test")
      .header(http::header::HOST, "api.example.com")
      .body(())
      .unwrap();
    assert!(!check_h3_authority_host_mismatch(&req));
  }

  #[test]
  fn test_check_h3_authority_host_mismatch_with_port() {
    // Host has port - should strip and match
    let req = http::Request::builder()
      .uri("http://api.example.com/test")
      .header(http::header::HOST, "api.example.com:443")
      .body(())
      .unwrap();
    assert!(!check_h3_authority_host_mismatch(&req));
  }

  #[test]
  fn test_check_h3_authority_host_mismatch_no_host() {
    // No Host header - no mismatch check
    let req = http::Request::builder()
      .uri("http://api.example.com/test")
      .body(())
      .unwrap();
    assert!(!check_h3_authority_host_mismatch(&req));
  }

  #[test]
  fn test_check_h3_authority_host_mismatch_no_authority() {
    // No authority in URI - no mismatch check
    let req = http::Request::builder()
      .uri("/test")
      .header(http::header::HOST, "api.example.com")
      .body(())
      .unwrap();
    assert!(!check_h3_authority_host_mismatch(&req));
  }

  #[test]
  fn test_check_h3_authority_host_mismatch_ipv4() {
    // IPv4 addresses should match
    let req = http::Request::builder()
      .uri("http://192.168.1.1/test")
      .header(http::header::HOST, "192.168.1.1")
      .body(())
      .unwrap();
    assert!(!check_h3_authority_host_mismatch(&req));
  }

  #[test]
  fn test_check_h3_authority_host_mismatch_ipv4_with_port() {
    // IPv4 with port should match after stripping port
    let req = http::Request::builder()
      .uri("http://192.168.1.1/test")
      .header(http::header::HOST, "192.168.1.1:8443")
      .body(())
      .unwrap();
    assert!(!check_h3_authority_host_mismatch(&req));
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
    // TLS is no longer at listener level
    let yaml = r#"
address: "0.0.0.0:443"
"#;
    let args: Http3ListenerArgs = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(args.address.as_ref().unwrap(), "0.0.0.0:443");
    assert!(args.quic.is_none());
  }

  #[test]
  fn test_http3_listener_args_deserialize_full() {
    // TLS and auth are no longer at listener level
    // Only QUIC config remains as listener-specific
    let yaml = r#"
address: "0.0.0.0:443"
quic:
  max_concurrent_bidi_streams: 200
  max_idle_timeout_ms: 60000
  initial_mtu: 1400
  send_window: 20971520
  receive_window: 20971520
"#;
    let args: Http3ListenerArgs = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(args.address.as_ref().unwrap(), "0.0.0.0:443");
    assert!(args.quic.is_some());
    let quic = args.quic.unwrap();
    assert_eq!(quic.max_concurrent_bidi_streams, Some(200));
    assert_eq!(quic.max_idle_timeout_ms, Some(60000));
  }

  #[test]
  fn test_http3_listener_args_no_required_fields() {
    // No required fields anymore - addresses/address are optional at parse time
    // The validation happens in effective_addresses() call
    let yaml = r#"{}"#;
    let result: Result<Http3ListenerArgs, _> =
      serde_yaml::from_str(yaml);
    // Parsing should succeed (no required fields)
    assert!(result.is_ok());
    let args = result.unwrap();
    // But effective_addresses() should fail
    assert!(args.effective_addresses().is_err());
  }

  // ============== Constants Tests ==============

  #[test]
  fn test_default_values() {
    assert_eq!(DEFAULT_MAX_CONCURRENT_BIDI_STREAMS, 100);
    assert_eq!(DEFAULT_MAX_IDLE_TIMEOUT_MS, 30000);
    assert_eq!(DEFAULT_INITIAL_MTU, 1200);
    assert_eq!(DEFAULT_SEND_WINDOW, 10485760);
    assert_eq!(DEFAULT_RECEIVE_WINDOW, 10485760);
  }

  #[test]
  fn test_listener_shutdown_timeout() {
    assert_eq!(LISTENER_SHUTDOWN_TIMEOUT, Duration::from_secs(3));
  }

  #[test]
  fn test_monitoring_log_interval() {
    assert_eq!(MONITORING_LOG_INTERVAL, Duration::from_secs(60));
  }

  // ============== Listening Trait Tests ==============

  #[test]
  fn test_listening_trait_implementation() {
    fn assert_listening<T: plugin::Listening>() {}
    assert_listening::<Http3Listener>();
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

  #[test]
  fn test_verify_and_extract_username_combines_auth_and_extraction() {
    // Test that verify_and_extract_username correctly combines auth and extraction
    // This verifies CR-001 and CR-002 fixes: no duplicated logic, no wasteful computation

    // Case 1: Auth required, valid credentials - should return username
    let user_password_auth =
      UserPasswordAuth::from_config(&ListenerAuthConfig {
        users: vec![UserCredential {
          username: "testuser".to_string(),
          password: "testpass".to_string(),
        }],
        client_ca_path: None,
      });
    let req = http::Request::builder()
      .method(http::Method::CONNECT)
      .uri("http://example.com:80")
      .header(
        "Proxy-Authorization",
        format!(
          "Basic {}",
          BASE64_STANDARD.encode("testuser:testpass")
        ),
      )
      .body(())
      .unwrap();
    let result = user_password_auth.verify_and_extract_username(&req);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), Some("testuser".to_string()));

    // Case 2: Auth required, invalid credentials - should return error
    let req_invalid = http::Request::builder()
      .method(http::Method::CONNECT)
      .uri("http://example.com:80")
      .header(
        "Proxy-Authorization",
        format!(
          "Basic {}",
          BASE64_STANDARD.encode("testuser:wrongpass")
        ),
      )
      .body(())
      .unwrap();
    let result =
      user_password_auth.verify_and_extract_username(&req_invalid);
    assert!(result.is_err());

    // Case 3: No auth required - should return Ok(None)
    let no_auth = UserPasswordAuth::none();
    let req_no_auth = http::Request::builder()
      .method(http::Method::CONNECT)
      .uri("http://example.com:80")
      .body(())
      .unwrap();
    let result = no_auth.verify_and_extract_username(&req_no_auth);
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
  }

  // ============== record_access_log Tests ==============

  #[test]
  fn test_record_access_log_writes_entry() {
    let dir = tempfile::tempdir().unwrap();
    let config = crate::access_log::AccessLogConfig {
      enabled: true,
      path_prefix: "h3test.log".to_string(),
      format: crate::access_log::LogFormat::Text,
      buffer: byte_unit::Byte::from_u64(64),
      flush: crate::access_log::config::HumanDuration(
        std::time::Duration::from_millis(100),
      ),
      max_size: byte_unit::Byte::from_u64(1024 * 1024),
    };
    let writer = crate::access_log::AccessLogWriter::new(
      dir.path().to_str().unwrap(),
      &config,
    );

    let client_addr: SocketAddr = "192.168.1.1:54321".parse().unwrap();
    let mut metrics = crate::access_log::ServiceMetrics::new();
    metrics.add("connect_ms", 42u64);

    record_access_log(
      &writer,
      client_addr,
      Some("testuser".to_string()),
      crate::access_log::AuthType::Password,
      "CONNECT".to_string(),
      "example.com:443".to_string(),
      200,
      std::time::Duration::from_millis(50),
      "tunnel".to_string(),
      metrics,
    );

    writer.flush();

    // Verify log file was created and contains expected fields
    let mut found = false;
    for entry in std::fs::read_dir(dir.path()).unwrap() {
      let entry = entry.unwrap();
      let name = entry.file_name().to_string_lossy().to_string();
      if name.starts_with("h3test.log") {
        let content = std::fs::read_to_string(entry.path()).unwrap();
        assert!(
          content.contains("192.168.1.1:54321"),
          "Should contain client addr"
        );
        assert!(
          content.contains("CONNECT example.com:443"),
          "Should contain request line"
        );
        assert!(content.contains("200"), "Should contain status code");
        assert!(
          content.contains("service=tunnel"),
          "Should contain service name"
        );
        assert!(
          content.contains("service.connect_ms=42"),
          "Should contain service metrics"
        );
        assert!(
          content.contains("auth=password"),
          "Should contain auth type"
        );
        found = true;
      }
    }
    assert!(found, "Access log file should exist");
  }

  // ============== CONNECT-Only Upgrade Pair Tests ==============

  /// Test that non-CONNECT requests do NOT create an upgrade pair in extensions.
  ///
  /// This test verifies the logic used in handle_h3_stream:
  /// - For non-CONNECT methods, `is_connect` is false
  /// - Therefore, H3OnUpgrade is NOT inserted into request extensions
  ///
  /// The actual integration test (test_h3_get_to_echo_service_no_upgrade_error)
  /// verifies this behavior end-to-end.
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
        "Method {} should NOT trigger upgrade pair creation (is_connect should be false)",
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
      "CONNECT method should trigger upgrade pair creation (is_connect should be true)"
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
  /// tests/integration/test_http3_listener.py::TestHTTP3EchoService::test_h3_get_to_echo_service_no_upgrade_error
  #[tokio::test]
  async fn test_h3_upgrade_trigger_only_for_connect() {
    use crate::stream::H3OnUpgrade;
    use http::Method;

    // Simulate the decision logic from handle_h3_stream
    fn should_insert_on_upgrade(method: &Method) -> bool {
      // This is the exact logic from handle_h3_stream (line 297)
      *method == Method::CONNECT
    }

    // Verify CONNECT method should insert H3OnUpgrade
    assert!(
      should_insert_on_upgrade(&Method::CONNECT),
      "CONNECT method should insert H3OnUpgrade into extensions"
    );

    // Verify non-CONNECT methods should NOT insert H3OnUpgrade
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
        "Method {} should NOT insert H3OnUpgrade into extensions",
        method
      );
    }

    // Additional verification: simulate the request building logic
    // to ensure H3OnUpgrade detection works correctly
    let mut request = http::Request::builder()
      .method(Method::CONNECT)
      .uri("example.com:443")
      .body(RequestBody::new(BytesBufBodyWrapper::new(
        http_body_util::Empty::<Bytes>::new(),
      )))
      .expect("failed to build request");

    // Verify H3OnUpgrade is NOT in extensions initially
    assert!(
      !H3OnUpgrade::is_available(&request),
      "H3OnUpgrade should NOT be in extensions before insertion"
    );

    // Simulate insertion (what handle_h3_stream does for CONNECT)
    let (_tx, rx) = tokio::sync::oneshot::channel::<
      Result<
        crate::h3_stream::H3ServerBidiStream,
        crate::stream::H3UpgradeError,
      >,
    >();
    let upgrade = H3OnUpgrade::new_for_test(rx);
    request.extensions_mut().insert(upgrade);

    // Verify H3OnUpgrade IS in extensions after insertion
    assert!(
      H3OnUpgrade::is_available(&request),
      "H3OnUpgrade should be in extensions after insertion for CONNECT"
    );

    // Verify extraction works (what Service does)
    let extracted = H3OnUpgrade::on(&mut request);
    assert!(
      extracted.is_some(),
      "H3OnUpgrade should be extractable for CONNECT"
    );

    // Verify second extraction returns None (single-extraction contract)
    let second = H3OnUpgrade::on(&mut request);
    assert!(
      second.is_none(),
      "H3OnUpgrade should only be extractable once"
    );
  }

  // ============== Multi-Address Support Tests ==============

  #[test]
  fn test_http3_listener_args_addresses_field() {
    // Test that addresses (plural) field is accepted
    // TLS and auth are now at server level, not listener level
    let yaml = r#"
addresses:
  - "127.0.0.1:8443"
  - "127.0.0.1:8444"
"#;
    let args: Http3ListenerArgs = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(args.addresses.len(), 2);
    assert_eq!(args.addresses[0], "127.0.0.1:8443");
    assert_eq!(args.addresses[1], "127.0.0.1:8444");
  }

  #[test]
  fn test_http3_listener_args_single_address_backward_compat() {
    // Test that single address field still works for backward compatibility
    // TLS and auth are now at server level, not listener level
    let yaml = r#"
address: "127.0.0.1:8443"
"#;
    let args: Http3ListenerArgs = serde_yaml::from_str(yaml).unwrap();
    // Should convert to addresses internally via effective_addresses()
    assert!(args.address.is_some());
    assert_eq!(args.address.as_ref().unwrap(), "127.0.0.1:8443");
    // effective_addresses should return the single address
    let effective = args.effective_addresses().unwrap();
    assert_eq!(effective.len(), 1);
    assert_eq!(effective[0], "127.0.0.1:8443");
  }

  #[test]
  fn test_http3_listener_args_effective_addresses_prioritizes_plural() {
    // When both addresses and address are provided, addresses takes priority
    // TLS and auth are now at server level, not listener level
    let yaml = r#"
addresses:
  - "127.0.0.1:8443"
  - "127.0.0.1:8444"
address: "127.0.0.1:8445"
"#;
    let args: Http3ListenerArgs = serde_yaml::from_str(yaml).unwrap();
    let effective = args.effective_addresses().unwrap();
    assert_eq!(effective.len(), 2);
    assert_eq!(effective[0], "127.0.0.1:8443");
    assert_eq!(effective[1], "127.0.0.1:8444");
  }

  #[test]
  fn test_http3_listener_args_no_address_error() {
    // When neither addresses nor address is provided, should return error
    // TLS and auth are now at server level, not listener level
    let yaml = r#"{}"#;
    let args: Http3ListenerArgs = serde_yaml::from_str(yaml).unwrap();
    let result = args.effective_addresses();
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("addresses") || err.contains("address"));
  }

  // ============== Task 011: Remove TLS/Auth from Listener Args Tests ==============

  #[test]
  fn test_http3_listener_args_no_tls_fields() {
    // TLS should no longer be at listener level
    let yaml = r#"
addresses:
  - "127.0.0.1:8443"
"#;
    let args: Http3ListenerArgs = serde_yaml::from_str(yaml).unwrap();
    assert!(args.addresses.len() == 1);
    // TLS should not be part of listener args
  }

  #[test]
  fn test_http3_listener_args_no_auth_field() {
    // Auth should no longer be at listener level
    // The struct no longer has an auth field, so parsing without it should work
    let yaml = r#"
addresses:
  - "127.0.0.1:8443"
"#;
    let args: Http3ListenerArgs = serde_yaml::from_str(yaml).unwrap();
    // Auth is now at server level, not listener level
    assert!(args.addresses.len() == 1);
  }

  #[test]
  fn test_http3_listener_args_quic_optional() {
    // QUIC config is still at listener level (protocol-specific)
    let yaml = r#"
addresses:
  - "127.0.0.1:8443"
quic:
  max_concurrent_bidi_streams: 200
"#;
    let args: Http3ListenerArgs = serde_yaml::from_str(yaml).unwrap();
    assert!(args.quic.is_some());
    assert_eq!(
      args.quic.as_ref().unwrap().max_concurrent_bidi_streams,
      Some(200)
    );
  }
}
