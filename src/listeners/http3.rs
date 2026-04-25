#![allow(clippy::await_holding_refcell_ref)]
use std::fs;
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
use rustls::pki_types::CertificateDer;
use serde::Deserialize;
use tracing::{info, warn};
use tower::Service;

use crate::auth::{
  ClientCertAuth, ListenerAuthConfig, UserPasswordAuth,
};
use crate::plugin;
use crate::shutdown::StreamTracker;
use crate::stream::H3UpgradeTrigger;

// ============================================================================
// Constants
// ============================================================================

/// ALPN protocol identifier for HTTP/3
static ALPN: &[u8] = b"h3";

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
  /// Listening address in "host:port" format
  pub address: String,
  /// TLS certificate file path (PEM format)
  pub server_cert_path: String,
  /// TLS private key file path (PEM format)
  pub server_key_path: String,
  /// QUIC protocol parameters (optional)
  pub quic: Option<QuicConfigArgs>,
  /// Authentication configuration (optional, raw YAML value)
  pub auth: Option<serde_yaml::Value>,
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

/// Build an error response with the given status and message
fn build_error_response(
  status: http::StatusCode,
  message: &str,
) -> plugin::Response {
  let full =
    http_body_util::Full::new(Bytes::from(message.to_string()));
  let bytes_buf = plugin::BytesBufBodyWrapper::new(full);
  let body = plugin::ResponseBody::new(bytes_buf);
  let mut resp = plugin::Response::new(body);
  *resp.status_mut() = status;
  resp.headers_mut().insert(
    http::header::CONTENT_TYPE,
    http::header::HeaderValue::from_static("text/plain"),
  );
  resp
}

// ============================================================================
// Access Log Recording
// ============================================================================

/// Record an access log entry for an HTTP/3 request.
///
/// Extracted from handle_h3_stream to enable unit testing.
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
  let entry = crate::access_log::AccessLogEntry {
    time: time::OffsetDateTime::now_local()
      .unwrap_or_else(|_| time::OffsetDateTime::now_utc()),
    client_ip: client_addr.ip().to_string(),
    client_port: client_addr.port(),
    user,
    auth_type,
    method,
    target,
    status,
    duration_ms: duration.as_millis() as u64,
    service: service_name,
    service_metrics,
  };
  writer.write(&entry);
}

// ============================================================================
// HTTP/3 Stream Handler
// ============================================================================

/// Handle a single HTTP/3 stream by delegating to the Service.
///
/// Flow:
/// 1. Authentication check (fail -> send 407 directly)
/// 2. Create (trigger, on_upgrade) pair
/// 3. Build plugin::Request with on_upgrade in extensions
/// 4. Call service.call(request)
/// 5. Based on response status, trigger.send_success() or trigger.send_error()
///
/// Returns unit `()` because all errors are handled internally via logging
/// and H3 error responses. This function never propagates errors upward.
async fn handle_h3_stream(
  req: http::Request<()>,
  stream: server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
  mut service: plugin::Service,
  user_password_auth: UserPasswordAuth,
  _shutdown_handle: plugin::ShutdownHandle,
  access_log_writer: Option<crate::access_log::AccessLogWriter>,
  service_name: String,
  client_addr: SocketAddr,
) -> () {
  // Capture start time for access log
  let start_time = std::time::Instant::now();
  let method = req.method().to_string();
  let target = req.uri().to_string();

  // Phase 1: Authentication - verify and extract username in one pass
  // This avoids duplicated extraction logic (CR-001) and wasteful computation when auth fails (CR-002)
  let auth_result = user_password_auth.verify_and_extract_username(&req);
  let (user, auth_type) = match auth_result {
    Ok(Some(username)) => (Some(username), crate::access_log::AuthType::Password),
    Ok(None) => (None, crate::access_log::AuthType::None),
    Err(_) => {
      // Auth failed: send 407 directly, do NOT call Service
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

  // Phase 2: Create upgrade pair
  let (trigger, on_upgrade) = H3UpgradeTrigger::pair(stream);

  // Phase 3: Build plugin::Request with on_upgrade in extensions
  let mut request = http::Request::builder()
    .method(req.method().clone())
    .uri(req.uri().clone())
    .version(req.version())
    .body(plugin::RequestBody::new(
      plugin::BytesBufBodyWrapper::new(
        http_body_util::Empty::<Bytes>::new(),
      ),
    ))
    .expect("failed to build request");

  // Copy headers from original request
  for (name, value) in req.headers() {
    request.headers_mut().insert(name.clone(), value.clone());
  }

  request.extensions_mut().insert(on_upgrade);

  // Phase 4: Call Service
  let result = service.call(request).await;

  // Track status and service metrics for access log
  let mut final_status: u16 = 502;
  let mut service_metrics = crate::access_log::ServiceMetrics::new();

  // Phase 5: Handle Service response
  match result {
    Ok(resp) => {
      final_status = resp.status().as_u16();
      // Extract ServiceMetrics from response extensions
      service_metrics = resp
        .extensions()
        .get::<crate::access_log::ServiceMetrics>()
        .cloned()
        .unwrap_or_default();

      if resp.status() == http::StatusCode::OK {
        if let Err(e) = trigger.send_success().await {
          warn!("H3 failed to send success: {e}");
        }
      } else {
        // Extract body from response before sending
        let status = resp.status();
        let body_bytes = match http_body_util::BodyExt::collect(resp.into_body()).await {
          Ok(collected) => collected.to_bytes(),
          Err(e) => {
            warn!("H3 failed to collect response body: {e}");
            Bytes::new()
          }
        };
        if let Err(e) = trigger.send_error_with_body(status, body_bytes).await {
          warn!("H3 failed to send error: {e}");
        }
      }
    }
    Err(e) => {
      warn!("H3 service error: {e}");
      if let Err(e) = trigger
        .send_error(http::StatusCode::BAD_GATEWAY)
        .await
      {
        warn!("H3 failed to send error: {e}");
      }
    }
  }

  // Record access log by calling the tested helper
  if let Some(ref writer) = access_log_writer {
    let duration = start_time.elapsed();

    record_access_log(
      writer,
      client_addr,
      user,
      auth_type,
      method,
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
  stream: &mut server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
  resp: plugin::Response,
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
  service: plugin::Service,
  user_password_auth: UserPasswordAuth,
  stream_tracker: Rc<StreamTracker>,
  shutdown_handle: plugin::ShutdownHandle,
  access_log_writer: Option<crate::access_log::AccessLogWriter>,
  service_name: String,
) {
  // Get client address from connection for access log
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
        let service = service.clone();
        let user_password_auth = user_password_auth.clone();
        let stream_shutdown = stream_tracker.shutdown_handle();
        let access_log_writer = access_log_writer.clone();
        let service_name = service_name.clone();
        stream_tracker.register(async move {
          match resolver.resolve_request().await {
            Ok((req, stream)) => {
              handle_h3_stream(
                req,
                stream,
                service,
                user_password_auth,
                stream_shutdown,
                access_log_writer,
                service_name,
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

/// Verify that the private key file has secure permissions (0o600)
///
/// Per security requirements (需求文档3.2节), private key files should
/// have permissions 600 (read/write for owner only) to prevent
/// unauthorized access.
fn verify_key_file_permissions(key_path: &str) -> Result<()> {
  use std::os::unix::fs::PermissionsExt;

  let metadata = fs::metadata(key_path).with_context(|| {
    format!("Failed to get metadata for private key file: {key_path}")
  })?;

  let mode = metadata.permissions().mode();
  let permission_bits = mode & 0o777;

  // Check if permissions are 0o600 (rw-------)
  // We allow 0o400 (r--------) as well since it's also secure (read-only)
  let secure_permissions = [0o600, 0o400];

  if !secure_permissions.contains(&permission_bits) {
    bail!(
      "Private key file '{}' has insecure permissions {:03o}. \
       Expected 600 (rw-------) or 400 (r--------). \
       Please run: chmod 600 '{}'",
      key_path,
      permission_bits,
      key_path
    );
  }

  Ok(())
}

/// Load TLS server configuration
fn load_tls_config(
  cert_path: &str,
  key_path: &str,
  client_cert_auth: &ClientCertAuth,
) -> Result<Arc<rustls::ServerConfig>> {
  // Verify private key file permissions before loading
  verify_key_file_permissions(key_path)?;

  // Load certificate
  let cert_file = fs::File::open(cert_path).with_context(|| {
    format!("Failed to open certificate file: {cert_path}")
  })?;
  let mut cert_reader = std::io::BufReader::new(cert_file);
  let certs: Vec<CertificateDer> =
    rustls_pemfile::certs(&mut cert_reader)
      .collect::<Result<Vec<_>, _>>()
      .with_context(|| "Failed to parse certificates")?;

  // Load private key
  let key_file = fs::File::open(key_path).with_context(|| {
    format!("Failed to open private key file: {key_path}")
  })?;
  let mut key_reader = std::io::BufReader::new(key_file);
  let key = rustls_pemfile::private_key(&mut key_reader)?
    .ok_or_else(|| anyhow!("No private key found in {}", key_path))?;

  // Build TLS config based on client cert auth
  let tls_config = match client_cert_auth.rustls_verifier() {
    Some(verifier) => {
      // TLS client cert auth configured - client cert is REQUIRED
      let mut config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)?;
      config.alpn_protocols = vec![ALPN.to_vec()];
      config
    }
    None => {
      // No TLS client cert auth - no client cert verification
      let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
      config.alpn_protocols = vec![ALPN.to_vec()];
      config
    }
  };

  Ok(Arc::new(tls_config))
}

// ============================================================================
// HTTP/3 Listener
// ============================================================================

/// HTTP/3 Listener implementation
pub struct Http3Listener {
  /// Listening address
  address: SocketAddr,
  /// TLS configuration
  tls_config: Arc<rustls::ServerConfig>,
  /// QUIC configuration
  quic_config: QuicConfig,
  /// Application-layer authentication (password)
  user_password_auth: UserPasswordAuth,
  /// Stream tracker
  stream_tracker: Rc<StreamTracker>,
  /// Shutdown handle
  shutdown_handle: plugin::ShutdownHandle,
  /// Associated service
  service: plugin::Service,
  /// Access log writer for logging request/response information.
  access_log_writer: Option<crate::access_log::AccessLogWriter>,
  /// Service name for identification in logs.
  service_name: String,
}

impl Http3Listener {
  /// Create a new HTTP/3 Listener
  #[allow(clippy::new_ret_no_self)]
  pub fn new(
    sargs: plugin::SerializedArgs,
    svc: plugin::Service,
    ctx: plugin::ListenerBuildContext,
  ) -> Result<plugin::Listener> {
    let args: Http3ListenerArgs = serde_yaml::from_value(sargs)?;

    // Parse address
    let address: SocketAddr = args
      .address
      .parse()
      .with_context(|| format!("Invalid address: {}", args.address))?;

    // Validate and apply QUIC config defaults
    let quic_config = match &args.quic {
      Some(quic_args) => quic_args.validate_and_apply_defaults()?,
      None => QuicConfig::default(),
    };

    // Parse authentication config using ListenerAuthConfig
    let auth_config: Option<ListenerAuthConfig> = args
      .auth
      .map(|a| {
        let config: ListenerAuthConfig = serde_yaml::from_value(a)?;
        config.validate()?;
        Ok(config)
      })
      .transpose()
      .map_err(|e: anyhow::Error| {
        anyhow!("auth config validation failed: {}", e)
      })?;

    // Build client cert auth (TLS layer) and user password auth (application layer)
    let client_cert_auth = match &auth_config {
      Some(config) => ClientCertAuth::from_config(config)
        .map_err(|e| anyhow!("client cert auth setup failed: {}", e))?,
      None => ClientCertAuth::none(),
    };
    let user_password_auth = match &auth_config {
      Some(config) => UserPasswordAuth::from_config(config),
      None => UserPasswordAuth::none(),
    };

    // Load TLS config
    let tls_config = load_tls_config(
      &args.server_cert_path,
      &args.server_key_path,
      &client_cert_auth,
    )?;

    Ok(plugin::Listener::new(Self {
      address,
      tls_config,
      quic_config,
      user_password_auth,
      stream_tracker: Rc::new(StreamTracker::new()),
      shutdown_handle: plugin::ShutdownHandle::new(),
      service: svc,
      access_log_writer: ctx.access_log_writer,
      service_name: ctx.service_name,
    }))
  }
}

impl plugin::Listening for Http3Listener {
  fn start(&self) -> Pin<Box<dyn Future<Output = Result<()>>>> {
    let address = self.address;
    let tls_config = self.tls_config.clone();
    let quic_config = self.quic_config.clone();
    let user_password_auth = self.user_password_auth.clone();
    let stream_tracker = self.stream_tracker.clone();
    let shutdown_handle = self.shutdown_handle.clone();
    let service = self.service.clone();
    let access_log_writer = self.access_log_writer.clone();
    let service_name = self.service_name.clone();

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

      // Create Quinn endpoint (server_config is already set here)
      let endpoint = quinn::Endpoint::server(server_config, address)?;

      info!("HTTP/3 Listener started on {}", address);

      // Monitoring is integrated into the accept loop below
      // to avoid Send requirements with spawn_local

      // Accept connections loop with integrated monitoring
      let mut monitoring_interval =
        tokio::time::interval(MONITORING_LOG_INTERVAL);
      monitoring_interval.tick().await; // Skip first immediate tick

      loop {
        let accept_result = tokio::select! {
          res = endpoint.accept() => res,
          _ = monitoring_interval.tick() => {
            // Log monitoring info
            info!(
              "[http3.listener] active_connections={}, active_streams={}",
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
            let service = service.clone();
            let user_password_auth_for_conn =
              user_password_auth.clone();
            let tracker_for_register = stream_tracker.clone();
            let tracker_for_handler = stream_tracker.clone();
            let stream_shutdown = tracker_for_handler.shutdown_handle();
            let access_log_writer = access_log_writer.clone();
            let service_name = service_name.clone();

            tracker_for_register.register_connection(async move {
              match conn.await {
                Ok(quinn_conn) => {
                  handle_h3_connection(
                    quinn_conn,
                    service,
                    user_password_auth_for_conn,
                    tracker_for_handler,
                    stream_shutdown,
                    access_log_writer,
                    service_name,
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
            // Endpoint closed
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

      // Close the endpoint with H3_NO_ERROR code for graceful shutdown
      endpoint.close(
        quinn::VarInt::from_u32(H3_NO_ERROR_CODE),
        b"listener shutdown",
      );

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
  "http3.listener"
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
  use crate::auth::listener_auth_config::UserCredential;
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
    // No auth configured (None) should work
    let args = Http3ListenerArgs {
      address: "0.0.0.0:443".to_string(),
      server_cert_path: "/path/cert.pem".to_string(),
      server_key_path: "/path/key.pem".to_string(),
      auth: None,
      quic: None,
    };
    assert!(args.auth.is_none());
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
    assert!(config.users.is_some());
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
      config.client_ca_pathbuf(),
      Some(std::path::PathBuf::from("/path/to/ca.pem"))
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
    assert!(config.users.is_some());
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

  // ============== Listener Name Tests ==============

  #[test]
  fn test_listener_name() {
    assert_eq!(listener_name(), "http3.listener");
  }

  #[test]
  fn test_create_listener_builder() {
    let _builder = create_listener_builder();
  }

  // ============== Http3ListenerArgs Tests ==============

  #[test]
  fn test_http3_listener_args_deserialize_minimal() {
    let yaml = r#"
address: "0.0.0.0:443"
server_cert_path: "/path/to/cert.pem"
server_key_path: "/path/to/key.pem"
"#;
    let args: Http3ListenerArgs = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(args.address, "0.0.0.0:443");
    assert_eq!(args.server_cert_path, "/path/to/cert.pem");
    assert_eq!(args.server_key_path, "/path/to/key.pem");
    assert!(args.quic.is_none());
    assert!(args.auth.is_none());
  }

  #[test]
  fn test_http3_listener_args_deserialize_full() {
    let yaml = r#"
address: "0.0.0.0:443"
server_cert_path: "/path/to/cert.pem"
server_key_path: "/path/to/key.pem"
quic:
  max_concurrent_bidi_streams: 200
  max_idle_timeout_ms: 60000
  initial_mtu: 1400
  send_window: 20971520
  receive_window: 20971520
auth:
  users:
    - username: user1
      password: secret123
    - username: user2
      password: secret456
"#;
    let args: Http3ListenerArgs = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(args.address, "0.0.0.0:443");
    assert!(args.quic.is_some());
    assert!(args.auth.is_some());
  }

  #[test]
  fn test_http3_listener_args_missing_required() {
    let yaml = r#"
address: "0.0.0.0:443"
"#;
    let result: Result<Http3ListenerArgs, _> =
      serde_yaml::from_str(yaml);
    assert!(result.is_err());
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
    let user_password_auth = UserPasswordAuth::from_config(&ListenerAuthConfig {
      users: Some(vec![UserCredential {
        username: "testuser".to_string(),
        password: "testpass".to_string(),
      }]),
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
    let result = user_password_auth.verify_and_extract_username(&req_invalid);
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
      buffer: crate::access_log::HumanBytes(64),
      flush: crate::access_log::HumanDuration(
        std::time::Duration::from_millis(100),
      ),
      max_size: crate::access_log::HumanBytes(1024 * 1024),
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
}
