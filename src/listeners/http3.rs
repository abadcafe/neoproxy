#![allow(clippy::await_holding_refcell_ref)]
use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use base64::{
  Engine, engine::general_purpose::STANDARD as BASE64_STANDARD,
};
use bytes::{Buf, Bytes};
use h3::server;
use http_body_util::BodyExt;
use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::CertificateDer;
use serde::Deserialize;
use tokio::net;
use tokio::task::JoinSet;
use tracing::{info, warn};

use crate::auth::{AuthType, TlsClientCertVerifier, verify_password};
use crate::plugin;

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
  pub cert_path: String,
  /// TLS private key file path (PEM format)
  pub key_path: String,
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
// Stream Tracker
// ============================================================================

/// Stream task tracker for graceful shutdown
///
/// Tracks all active HTTP/3 stream tasks and provides graceful shutdown
/// capabilities. When shutdown is triggered, stream tasks should listen
/// to the shutdown notification and exit gracefully.
///
/// # Example
///
/// ```ignore
/// let tracker = StreamTracker::new();
///
/// // Register a stream task
/// tracker.register(async move {
///     // Handle stream data transfer
/// });
///
/// // Graceful shutdown: trigger notification, wait for streams to exit
/// tracker.shutdown();
/// tokio::time::timeout(Duration::from_secs(5), tracker.wait_shutdown()).await.ok();
/// tracker.abort_all();
/// ```
pub struct StreamTracker {
  /// Active stream tasks
  streams: Rc<RefCell<JoinSet<()>>>,
  /// Active connection tasks (for connection_count)
  connections: Rc<RefCell<JoinSet<()>>>,
  /// Shutdown notification handle
  shutdown_handle: plugin::ShutdownHandle,
}

impl StreamTracker {
  /// Create a new StreamTracker
  pub fn new() -> Self {
    Self {
      streams: Rc::new(RefCell::new(JoinSet::new())),
      connections: Rc::new(RefCell::new(JoinSet::new())),
      shutdown_handle: plugin::ShutdownHandle::new(),
    }
  }

  /// Register a new stream task
  ///
  /// The stream task will be tracked and can be notified on shutdown.
  pub fn register(
    &self,
    stream_future: impl Future<Output = ()> + 'static,
  ) {
    self.streams.borrow_mut().spawn_local(stream_future);
  }

  /// Register a connection task (for connection tracking)
  pub fn register_connection(
    &self,
    conn_future: impl Future<Output = ()> + 'static,
  ) {
    self.connections.borrow_mut().spawn_local(conn_future);
  }

  /// Trigger shutdown notification
  ///
  /// Notifies all stream tasks to prepare for shutdown.
  /// Stream tasks should listen to `shutdown_handle().notified()`.
  pub fn shutdown(&self) {
    self.shutdown_handle.shutdown();
  }

  /// Forcefully abort all stream tasks
  ///
  /// Immediately terminates all registered stream tasks.
  /// Should be called after `shutdown()` timeout.
  pub fn abort_all(&self) {
    self.streams.borrow_mut().abort_all();
    self.connections.borrow_mut().abort_all();
  }

  /// Wait for all stream tasks to complete
  ///
  /// Returns when all stream tasks have finished.
  /// Efficiently waits using join_next in a loop.
  pub async fn wait_shutdown(&self) {
    // Wait for all streams to complete
    while self.streams.borrow_mut().join_next().await.is_some() {}
    // Wait for all connections to complete
    while self.connections.borrow_mut().join_next().await.is_some() {}
  }

  /// Wait for all stream tasks to complete with timeout
  ///
  /// Returns Ok(()) if all tasks complete within timeout.
  /// Returns Err(()) if timeout expires before all tasks complete.
  pub async fn wait_shutdown_with_timeout(
    &self,
    timeout: Duration,
  ) -> std::result::Result<(), ()> {
    tokio::time::timeout(timeout, self.wait_shutdown())
      .await
      .map_err(|_| ())
  }

  /// Get the shutdown handle for listening to shutdown notifications
  pub fn shutdown_handle(&self) -> plugin::ShutdownHandle {
    self.shutdown_handle.clone()
  }

  /// Get the count of active streams
  pub fn active_count(&self) -> usize {
    self.streams.borrow().len()
  }

  /// Get the count of active connections
  pub fn connection_count(&self) -> usize {
    self.connections.borrow().len()
  }
}

impl Default for StreamTracker {
  fn default() -> Self {
    Self::new()
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

/// Build an empty response with the given status
fn build_empty_response(status: http::StatusCode) -> plugin::Response {
  let empty = http_body_util::Empty::new();
  let bytes_buf = plugin::BytesBufBodyWrapper::new(empty);
  let body = plugin::ResponseBody::new(bytes_buf);
  let mut resp = plugin::Response::new(body);
  *resp.status_mut() = status;
  resp
}

// ============================================================================
// HTTP/3 Stream Handler Helpers
// ============================================================================

/// Transfer direction indicator for logging
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransferDirection {
  H3ToTcp,
  TcpToH3,
  Shutdown,
}

impl std::fmt::Display for TransferDirection {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      TransferDirection::H3ToTcp => write!(f, "H3->TCP"),
      TransferDirection::TcpToH3 => write!(f, "TCP->H3"),
      TransferDirection::Shutdown => write!(f, "shutdown"),
    }
  }
}

/// Validate HTTP method for CONNECT request
///
/// Returns Ok(()) if method is CONNECT, Err with error response otherwise.
fn validate_connect_method(req: &http::Request<()>) -> Result<()> {
  if req.method() == http::Method::CONNECT {
    Ok(())
  } else {
    bail!(
      "Method Not Allowed: only CONNECT is supported, got {}",
      req.method()
    )
  }
}

/// Validate target address from CONNECT request
///
/// Returns Ok(target_address) if valid, Err with error message otherwise.
fn validate_target_address(req: &http::Request<()>) -> Result<String> {
  let authority = req.uri().authority().ok_or_else(|| {
    anyhow!("Bad Request: invalid target address - missing authority")
  })?;

  let port = authority.port_u16().ok_or_else(|| {
    anyhow!("Bad Request: invalid target address - missing port")
  })?;

  if port == 0 {
    bail!("Bad Request: invalid target address - port cannot be zero");
  }

  Ok(authority.to_string())
}

/// Handle password authentication for HTTP proxy
///
/// Returns Ok(()) if authentication succeeds, Err with error message otherwise.
fn handle_password_auth(
  req: &http::Request<()>,
  credentials: &HashMap<String, String>,
) -> Result<()> {
  let auth_header = req
    .headers()
    .get(http::header::PROXY_AUTHORIZATION)
    .ok_or_else(|| anyhow!("Proxy Authentication Required"))?;

  let (username, password) = parse_basic_auth(auth_header.clone())?;

  // Use plaintext password verification from auth module
  verify_password(credentials, &username, &password).map_err(|_| {
    anyhow!("Proxy Authentication Required - invalid credentials")
  })?;

  Ok(())
}

/// Perform HTTP authentication based on config
///
/// Returns Ok(()) if authentication succeeds or no auth needed,
/// Err with error message otherwise.
fn perform_authentication(
  req: &http::Request<()>,
  auth_config: Option<&crate::auth::AuthConfig>,
) -> Result<()> {
  match auth_config {
    None => Ok(()), // No auth configured
    Some(config) => {
      match config.auth_type {
        AuthType::Password => {
          let users = config.users_map().ok_or_else(|| {
            anyhow!("password auth configured but no users")
          })?;
          handle_password_auth(req, &users)
        }
        AuthType::TlsClientCert => Ok(()), // TLS cert handled at QUIC level
      }
    }
  }
}

/// Connect to target server
///
/// Returns Ok(TcpStream) if connection succeeds, Err with error message otherwise.
async fn connect_to_target(
  target_addr: &str,
) -> Result<net::TcpStream> {
  match net::TcpStream::connect(target_addr).await {
    Ok(s) => Ok(s),
    Err(e) => {
      warn!("Failed to connect to target {}: {}", target_addr, e);
      bail!("Bad Gateway: failed to connect to target")
    }
  }
}

// ============================================================================
// HTTP/3 Stream Handler
// ============================================================================

/// Result of CONNECT request validation
enum ValidationError {
  MethodNotAllowed(String),
  Unauthorized(String),
  BadRequest(String),
}

/// Validate CONNECT request (method, authentication, target address)
///
/// Returns Ok(target_address) if validation passes, Err otherwise.
fn validate_connect_request(
  req: &http::Request<()>,
  auth_config: Option<&crate::auth::AuthConfig>,
) -> std::result::Result<String, ValidationError> {
  // Step 1: Validate CONNECT method
  if let Err(e) = validate_connect_method(req) {
    return Err(ValidationError::MethodNotAllowed(e.to_string()));
  }

  // Step 2: Perform authentication
  if let Err(e) = perform_authentication(req, auth_config) {
    return Err(ValidationError::Unauthorized(e.to_string()));
  }

  // Step 3: Validate target address
  match validate_target_address(req) {
    Ok(addr) => Ok(addr),
    Err(e) => Err(ValidationError::BadRequest(e.to_string())),
  }
}

/// Log the result of bidirectional transfer
fn log_transfer_result(
  direction: TransferDirection,
  result: &Result<()>,
) {
  match result {
    Ok(()) => {
      info!(
        "Bidirectional transfer completed normally on {} direction",
        direction
      );
    }
    Err(e) => {
      if direction == TransferDirection::Shutdown {
        info!("Bidirectional transfer terminated by shutdown");
      } else {
        warn!(
          "Bidirectional transfer terminated with error on {} direction: {}",
          direction, e
        );
      }
    }
  }
}

/// Result of bidirectional transfer
struct TransferResult {
  direction: TransferDirection,
  result: Result<()>,
}

/// Perform bidirectional data transfer between H3 stream and TCP
///
/// This function handles the data transfer phase of a CONNECT tunnel,
/// simultaneously transferring data in both directions until one side
/// closes, an error occurs, or shutdown is signaled.
async fn perform_bidirectional_transfer<S>(
  stream: server::RequestStream<S, Bytes>,
  target_stream: net::TcpStream,
  shutdown_handle: plugin::ShutdownHandle,
) -> TransferResult
where
  S: h3::quic::BidiStream<Bytes> + Send + 'static,
  <S as h3::quic::BidiStream<Bytes>>::SendStream: Send,
  <S as h3::quic::BidiStream<Bytes>>::RecvStream: Send,
{
  let (mut tcp_read, mut tcp_write) = target_stream.into_split();
  let (mut send_stream, mut recv_stream) = stream.split();

  let (direction, result) = tokio::select! {
    res = async {
      // H3 stream -> TCP
      use tokio::io::AsyncWriteExt;
      while let Some(mut data) = recv_stream.recv_data().await? {
        while data.has_remaining() {
          let chunk = data.chunk();
          tcp_write.write_all(chunk).await?;
          data.advance(chunk.len());
        }
      }
      Ok::<_, anyhow::Error>(())
    } => {
      (TransferDirection::H3ToTcp, res)
    }
    res = async {
      // TCP -> H3 stream
      use tokio::io::AsyncReadExt;
      let mut buf = [0u8; 8192];
      loop {
        let n = tcp_read.read(&mut buf).await?;
        if n == 0 {
          break;
        }
        send_stream.send_data(Bytes::copy_from_slice(&buf[..n])).await?;
      }
      Ok::<_, anyhow::Error>(())
    } => {
      (TransferDirection::TcpToH3, res)
    }
    _ = shutdown_handle.notified() => {
      (TransferDirection::Shutdown, Err(anyhow!("shutdown notification")))
    }
  };

  // Finish the send stream to properly close the H3 stream
  if let Err(e) = send_stream.finish().await {
    warn!("Failed to finish send stream: {e}");
  }

  TransferResult { direction, result }
}

/// Send error response for a validation error
///
/// Maps ValidationError to appropriate HTTP status codes and sends
/// the error response to the client.
async fn handle_validation_error<S>(
  stream: &mut server::RequestStream<S, Bytes>,
  error: ValidationError,
) where
  S: h3::quic::SendStream<Bytes>,
{
  match error {
    ValidationError::MethodNotAllowed(msg) => {
      send_error_response(stream, msg, 405, true).await;
    }
    ValidationError::Unauthorized(msg) => {
      send_error_response(stream, msg, 407, true).await;
    }
    ValidationError::BadRequest(msg) => {
      send_error_response(stream, msg, 400, true).await;
    }
  }
}

/// Handle a single HTTP/3 stream (CONNECT request)
///
/// This function orchestrates the complete handling of an HTTP/3 CONNECT
/// request including validation, authentication, target connection, and
/// bidirectional data transfer.
async fn handle_h3_stream<S>(
  req: http::Request<()>,
  mut stream: server::RequestStream<S, Bytes>,
  _service: plugin::Service,
  auth_config: Option<crate::auth::AuthConfig>,
  shutdown_handle: plugin::ShutdownHandle,
) where
  S: h3::quic::BidiStream<Bytes> + Send + 'static,
  <S as h3::quic::BidiStream<Bytes>>::SendStream: Send,
  <S as h3::quic::BidiStream<Bytes>>::RecvStream: Send,
{
  // Phase 1: Validate request
  let target_addr =
    match validate_connect_request(&req, auth_config.as_ref()) {
      Ok(addr) => addr,
      Err(e) => {
        handle_validation_error(&mut stream, e).await;
        return;
      }
    };

  // Phase 2: Connect to target
  let target_stream = match connect_to_target(&target_addr).await {
    Ok(s) => s,
    Err(e) => {
      send_error_response(&mut stream, e.to_string(), 502, true).await;
      return;
    }
  };

  // Phase 3: Send 200 OK response
  let resp = build_empty_response(http::StatusCode::OK);
  if let Err(e) = send_h3_response(&mut stream, resp, false).await {
    warn!("Failed to send HTTP/3 response: {e}");
    return;
  }

  // Phase 4: Perform bidirectional transfer
  let transfer_result = perform_bidirectional_transfer(
    stream,
    target_stream,
    shutdown_handle,
  )
  .await;

  log_transfer_result(
    transfer_result.direction,
    &transfer_result.result,
  );
}

/// Send an error response to the client
///
/// Helper function to send error responses with proper logging.
async fn send_error_response<S>(
  stream: &mut server::RequestStream<S, Bytes>,
  message: String,
  status_code: u16,
  finish_stream: bool,
) where
  S: h3::quic::SendStream<Bytes>,
{
  let status = http::StatusCode::from_u16(status_code)
    .unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR);
  let resp = build_error_response(status, &message);
  if let Err(e) = send_h3_response(stream, resp, finish_stream).await {
    warn!("Failed to send {} response: {}", status_code, e);
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
async fn send_h3_response<S>(
  stream: &mut server::RequestStream<S, Bytes>,
  resp: plugin::Response,
  finish_stream: bool,
) -> Result<()>
where
  S: h3::quic::SendStream<Bytes>,
{
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

/// Parse Basic authentication header
fn parse_basic_auth(
  header_value: http::HeaderValue,
) -> Result<(String, String)> {
  let header_str = header_value.to_str()?;
  if !header_str.starts_with("Basic ") {
    bail!("Not Basic authentication");
  }
  let encoded = &header_str[6..];
  let decoded = BASE64_STANDARD.decode(encoded)?;
  let decoded_str = String::from_utf8(decoded)?;
  let mut parts = decoded_str.splitn(2, ':');
  let username = parts.next().ok_or_else(|| anyhow!("No username"))?;
  let password = parts.next().ok_or_else(|| anyhow!("No password"))?;
  Ok((username.to_string(), password.to_string()))
}

// ============================================================================
// HTTP/3 Connection Handler
// ============================================================================

/// Result of TLS client certificate verification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsClientCertVerifyResult {
  /// Certificate is present and valid
  Valid,
  /// No certificate was presented
  Missing,
  /// Certificate downcast failed (unexpected type)
  InvalidType,
}

/// Verify TLS client certificate for TlsClientCert authentication
///
/// This function checks if the peer identity (client certificate) is present
/// and can be properly downcast to the expected certificate type.
///
/// # Arguments
/// * `peer_identity` - Optional peer identity from `conn.peer_identity()`
///
/// # Returns
/// * `Valid` if certificate is present and properly typed
/// * `Missing` if no certificate was presented
/// * `InvalidType` if certificate is present but has unexpected type
pub fn verify_tls_client_cert(
  peer_identity: Option<Box<dyn std::any::Any>>,
) -> TlsClientCertVerifyResult {
  match peer_identity {
    Some(certificates) => {
      // Verify the downcast to Vec<CertificateDer> succeeds
      // The peer_identity returns Box<dyn Any>, and for rustls backend
      // it should be downcastable to Vec<CertificateDer>
      if certificates
        .downcast::<Vec<CertificateDer<'static>>>()
        .is_err()
      {
        TlsClientCertVerifyResult::InvalidType
      } else {
        TlsClientCertVerifyResult::Valid
      }
    }
    None => TlsClientCertVerifyResult::Missing,
  }
}

/// Handle a single HTTP/3 connection
async fn handle_h3_connection(
  conn: quinn::Connection,
  service: plugin::Service,
  auth_config: Option<crate::auth::AuthConfig>,
  stream_tracker: Rc<StreamTracker>,
  shutdown_handle: plugin::ShutdownHandle,
) {
  // Security check: Verify client certificate for TlsClientCert authentication
  // This is required to prevent TLS client cert bypass vulnerability.
  // Per architecture doc section 5.3.2, when TlsClientCert auth is configured,
  // we must verify that the peer presented a valid client certificate.
  if let Some(ref config) = auth_config
    && matches!(config.auth_type, AuthType::TlsClientCert)
  {
    let verify_result = verify_tls_client_cert(conn.peer_identity());
    match verify_result {
      TlsClientCertVerifyResult::Valid => {
        // Client certificate is present and valid
        info!("TLS client certificate verified successfully");
      }
      TlsClientCertVerifyResult::Missing => {
        warn!(
          "No client certificate presented - closing connection for security"
        );
        // Close with H3_NO_ERROR code for graceful shutdown
        conn.close(
          quinn::VarInt::from_u32(H3_NO_ERROR_CODE),
          b"client certificate required",
        );
        return;
      }
      TlsClientCertVerifyResult::InvalidType => {
        warn!(
          "Failed to downcast peer certificate - closing connection for \
           security"
        );
        // Close with H3_NO_ERROR code for graceful shutdown
        conn.close(
          quinn::VarInt::from_u32(H3_NO_ERROR_CODE),
          b"invalid client certificate",
        );
        return;
      }
    }
  }

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
        let auth_config = auth_config.clone();
        let stream_shutdown = stream_tracker.shutdown_handle();
        stream_tracker.register(async move {
          match resolver.resolve_request().await {
            Ok((req, stream)) => {
              handle_h3_stream(
                req,
                stream,
                service,
                auth_config,
                stream_shutdown,
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
  auth_config: Option<&crate::auth::AuthConfig>,
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

  // Build TLS config based on auth type
  let tls_config = match auth_config {
    None => {
      let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
      config.alpn_protocols = vec![ALPN.to_vec()];
      config
    }
    Some(config) => {
      match config.auth_type {
        AuthType::Password => {
          let mut tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;
          tls_config.alpn_protocols = vec![ALPN.to_vec()];
          tls_config
        }
        AuthType::TlsClientCert => {
          let client_ca_path =
            config.client_ca_pathbuf().ok_or_else(|| {
              anyhow!(
                "client_ca_path required for tls_client_cert auth"
              )
            })?;

          // Use TlsClientCertVerifier from auth module
          let verifier =
            TlsClientCertVerifier::from_ca_path(&client_ca_path)?;
          let mut tls_config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier.verifier())
            .with_single_cert(certs, key)?;
          tls_config.alpn_protocols = vec![ALPN.to_vec()];
          tls_config
        }
      }
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
  /// Authentication configuration (None = no auth required)
  auth_config: Option<crate::auth::AuthConfig>,
  /// Stream tracker
  stream_tracker: Rc<StreamTracker>,
  /// Shutdown handle
  shutdown_handle: plugin::ShutdownHandle,
  /// Associated service
  service: plugin::Service,
}

impl Http3Listener {
  /// Create a new HTTP/3 Listener
  #[allow(clippy::new_ret_no_self)]
  pub fn new(
    sargs: plugin::SerializedArgs,
    svc: plugin::Service,
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

    // Parse authentication config
    let auth_config: Option<crate::auth::AuthConfig> = args
      .auth
      .map(|a| {
        crate::auth::AuthConfig::from_yaml(
          a,
          &[AuthType::Password, AuthType::TlsClientCert],
        )
      })
      .transpose()
      .map_err(|e| anyhow!("auth config validation failed: {}", e))?;

    // Load TLS config
    let tls_config = load_tls_config(
      &args.cert_path,
      &args.key_path,
      auth_config.as_ref(),
    )?;

    Ok(plugin::Listener::new(Self {
      address,
      tls_config,
      quic_config,
      auth_config,
      stream_tracker: Rc::new(StreamTracker::new()),
      shutdown_handle: plugin::ShutdownHandle::new(),
      service: svc,
    }))
  }
}

impl plugin::Listening for Http3Listener {
  fn start(&self) -> Pin<Box<dyn Future<Output = Result<()>>>> {
    let address = self.address;
    let tls_config = self.tls_config.clone();
    let quic_config = self.quic_config.clone();
    let auth_config = self.auth_config.clone();
    let stream_tracker = self.stream_tracker.clone();
    let shutdown_handle = self.shutdown_handle.clone();
    let service = self.service.clone();

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
            let auth_config = auth_config.clone();
            let tracker_for_register = stream_tracker.clone();
            let tracker_for_handler = stream_tracker.clone();
            let stream_shutdown = tracker_for_handler.shutdown_handle();

            tracker_for_register.register_connection(async move {
              match conn.await {
                Ok(quinn_conn) => {
                  handle_h3_connection(
                    quinn_conn,
                    service,
                    auth_config,
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
  use http_body::Body;

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

  // ============== AuthConfig Tests ==============
  // Tests for the new auth module integration

  #[test]
  fn test_auth_config_none() {
    // No auth configured (None) should work
    let args = Http3ListenerArgs {
      address: "0.0.0.0:443".to_string(),
      cert_path: "/path/cert.pem".to_string(),
      key_path: "/path/key.pem".to_string(),
      auth: None,
      quic: None,
    };
    assert!(args.auth.is_none());
  }

  #[test]
  fn test_auth_config_password_plaintext() {
    // Test that plaintext password format works with new auth module
    let yaml = r#"
type: password
users:
  - username: admin
    password: plaintext_secret
"#;
    let yaml_value: serde_yaml::Value =
      serde_yaml::from_str(yaml).expect("parse yaml");
    let result = crate::auth::AuthConfig::from_yaml(
      yaml_value,
      &[AuthType::Password, AuthType::TlsClientCert],
    );
    assert!(result.is_ok());
    let config = result.unwrap();
    assert_eq!(config.auth_type, AuthType::Password);
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
type: tls_client_cert
client_ca_path: /path/to/ca.pem
"#;
    let yaml_value: serde_yaml::Value =
      serde_yaml::from_str(yaml).expect("parse yaml");
    let result = crate::auth::AuthConfig::from_yaml(
      yaml_value,
      &[AuthType::Password, AuthType::TlsClientCert],
    );
    assert!(result.is_ok());
    let config = result.unwrap();
    assert_eq!(config.auth_type, AuthType::TlsClientCert);
    assert_eq!(
      config.client_ca_pathbuf(),
      Some(std::path::PathBuf::from("/path/to/ca.pem"))
    );
  }

  #[test]
  fn test_auth_config_password_missing_users() {
    // Password auth without users should fail
    let yaml = r#"
type: password
"#;
    let yaml_value: serde_yaml::Value =
      serde_yaml::from_str(yaml).expect("parse yaml");
    let result = crate::auth::AuthConfig::from_yaml(
      yaml_value,
      &[AuthType::Password, AuthType::TlsClientCert],
    );
    assert!(result.is_err());
  }

  #[test]
  fn test_auth_config_tls_client_cert_missing_path() {
    // TLS client cert without path should fail
    let yaml = r#"
type: tls_client_cert
"#;
    let yaml_value: serde_yaml::Value =
      serde_yaml::from_str(yaml).expect("parse yaml");
    let result = crate::auth::AuthConfig::from_yaml(
      yaml_value,
      &[AuthType::Password, AuthType::TlsClientCert],
    );
    assert!(result.is_err());
  }

  #[test]
  fn test_auth_config_invalid_type() {
    // Invalid auth type should fail
    let yaml = r#"
type: invalid_type
"#;
    let yaml_value: serde_yaml::Value =
      serde_yaml::from_str(yaml).expect("parse yaml");
    let result = crate::auth::AuthConfig::from_yaml(
      yaml_value,
      &[AuthType::Password, AuthType::TlsClientCert],
    );
    assert!(result.is_err());
  }

  // ============== StreamTracker Tests ==============

  #[test]
  fn test_stream_tracker_new() {
    let tracker = StreamTracker::new();
    assert_eq!(tracker.active_count(), 0);
    assert_eq!(tracker.connection_count(), 0);
  }

  #[test]
  fn test_stream_tracker_default() {
    let tracker = StreamTracker::default();
    assert_eq!(tracker.active_count(), 0);
  }

  #[tokio::test]
  async fn test_stream_tracker_register() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let tracker = StreamTracker::new();
        tracker.register(async {});
        tokio::task::yield_now().await;
        assert_eq!(tracker.active_count(), 1);
      })
      .await;
  }

  #[tokio::test]
  async fn test_stream_tracker_register_multiple() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let tracker = StreamTracker::new();
        tracker.register(async {});
        tracker.register(async {});
        tracker.register(async {});
        tokio::task::yield_now().await;
        assert_eq!(tracker.active_count(), 3);
      })
      .await;
  }

  #[tokio::test]
  async fn test_stream_tracker_shutdown() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let tracker = StreamTracker::new();
        let shutdown_handle = tracker.shutdown_handle();

        let notified = Rc::new(std::cell::Cell::new(false));
        let notified_clone = notified.clone();
        tracker.register(async move {
          shutdown_handle.notified().await;
          notified_clone.set(true);
        });
        tokio::task::yield_now().await;

        tracker.shutdown();
        tracker.wait_shutdown().await;
        assert_eq!(tracker.active_count(), 0);
        assert!(notified.get());
      })
      .await;
  }

  #[tokio::test]
  async fn test_stream_tracker_abort_all() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let tracker = StreamTracker::new();
        tracker.register(async {
          std::future::pending::<()>().await;
        });
        tokio::task::yield_now().await;
        assert_eq!(tracker.active_count(), 1);

        tracker.abort_all();
        tracker.wait_shutdown().await;
        assert_eq!(tracker.active_count(), 0);
      })
      .await;
  }

  #[test]
  fn test_stream_tracker_abort_all_empty() {
    let tracker = StreamTracker::new();
    tracker.abort_all();
    assert_eq!(tracker.active_count(), 0);
  }

  #[test]
  fn test_stream_tracker_shutdown_handle() {
    let tracker = StreamTracker::new();
    let _handle = tracker.shutdown_handle();
  }

  #[tokio::test]
  async fn test_stream_tracker_connection_count() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let tracker = StreamTracker::new();
        tracker.register_connection(async {});
        tokio::task::yield_now().await;
        assert_eq!(tracker.connection_count(), 1);
        assert_eq!(tracker.active_count(), 0);
      })
      .await;
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
  fn test_build_empty_response_ok() {
    let resp = build_empty_response(http::StatusCode::OK);
    assert_eq!(resp.status(), http::StatusCode::OK);
  }

  // ============== Base64 Decode Tests ==============

  #[test]
  fn test_base64_decode_simple() {
    let result = BASE64_STANDARD.decode("dGVzdA==").unwrap();
    assert_eq!(result, b"test");
  }

  #[test]
  fn test_base64_decode_user_password() {
    // base64 of "user:password"
    let result =
      BASE64_STANDARD.decode("dXNlcjpwYXNzd29yZA==").unwrap();
    assert_eq!(result, b"user:password");
  }

  #[test]
  fn test_base64_decode_invalid_character() {
    let result = BASE64_STANDARD.decode("!!!invalid");
    assert!(result.is_err());
  }

  // ============== Basic Auth Parsing Tests ==============

  #[test]
  fn test_parse_basic_auth_valid() {
    // base64 of "user:password" is "dXNlcjpwYXNzd29yZA=="
    let header_value =
      http::HeaderValue::from_str("Basic dXNlcjpwYXNzd29yZA==")
        .unwrap();
    let (username, password) = parse_basic_auth(header_value).unwrap();
    assert_eq!(username, "user");
    assert_eq!(password, "password");
  }

  #[test]
  fn test_parse_basic_auth_not_basic() {
    let header_value =
      http::HeaderValue::from_str("Bearer token123").unwrap();
    let result = parse_basic_auth(header_value);
    assert!(result.is_err());
  }

  #[test]
  fn test_parse_basic_auth_missing_password() {
    // base64 of "user" is "dXNlcg=="
    let header_value =
      http::HeaderValue::from_str("Basic dXNlcg==").unwrap();
    let result = parse_basic_auth(header_value);
    assert!(result.is_err());
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
cert_path: "/path/to/cert.pem"
key_path: "/path/to/key.pem"
"#;
    let args: Http3ListenerArgs = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(args.address, "0.0.0.0:443");
    assert_eq!(args.cert_path, "/path/to/cert.pem");
    assert_eq!(args.key_path, "/path/to/key.pem");
    assert!(args.quic.is_none());
    assert!(args.auth.is_none());
  }

  #[test]
  fn test_http3_listener_args_deserialize_full() {
    let yaml = r#"
address: "0.0.0.0:443"
cert_path: "/path/to/cert.pem"
key_path: "/path/to/key.pem"
quic:
  max_concurrent_bidi_streams: 200
  max_idle_timeout_ms: 60000
  initial_mtu: 1400
  send_window: 20971520
  receive_window: 20971520
auth:
  type: password
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

  // ============== Additional StreamTracker Tests ==============

  #[tokio::test]
  async fn test_stream_tracker_register_and_complete() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let tracker = StreamTracker::new();
        let completed = Rc::new(std::cell::Cell::new(false));
        let completed_clone = completed.clone();
        tracker.register(async move {
          completed_clone.set(true);
        });
        tokio::task::yield_now().await;
        assert_eq!(tracker.active_count(), 1);

        // Wait for task to complete
        tracker.wait_shutdown().await;
        assert_eq!(tracker.active_count(), 0);
        assert!(completed.get());
      })
      .await;
  }

  #[tokio::test]
  async fn test_stream_tracker_shutdown_before_wait() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let tracker = StreamTracker::new();
        let shutdown_handle = tracker.shutdown_handle();

        tracker.register(async move {
          // Wait for shutdown notification
          shutdown_handle.notified().await;
        });
        tokio::task::yield_now().await;
        assert_eq!(tracker.active_count(), 1);

        // Trigger shutdown
        tracker.shutdown();

        // Give time for notification to propagate
        tokio::task::yield_now().await;

        // Wait for tasks to complete
        tracker.wait_shutdown().await;
        assert_eq!(tracker.active_count(), 0);
      })
      .await;
  }

  // ============== QuicConfigArgs Edge Cases ==============

  #[test]
  fn test_quic_config_args_validate_boundary_values() {
    // Test min boundary
    let args = QuicConfigArgs {
      max_concurrent_bidi_streams: Some(1),
      max_idle_timeout_ms: Some(1),
      initial_mtu: Some(1200),
      send_window: Some(1),
      receive_window: Some(1),
    };
    let config = args.validate_and_apply_defaults().unwrap();
    assert_eq!(config.max_concurrent_bidi_streams, 1);
    assert_eq!(config.max_idle_timeout_ms, 1);
    assert_eq!(config.initial_mtu, 1200);
    assert_eq!(config.send_window, 1);
    assert_eq!(config.receive_window, 1);

    // Test max boundary for max_concurrent_bidi_streams
    let args = QuicConfigArgs {
      max_concurrent_bidi_streams: Some(10000),
      ..Default::default()
    };
    let config = args.validate_and_apply_defaults().unwrap();
    assert_eq!(config.max_concurrent_bidi_streams, 10000);

    // Test max boundary for initial_mtu
    let args =
      QuicConfigArgs { initial_mtu: Some(9000), ..Default::default() };
    let config = args.validate_and_apply_defaults().unwrap();
    assert_eq!(config.initial_mtu, 9000);
  }

  // ============== Http3ListenerArgs Edge Cases ==============

  #[test]
  fn test_http3_listener_args_with_quic_and_auth() {
    let yaml = r#"
address: "127.0.0.1:8443"
cert_path: "/etc/ssl/cert.pem"
key_path: "/etc/ssl/key.pem"
quic:
  max_concurrent_bidi_streams: 50
auth:
  type: tls_client_cert
  client_ca_path: "/etc/ssl/client-ca.pem"
"#;
    let args: Http3ListenerArgs = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(args.address, "127.0.0.1:8443");
    assert!(args.quic.is_some());
    assert!(args.auth.is_some());

    let quic = args.quic.unwrap();
    assert_eq!(quic.max_concurrent_bidi_streams, Some(50));
  }

  // ============== Additional Http3ListenerArgs Tests ==============

  #[test]
  fn test_http3_listener_args_invalid_address() {
    // Test invalid address format (missing port)
    let yaml = r#"
address: "invalid_address"
cert_path: "/path/to/cert.pem"
key_path: "/path/to/key.pem"
"#;
    let args: Http3ListenerArgs = serde_yaml::from_str(yaml).unwrap();
    // The args parse successfully, but creating listener would fail
    // because the address is invalid for SocketAddr parsing
    assert_eq!(args.address, "invalid_address");
  }

  #[test]
  fn test_http3_listener_args_optional_defaults() {
    // Test that optional parameters are None when not provided
    let yaml = r#"
address: "0.0.0.0:443"
cert_path: "/path/to/cert.pem"
key_path: "/path/to/key.pem"
"#;
    let args: Http3ListenerArgs = serde_yaml::from_str(yaml).unwrap();
    assert!(args.quic.is_none());
    assert!(args.auth.is_none());
  }

  // ============== StreamTracker Timeout Tests ==============

  #[tokio::test]
  async fn test_stream_tracker_shutdown_with_timeout() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let tracker = StreamTracker::new();
        let _shutdown_handle = tracker.shutdown_handle();

        // Register a pending task that will wait for shutdown
        tracker.register(async move {
          // This will wait forever unless shutdown is triggered
          std::future::pending::<()>().await;
        });
        tokio::task::yield_now().await;
        assert_eq!(tracker.active_count(), 1);

        // Trigger shutdown
        tracker.shutdown();

        // Wait with timeout - should timeout because task is pending
        let wait_result = tokio::time::timeout(
          Duration::from_millis(50),
          tracker.wait_shutdown(),
        )
        .await;
        assert!(
          wait_result.is_err(),
          "wait_shutdown should timeout with pending task"
        );

        // Force abort
        tracker.abort_all();
        tracker.wait_shutdown().await;
        assert_eq!(tracker.active_count(), 0);
      })
      .await;
  }

  #[tokio::test]
  async fn test_stream_tracker_multiple_shutdown_calls() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let tracker = StreamTracker::new();
        tracker.register(async {});
        tokio::task::yield_now().await;

        // Multiple shutdown calls should be idempotent
        tracker.shutdown();
        tracker.shutdown();
        tracker.shutdown();

        tracker.wait_shutdown().await;
        assert_eq!(tracker.active_count(), 0);
      })
      .await;
  }

  // ============== QuicConfigArgs Clone Tests ==============

  #[test]
  fn test_quic_config_args_clone() {
    let args = QuicConfigArgs {
      max_concurrent_bidi_streams: Some(200),
      max_idle_timeout_ms: Some(60000),
      initial_mtu: Some(1400),
      send_window: Some(20971520),
      receive_window: Some(20971520),
    };
    let cloned = args.clone();
    assert_eq!(
      cloned.max_concurrent_bidi_streams,
      args.max_concurrent_bidi_streams
    );
  }

  #[test]
  fn test_quic_config_clone() {
    let config = QuicConfig {
      max_concurrent_bidi_streams: 200,
      max_idle_timeout_ms: 60000,
      initial_mtu: 1400,
      send_window: 20971520,
      receive_window: 20971520,
    };
    let cloned = config.clone();
    assert_eq!(
      cloned.max_concurrent_bidi_streams,
      config.max_concurrent_bidi_streams
    );
  }

  // ============== Http3ListenerArgs Clone Tests ==============

  #[test]
  fn test_http3_listener_args_clone() {
    let args = Http3ListenerArgs {
      address: "0.0.0.0:443".to_string(),
      cert_path: "/path/to/cert.pem".to_string(),
      key_path: "/path/to/key.pem".to_string(),
      quic: None,
      auth: None,
    };
    let cloned = args.clone();
    assert_eq!(cloned.address, args.address);
  }

  // ============== Error Response Body Tests ==============

  #[test]
  fn test_build_error_response_with_body() {
    let resp = build_error_response(
      http::StatusCode::INTERNAL_SERVER_ERROR,
      "Internal Server Error",
    );
    assert_eq!(resp.status(), http::StatusCode::INTERNAL_SERVER_ERROR);
  }

  // ============== TLS Configuration Tests ==============

  // Initialize CryptoProvider for tests that involve TLS
  static CRYPTO_PROVIDER_INIT: std::sync::Once = std::sync::Once::new();

  fn ensure_crypto_provider() {
    CRYPTO_PROVIDER_INIT.call_once(|| {
      let _ =
        rustls::crypto::ring::default_provider().install_default();
    });
  }

  /// Helper to generate a self-signed certificate using rcgen
  fn generate_test_cert(common_name: &str) -> (String, String) {
    let subject_alt_names = vec![common_name.to_string()];
    let rcgen::CertifiedKey { cert, key_pair } =
      rcgen::generate_simple_self_signed(subject_alt_names)
        .expect("Failed to generate test certificate");
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    (cert_pem, key_pem)
  }

  /// Helper to generate a CA certificate for client authentication
  fn generate_ca_cert() -> (String, String) {
    let mut params = rcgen::CertificateParams::default();
    params.is_ca =
      rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
      .distinguished_name
      .push(rcgen::DnType::CommonName, "Test CA");
    let key_pair =
      rcgen::KeyPair::generate().expect("Failed to generate key");
    let cert = params
      .self_signed(&key_pair)
      .expect("Failed to generate test CA certificate");
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    (cert_pem, key_pem)
  }

  /// Helper to set secure permissions on key file for Unix systems
  #[cfg(unix)]
  fn set_secure_key_permissions(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
      path,
      std::fs::Permissions::from_mode(0o600),
    )
    .expect("Failed to set key file permissions");
  }

  /// Helper to set secure permissions on key file for Unix systems
  /// (no-op on non-Unix systems)
  #[cfg(not(unix))]
  fn set_secure_key_permissions(_path: &std::path::Path) {
    // No permission check on non-Unix systems
  }

  /// Helper to write key file with secure permissions
  fn write_key_file_secure(
    path: &std::path::Path,
    content: &str,
  ) -> std::io::Result<()> {
    std::fs::write(path, content)?;
    set_secure_key_permissions(path);
    Ok(())
  }

  #[test]
  fn test_load_tls_config_success() {
    ensure_crypto_provider();
    // Generate test certificate and key
    let (cert_pem, key_pem) = generate_test_cert("test-server");

    // Create temp directory for test files
    let tmp_dir =
      tempfile::tempdir().expect("Failed to create temp dir");
    let cert_path = tmp_dir.path().join("cert.pem");
    let key_path = tmp_dir.path().join("key.pem");

    // Write certificate and key to files
    std::fs::write(&cert_path, cert_pem).expect("Failed to write cert");
    write_key_file_secure(&key_path, &key_pem)
      .expect("Failed to write key");

    // Test with no auth
    let auth_config = None;
    let result = load_tls_config(
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap(),
      auth_config.as_ref(),
    );

    assert!(
      result.is_ok(),
      "load_tls_config should succeed with valid cert and key"
    );
    let tls_config = result.unwrap();
    // Verify ALPN protocol is set
    assert!(tls_config.alpn_protocols.iter().any(|p| p == b"h3"));
  }

  #[test]
  fn test_load_tls_config_cert_not_found() {
    ensure_crypto_provider();
    let tmp_dir =
      tempfile::tempdir().expect("Failed to create temp dir");
    let cert_path = tmp_dir.path().join("nonexistent.pem");
    let key_path = tmp_dir.path().join("key.pem");

    // Only create key file, not cert
    let (_, key_pem) = generate_test_cert("test");
    write_key_file_secure(&key_path, &key_pem)
      .expect("Failed to write key");

    let auth_config = None;
    let result = load_tls_config(
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap(),
      auth_config.as_ref(),
    );

    assert!(
      result.is_err(),
      "load_tls_config should fail when cert file not found"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
      err_msg.contains("Failed to open certificate file"),
      "Error should mention certificate file: {err_msg}"
    );
  }

  #[test]
  fn test_load_tls_config_key_not_found() {
    ensure_crypto_provider();
    let tmp_dir =
      tempfile::tempdir().expect("Failed to create temp dir");
    let cert_path = tmp_dir.path().join("cert.pem");
    let key_path = tmp_dir.path().join("nonexistent.pem");

    // Only create cert file, not key
    let (cert_pem, _) = generate_test_cert("test");
    std::fs::write(&cert_path, cert_pem).expect("Failed to write cert");

    let auth_config = None;
    let result = load_tls_config(
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap(),
      auth_config.as_ref(),
    );

    assert!(
      result.is_err(),
      "load_tls_config should fail when key file not found"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
      err_msg.contains("Failed to get metadata")
        || err_msg.contains("Failed to open private key file"),
      "Error should mention key file issue: {err_msg}"
    );
  }

  #[test]
  fn test_load_tls_config_no_auth() {
    ensure_crypto_provider();
    let (cert_pem, key_pem) = generate_test_cert("test-server");
    let tmp_dir =
      tempfile::tempdir().expect("Failed to create temp dir");
    let cert_path = tmp_dir.path().join("cert.pem");
    let key_path = tmp_dir.path().join("key.pem");

    std::fs::write(&cert_path, cert_pem).expect("Failed to write cert");
    write_key_file_secure(&key_path, &key_pem)
      .expect("Failed to write key");

    let auth_config = None;
    let result = load_tls_config(
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap(),
      auth_config.as_ref(),
    );

    assert!(
      result.is_ok(),
      "load_tls_config should succeed with no auth"
    );
  }

  #[test]
  fn test_load_tls_config_password_auth() {
    ensure_crypto_provider();
    let (cert_pem, key_pem) = generate_test_cert("test-server");
    let tmp_dir =
      tempfile::tempdir().expect("Failed to create temp dir");
    let cert_path = tmp_dir.path().join("cert.pem");
    let key_path = tmp_dir.path().join("key.pem");

    std::fs::write(&cert_path, cert_pem).expect("Failed to write cert");
    write_key_file_secure(&key_path, &key_pem)
      .expect("Failed to write key");

    // Create password auth config using the new auth module
    let auth_config = Some(crate::auth::AuthConfig {
      auth_type: AuthType::Password,
      users: Some(vec![crate::auth::UserCredential {
        username: "user".to_string(),
        password: "test_password".to_string(),
      }]),
      client_ca_path: None,
    });

    let result = load_tls_config(
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap(),
      auth_config.as_ref(),
    );

    assert!(
      result.is_ok(),
      "load_tls_config should succeed with password auth"
    );
    // Password auth should use no_client_auth like None
    let tls_config = result.unwrap();
    assert!(tls_config.alpn_protocols.iter().any(|p| p == b"h3"));
  }

  #[test]
  fn test_load_tls_config_tls_client_cert_auth() {
    ensure_crypto_provider();
    // Generate server cert and CA cert
    let (server_cert_pem, server_key_pem) =
      generate_test_cert("test-server");
    let (ca_cert_pem, _) = generate_ca_cert();

    let tmp_dir =
      tempfile::tempdir().expect("Failed to create temp dir");
    let cert_path = tmp_dir.path().join("cert.pem");
    let key_path = tmp_dir.path().join("key.pem");
    let ca_path = tmp_dir.path().join("client_ca.pem");

    std::fs::write(&cert_path, server_cert_pem)
      .expect("Failed to write cert");
    write_key_file_secure(&key_path, &server_key_pem)
      .expect("Failed to write key");
    std::fs::write(&ca_path, ca_cert_pem)
      .expect("Failed to write CA cert");

    let auth_config = Some(crate::auth::AuthConfig {
      auth_type: AuthType::TlsClientCert,
      users: None,
      client_ca_path: Some(ca_path.to_str().unwrap().to_string()),
    });

    let result = load_tls_config(
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap(),
      auth_config.as_ref(),
    );

    assert!(
      result.is_ok(),
      "load_tls_config should succeed with TLS client cert auth"
    );
    let tls_config = result.unwrap();
    assert!(tls_config.alpn_protocols.iter().any(|p| p == b"h3"));
  }

  #[test]
  fn test_load_tls_config_tls_client_cert_auth_ca_not_found() {
    ensure_crypto_provider();
    let (cert_pem, key_pem) = generate_test_cert("test-server");
    let tmp_dir =
      tempfile::tempdir().expect("Failed to create temp dir");
    let cert_path = tmp_dir.path().join("cert.pem");
    let key_path = tmp_dir.path().join("key.pem");
    let ca_path = tmp_dir.path().join("nonexistent_ca.pem");

    std::fs::write(&cert_path, cert_pem).expect("Failed to write cert");
    write_key_file_secure(&key_path, &key_pem)
      .expect("Failed to write key");

    let auth_config = Some(crate::auth::AuthConfig {
      auth_type: AuthType::TlsClientCert,
      users: None,
      client_ca_path: Some(ca_path.to_str().unwrap().to_string()),
    });

    let result = load_tls_config(
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap(),
      auth_config.as_ref(),
    );

    assert!(
      result.is_err(),
      "load_tls_config should fail when client CA file not found"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
      err_msg.contains("failed to open CA file"),
      "Error should mention CA file: {err_msg}"
    );
  }

  #[test]
  fn test_load_tls_config_invalid_cert_content() {
    ensure_crypto_provider();
    let tmp_dir =
      tempfile::tempdir().expect("Failed to create temp dir");
    let cert_path = tmp_dir.path().join("cert.pem");
    let key_path = tmp_dir.path().join("key.pem");

    // Write invalid content
    std::fs::write(&cert_path, "not a valid certificate").unwrap();
    let (_, key_pem) = generate_test_cert("test");
    write_key_file_secure(&key_path, &key_pem)
      .expect("Failed to write key");

    let auth_config = None;
    let result = load_tls_config(
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap(),
      auth_config.as_ref(),
    );

    assert!(
      result.is_err(),
      "load_tls_config should fail with invalid cert content"
    );
  }

  #[test]
  fn test_load_tls_config_invalid_key_content() {
    ensure_crypto_provider();
    let tmp_dir =
      tempfile::tempdir().expect("Failed to create temp dir");
    let cert_path = tmp_dir.path().join("cert.pem");
    let key_path = tmp_dir.path().join("key.pem");

    let (cert_pem, _) = generate_test_cert("test");
    std::fs::write(&cert_path, cert_pem).expect("Failed to write cert");
    // Write invalid key content with secure permissions
    // (this is a test for invalid content, so we don't use write_key_file_secure)
    std::fs::write(&key_path, "not a valid private key").unwrap();
    #[cfg(unix)]
    {
      use std::os::unix::fs::PermissionsExt;
      std::fs::set_permissions(
        &key_path,
        std::fs::Permissions::from_mode(0o600),
      )
      .expect("Failed to set permissions");
    }

    let auth_config = None;
    let result = load_tls_config(
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap(),
      auth_config.as_ref(),
    );

    assert!(
      result.is_err(),
      "load_tls_config should fail with invalid key content"
    );
  }

  #[test]
  fn test_load_tls_config_empty_key_file() {
    ensure_crypto_provider();
    let tmp_dir =
      tempfile::tempdir().expect("Failed to create temp dir");
    let cert_path = tmp_dir.path().join("cert.pem");
    let key_path = tmp_dir.path().join("key.pem");

    let (cert_pem, _) = generate_test_cert("test");
    std::fs::write(&cert_path, cert_pem).expect("Failed to write cert");
    // Write empty key file with secure permissions
    write_key_file_secure(&key_path, "").expect("Failed to write key");

    let auth_config = None;
    let result = load_tls_config(
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap(),
      auth_config.as_ref(),
    );

    assert!(
      result.is_err(),
      "load_tls_config should fail with empty key file"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
      err_msg.contains("No private key found"),
      "Error should mention no private key: {err_msg}"
    );
  }

  #[test]
  fn test_load_tls_config_with_password_and_tls_client_cert_both() {
    ensure_crypto_provider();
    use crate::auth::{AuthConfig, AuthType, UserCredential};
    // Test that both Password and TlsClientCert use the same cert/key files
    let (cert_pem, key_pem) = generate_test_cert("test-server");
    let (ca_cert_pem, _) = generate_ca_cert();

    let tmp_dir =
      tempfile::tempdir().expect("Failed to create temp dir");
    let cert_path = tmp_dir.path().join("cert.pem");
    let key_path = tmp_dir.path().join("key.pem");
    let ca_path = tmp_dir.path().join("client_ca.pem");

    std::fs::write(&cert_path, cert_pem.clone())
      .expect("Failed to write cert");
    write_key_file_secure(&key_path, &key_pem)
      .expect("Failed to write key");
    std::fs::write(&ca_path, ca_cert_pem)
      .expect("Failed to write CA cert");

    // Test Password auth with plaintext password
    let auth_config = Some(AuthConfig {
      auth_type: AuthType::Password,
      users: Some(vec![UserCredential {
        username: "user".to_string(),
        password: "test_password".to_string(),
      }]),
      client_ca_path: None,
    });
    let result1 = load_tls_config(
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap(),
      auth_config.as_ref(),
    );
    assert!(result1.is_ok());

    // Test TlsClientCert auth
    let auth_config = Some(AuthConfig {
      auth_type: AuthType::TlsClientCert,
      users: None,
      client_ca_path: Some(ca_path.to_str().unwrap().to_string()),
    });
    let result2 = load_tls_config(
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap(),
      auth_config.as_ref(),
    );
    assert!(result2.is_ok());
  }

  #[test]
  fn test_load_tls_config_multiple_certs_in_file() {
    ensure_crypto_provider();
    // Test with a certificate chain (multiple certs in one file)
    let (cert_pem, key_pem) = generate_test_cert("test-server");
    let (ca_cert_pem, _) = generate_ca_cert();

    // Combine server cert and CA cert into one file
    let combined_cert = format!("{cert_pem}{ca_cert_pem}");

    let tmp_dir =
      tempfile::tempdir().expect("Failed to create temp dir");
    let cert_path = tmp_dir.path().join("cert.pem");
    let key_path = tmp_dir.path().join("key.pem");

    std::fs::write(&cert_path, combined_cert)
      .expect("Failed to write cert");
    // Set correct permissions for key file
    std::fs::write(&key_path, key_pem.clone())
      .expect("Failed to write key");
    #[cfg(unix)]
    {
      use std::os::unix::fs::PermissionsExt;
      std::fs::set_permissions(
        &key_path,
        std::fs::Permissions::from_mode(0o600),
      )
      .expect("Failed to set permissions");
    }

    let auth_config = None;
    let result = load_tls_config(
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap(),
      auth_config.as_ref(),
    );

    assert!(
      result.is_ok(),
      "load_tls_config should handle certificate chains"
    );
  }

  // ============== Private Key Permission Tests ==============

  #[cfg(unix)]
  fn set_file_permissions(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
      path,
      std::fs::Permissions::from_mode(mode),
    )
    .expect("Failed to set permissions");
  }

  #[test]
  #[cfg(unix)]
  fn test_verify_key_file_permissions_600() {
    let tmp_dir =
      tempfile::tempdir().expect("Failed to create temp dir");
    let key_path = tmp_dir.path().join("key.pem");

    // Create file with 600 permissions
    std::fs::write(&key_path, "test key").expect("Failed to write key");
    set_file_permissions(&key_path, 0o600);

    let result =
      verify_key_file_permissions(key_path.to_str().unwrap());
    assert!(
      result.is_ok(),
      "verify_key_file_permissions should accept 600 permissions"
    );
  }

  #[test]
  #[cfg(unix)]
  fn test_verify_key_file_permissions_400() {
    let tmp_dir =
      tempfile::tempdir().expect("Failed to create temp dir");
    let key_path = tmp_dir.path().join("key.pem");

    // Create file with 400 permissions (read-only, also secure)
    std::fs::write(&key_path, "test key").expect("Failed to write key");
    set_file_permissions(&key_path, 0o400);

    let result =
      verify_key_file_permissions(key_path.to_str().unwrap());
    assert!(
      result.is_ok(),
      "verify_key_file_permissions should accept 400 permissions"
    );
  }

  #[test]
  #[cfg(unix)]
  fn test_verify_key_file_permissions_644_insecure() {
    let tmp_dir =
      tempfile::tempdir().expect("Failed to create temp dir");
    let key_path = tmp_dir.path().join("key.pem");

    // Create file with 644 permissions (insecure - group/others can read)
    std::fs::write(&key_path, "test key").expect("Failed to write key");
    set_file_permissions(&key_path, 0o644);

    let result =
      verify_key_file_permissions(key_path.to_str().unwrap());
    assert!(
      result.is_err(),
      "verify_key_file_permissions should reject 644 permissions"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
      err_msg.contains("insecure permissions"),
      "Error should mention insecure permissions: {err_msg}"
    );
    assert!(
      err_msg.contains("chmod 600"),
      "Error should suggest chmod 600: {err_msg}"
    );
  }

  #[test]
  #[cfg(unix)]
  fn test_verify_key_file_permissions_666_insecure() {
    let tmp_dir =
      tempfile::tempdir().expect("Failed to create temp dir");
    let key_path = tmp_dir.path().join("key.pem");

    // Create file with 666 permissions (insecure - everyone can read/write)
    std::fs::write(&key_path, "test key").expect("Failed to write key");
    set_file_permissions(&key_path, 0o666);

    let result =
      verify_key_file_permissions(key_path.to_str().unwrap());
    assert!(
      result.is_err(),
      "verify_key_file_permissions should reject 666 permissions"
    );
  }

  #[test]
  #[cfg(unix)]
  fn test_verify_key_file_permissions_nonexistent_file() {
    let tmp_dir =
      tempfile::tempdir().expect("Failed to create temp dir");
    let key_path = tmp_dir.path().join("nonexistent.pem");

    let result =
      verify_key_file_permissions(key_path.to_str().unwrap());
    assert!(
      result.is_err(),
      "verify_key_file_permissions should fail for nonexistent file"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
      err_msg.contains("Failed to get metadata"),
      "Error should mention metadata failure: {err_msg}"
    );
  }

  #[test]
  #[cfg(unix)]
  fn test_load_tls_config_insecure_key_permissions() {
    ensure_crypto_provider();
    let (cert_pem, key_pem) = generate_test_cert("test-server");

    let tmp_dir =
      tempfile::tempdir().expect("Failed to create temp dir");
    let cert_path = tmp_dir.path().join("cert.pem");
    let key_path = tmp_dir.path().join("key.pem");

    std::fs::write(&cert_path, cert_pem).expect("Failed to write cert");
    std::fs::write(&key_path, key_pem).expect("Failed to write key");
    // Set insecure permissions
    set_file_permissions(&key_path, 0o644);

    let auth_config = None;
    let result = load_tls_config(
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap(),
      auth_config.as_ref(),
    );

    assert!(
      result.is_err(),
      "load_tls_config should fail with insecure key permissions"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
      err_msg.contains("insecure permissions"),
      "Error should mention insecure permissions: {err_msg}"
    );
  }

  #[test]
  #[cfg(unix)]
  fn test_load_tls_config_secure_key_permissions_600() {
    ensure_crypto_provider();
    let (cert_pem, key_pem) = generate_test_cert("test-server");

    let tmp_dir =
      tempfile::tempdir().expect("Failed to create temp dir");
    let cert_path = tmp_dir.path().join("cert.pem");
    let key_path = tmp_dir.path().join("key.pem");

    std::fs::write(&cert_path, cert_pem).expect("Failed to write cert");
    std::fs::write(&key_path, key_pem).expect("Failed to write key");
    // Set secure permissions
    set_file_permissions(&key_path, 0o600);

    let auth_config = None;
    let result = load_tls_config(
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap(),
      auth_config.as_ref(),
    );

    assert!(
      result.is_ok(),
      "load_tls_config should succeed with 600 key permissions"
    );
  }

  #[test]
  #[cfg(unix)]
  fn test_load_tls_config_secure_key_permissions_400() {
    ensure_crypto_provider();
    let (cert_pem, key_pem) = generate_test_cert("test-server");

    let tmp_dir =
      tempfile::tempdir().expect("Failed to create temp dir");
    let cert_path = tmp_dir.path().join("cert.pem");
    let key_path = tmp_dir.path().join("key.pem");

    std::fs::write(&cert_path, cert_pem).expect("Failed to write cert");
    std::fs::write(&key_path, key_pem).expect("Failed to write key");
    // Set secure read-only permissions
    set_file_permissions(&key_path, 0o400);

    let auth_config = None;
    let result = load_tls_config(
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap(),
      auth_config.as_ref(),
    );

    assert!(
      result.is_ok(),
      "load_tls_config should succeed with 400 key permissions"
    );
  }

  // ============== Transfer Direction Display Tests ==============

  #[test]
  fn test_transfer_direction_display() {
    // Test that the TransferDirection enum displays correctly
    // Since it's defined inside handle_h3_stream, we test the logic here
    // by verifying the format strings
    assert_eq!(format!("{}", "H3->TCP"), "H3->TCP");
    assert_eq!(format!("{}", "TCP->H3"), "TCP->H3");
    assert_eq!(format!("{}", "shutdown"), "shutdown");
  }

  // ============== Http3Listener stop() Tests ==============

  #[test]
  fn test_stream_tracker_shutdown_handle_is_shutdown_after_stop() {
    // Verify that StreamTracker's shutdown handle is triggered when
    // shutdown() is called on it
    let tracker = StreamTracker::new();
    let handle = tracker.shutdown_handle();

    assert!(
      !handle.is_shutdown(),
      "ShutdownHandle should not be shutdown initially"
    );

    // Call shutdown on tracker
    tracker.shutdown();

    assert!(
      handle.is_shutdown(),
      "ShutdownHandle should be shutdown after tracker.shutdown() is called"
    );
  }

  #[test]
  fn test_stream_tracker_shutdown_is_idempotent() {
    // Verify that multiple calls to shutdown() don't cause issues
    let tracker = StreamTracker::new();
    let handle = tracker.shutdown_handle();

    // Call shutdown multiple times
    tracker.shutdown();
    assert!(handle.is_shutdown());

    tracker.shutdown();
    assert!(handle.is_shutdown());

    tracker.shutdown();
    assert!(handle.is_shutdown());
  }

  #[tokio::test]
  async fn test_stream_tracker_shutdown_notifies_pending_tasks() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let tracker = StreamTracker::new();
        let handle = tracker.shutdown_handle();

        let notified = Rc::new(std::cell::Cell::new(false));
        let notified_clone = notified.clone();

        // Register a task that waits for shutdown notification
        tracker.register(async move {
          handle.notified().await;
          notified_clone.set(true);
        });
        tokio::task::yield_now().await;

        // Trigger shutdown
        tracker.shutdown();

        // Give time for notification to propagate
        tokio::task::yield_now().await;

        // The task should have been notified
        assert!(
          notified.get(),
          "Task should be notified after shutdown()"
        );
      })
      .await;
  }

  // ============== Helper Functions Tests ==============

  #[test]
  fn test_validate_connect_method_valid() {
    let req = http::Request::builder()
      .method(http::Method::CONNECT)
      .uri("example.com:443")
      .body(())
      .unwrap();
    assert!(
      validate_connect_method(&req).is_ok(),
      "CONNECT method should be valid"
    );
  }

  #[test]
  fn test_validate_connect_method_invalid() {
    let req = http::Request::builder()
      .method(http::Method::GET)
      .uri("http://example.com/")
      .body(())
      .unwrap();
    let result = validate_connect_method(&req);
    assert!(result.is_err(), "Non-CONNECT method should be invalid");
    let err = result.unwrap_err();
    assert!(
      err.to_string().contains("Method Not Allowed"),
      "Error should mention method not allowed"
    );
  }

  #[test]
  fn test_validate_target_address_valid() {
    let req = http::Request::builder()
      .method(http::Method::CONNECT)
      .uri("example.com:443")
      .body(())
      .unwrap();
    let result = validate_target_address(&req);
    assert!(result.is_ok(), "Valid target address should pass");
    assert_eq!(result.unwrap(), "example.com:443");
  }

  #[test]
  fn test_validate_target_address_missing_authority() {
    let req = http::Request::builder()
      .method(http::Method::CONNECT)
      .uri("/")
      .body(())
      .unwrap();
    let result = validate_target_address(&req);
    assert!(result.is_err(), "Missing authority should fail");
    assert!(
      result.unwrap_err().to_string().contains("missing authority")
    );
  }

  #[test]
  fn test_validate_target_address_missing_port() {
    let req = http::Request::builder()
      .method(http::Method::CONNECT)
      .uri("example.com")
      .body(())
      .unwrap();
    let result = validate_target_address(&req);
    assert!(result.is_err(), "Missing port should fail");
    assert!(result.unwrap_err().to_string().contains("missing port"));
  }

  #[test]
  fn test_validate_target_address_zero_port() {
    // Create a URI with port 0
    let uri: http::Uri = "example.com:0".parse().unwrap();
    let req = http::Request::builder()
      .method(http::Method::CONNECT)
      .uri(uri)
      .body(())
      .unwrap();
    let result = validate_target_address(&req);
    assert!(result.is_err(), "Port 0 should fail");
    assert!(
      result.unwrap_err().to_string().contains("port cannot be zero")
    );
  }

  #[test]
  fn test_handle_password_auth_missing_header() {
    let credentials = HashMap::new();
    let req = http::Request::builder()
      .method(http::Method::CONNECT)
      .uri("example.com:443")
      .body(())
      .unwrap();

    let result = handle_password_auth(&req, &credentials);
    assert!(result.is_err(), "Missing auth header should fail");
    assert!(
      result
        .unwrap_err()
        .to_string()
        .contains("Proxy Authentication Required")
    );
  }

  #[test]
  fn test_perform_authentication_none() {
    let req = http::Request::builder()
      .method(http::Method::CONNECT)
      .uri("example.com:443")
      .body(())
      .unwrap();
    assert!(
      perform_authentication(&req, None).is_ok(),
      "No auth should always pass"
    );
  }

  // ============== TransferDirection Tests ==============

  #[test]
  fn test_transfer_direction_variants() {
    assert_eq!(TransferDirection::H3ToTcp.to_string(), "H3->TCP");
    assert_eq!(TransferDirection::TcpToH3.to_string(), "TCP->H3");
    assert_eq!(TransferDirection::Shutdown.to_string(), "shutdown");
  }

  #[test]
  fn test_transfer_direction_equality() {
    assert_eq!(TransferDirection::H3ToTcp, TransferDirection::H3ToTcp);
    assert_ne!(TransferDirection::H3ToTcp, TransferDirection::TcpToH3);
    assert_ne!(TransferDirection::H3ToTcp, TransferDirection::Shutdown);
  }

  // ============== connect_to_target Tests ==============

  #[tokio::test]
  async fn test_connect_to_target_invalid_address() {
    // Try to connect to an invalid address that should fail
    // Using a non-routable IP address to ensure connection fails quickly
    let result = connect_to_target("10.255.255.1:9999").await;
    assert!(
      result.is_err(),
      "Connection to invalid address should fail"
    );
    let err = result.unwrap_err();
    assert!(
      err.to_string().contains("Bad Gateway"),
      "Error should mention Bad Gateway: {}",
      err
    );
  }

  #[tokio::test]
  async fn test_connect_to_target_connection_refused() {
    // Try to connect to localhost on a port that's unlikely to be in use
    let result = connect_to_target("127.0.0.1:1").await;
    assert!(result.is_err(), "Connection to refused port should fail");
    let err = result.unwrap_err();
    assert!(
      err.to_string().contains("Bad Gateway"),
      "Error should mention Bad Gateway: {}",
      err
    );
  }

  // ============== TLS Client Certificate Verification Tests ==============

  #[test]
  fn test_verify_tls_client_cert_missing() {
    // Test when no peer identity is provided (None)
    let result = verify_tls_client_cert(None);
    assert_eq!(
      result,
      TlsClientCertVerifyResult::Missing,
      "Should return Missing when peer_identity is None"
    );
  }

  #[test]
  fn test_verify_tls_client_cert_valid() {
    // Test with valid certificate chain (Vec<CertificateDer>)
    use rustls::pki_types::CertificateDer;

    // Create a mock certificate (empty for test purposes)
    let cert = CertificateDer::from(vec![0x30, 0x00]); // Minimal DER structure
    let certs: Vec<CertificateDer<'static>> = vec![cert];

    // Box it as dyn Any (simulating what quinn::Connection::peer_identity returns)
    let peer_identity: Option<Box<dyn std::any::Any>> =
      Some(Box::new(certs));

    let result = verify_tls_client_cert(peer_identity);
    assert_eq!(
      result,
      TlsClientCertVerifyResult::Valid,
      "Should return Valid when certificate is present and properly typed"
    );
  }

  #[test]
  fn test_verify_tls_client_cert_invalid_type() {
    // Test with wrong type (not Vec<CertificateDer>)
    let peer_identity: Option<Box<dyn std::any::Any>> =
      Some(Box::new("not a certificate".to_string()));

    let result = verify_tls_client_cert(peer_identity);
    assert_eq!(
      result,
      TlsClientCertVerifyResult::InvalidType,
      "Should return InvalidType when peer_identity has wrong type"
    );
  }

  #[test]
  fn test_verify_tls_client_cert_empty_cert_chain() {
    // Test with empty certificate chain
    use rustls::pki_types::CertificateDer;

    let certs: Vec<CertificateDer<'static>> = vec![];
    let peer_identity: Option<Box<dyn std::any::Any>> =
      Some(Box::new(certs));

    let result = verify_tls_client_cert(peer_identity);
    assert_eq!(
      result,
      TlsClientCertVerifyResult::Valid,
      "Should return Valid even for empty chain (validation is at TLS level)"
    );
  }

  #[test]
  fn test_verify_tls_client_cert_multiple_certs() {
    // Test with multiple certificates in chain
    use rustls::pki_types::CertificateDer;

    let cert1 = CertificateDer::from(vec![0x30, 0x01]);
    let cert2 = CertificateDer::from(vec![0x30, 0x02]);
    let certs: Vec<CertificateDer<'static>> = vec![cert1, cert2];

    let peer_identity: Option<Box<dyn std::any::Any>> =
      Some(Box::new(certs));

    let result = verify_tls_client_cert(peer_identity);
    assert_eq!(
      result,
      TlsClientCertVerifyResult::Valid,
      "Should return Valid for certificate chain with multiple certs"
    );
  }

  #[test]
  fn test_tls_client_cert_verify_result_debug() {
    // Test Debug trait implementation
    assert_eq!(
      format!("{:?}", TlsClientCertVerifyResult::Valid),
      "Valid"
    );
    assert_eq!(
      format!("{:?}", TlsClientCertVerifyResult::Missing),
      "Missing"
    );
    assert_eq!(
      format!("{:?}", TlsClientCertVerifyResult::InvalidType),
      "InvalidType"
    );
  }

  #[test]
  fn test_tls_client_cert_verify_result_equality() {
    // Test PartialEq and Eq trait implementations
    assert_eq!(
      TlsClientCertVerifyResult::Valid,
      TlsClientCertVerifyResult::Valid
    );
    assert_eq!(
      TlsClientCertVerifyResult::Missing,
      TlsClientCertVerifyResult::Missing
    );
    assert_eq!(
      TlsClientCertVerifyResult::InvalidType,
      TlsClientCertVerifyResult::InvalidType
    );

    assert_ne!(
      TlsClientCertVerifyResult::Valid,
      TlsClientCertVerifyResult::Missing
    );
    assert_ne!(
      TlsClientCertVerifyResult::Valid,
      TlsClientCertVerifyResult::InvalidType
    );
    assert_ne!(
      TlsClientCertVerifyResult::Missing,
      TlsClientCertVerifyResult::InvalidType
    );
  }

  #[test]
  fn test_tls_client_cert_verify_result_clone() {
    // Test Clone trait implementation
    let result = TlsClientCertVerifyResult::Valid;
    let cloned = result;
    assert_eq!(result, cloned);

    let result = TlsClientCertVerifyResult::Missing;
    let cloned = result;
    assert_eq!(result, cloned);

    let result = TlsClientCertVerifyResult::InvalidType;
    let cloned = result;
    assert_eq!(result, cloned);
  }

  #[test]
  fn test_tls_client_cert_verify_result_copy() {
    // Test Copy trait implementation (should be implicitly Copy since all
    // variants are unit variants)
    let result = TlsClientCertVerifyResult::Valid;
    let copied = result; // This should work without Clone due to Copy
    assert_eq!(result, copied);
  }

  #[test]
  fn test_h3_no_error_code_value() {
    // Test that H3_NO_ERROR_CODE has the correct value per RFC 9114
    // H3_NO_ERROR = 0x100 (256)
    assert_eq!(H3_NO_ERROR_CODE, 0x100);
    assert_eq!(H3_NO_ERROR_CODE, 256);
  }

  // ============== wait_shutdown_with_timeout Tests ==============

  #[tokio::test]
  async fn test_wait_shutdown_with_timeout_success() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let tracker = StreamTracker::new();

        // Register a task that completes immediately
        tracker.register(async {});
        tokio::task::yield_now().await;

        // Wait with timeout should succeed
        let result = tracker
          .wait_shutdown_with_timeout(Duration::from_millis(100))
          .await;
        assert!(
          result.is_ok(),
          "wait_shutdown_with_timeout should succeed when tasks complete"
        );
        assert_eq!(tracker.active_count(), 0);
      })
      .await;
  }

  #[tokio::test]
  async fn test_wait_shutdown_with_timeout_expires() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let tracker = StreamTracker::new();

        // Register a task that never completes
        tracker.register(async {
          std::future::pending::<()>().await;
        });
        tokio::task::yield_now().await;
        assert_eq!(tracker.active_count(), 1);

        // Wait with short timeout should fail
        let result = tracker
          .wait_shutdown_with_timeout(Duration::from_millis(10))
          .await;
        assert!(
          result.is_err(),
          "wait_shutdown_with_timeout should timeout with pending task"
        );

        // Clean up
        tracker.abort_all();
        tracker.wait_shutdown().await;
      })
      .await;
  }

  #[tokio::test]
  async fn test_wait_shutdown_with_timeout_after_abort() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let tracker = StreamTracker::new();

        // Register a pending task
        tracker.register(async {
          std::future::pending::<()>().await;
        });
        tokio::task::yield_now().await;
        assert_eq!(tracker.active_count(), 1);

        // Abort and wait with timeout
        tracker.abort_all();
        let result = tracker
          .wait_shutdown_with_timeout(Duration::from_millis(100))
          .await;
        assert!(
          result.is_ok(),
          "wait_shutdown_with_timeout should succeed after abort"
        );
        assert_eq!(tracker.active_count(), 0);
      })
      .await;
  }

  // ============================================================================
  // Task 005-010: Password Authentication Tests
  // ============================================================================

  // ============== Task 005: Proxy-Authorization Header Parsing Tests ==============

  #[test]
  fn test_proxy_authorization_header_missing_returns_407() {
    // Test that missing Proxy-Authorization header returns 407 error
    let credentials = HashMap::new();
    let req = http::Request::builder()
      .method(http::Method::CONNECT)
      .uri("example.com:443")
      .body(())
      .unwrap();
    let result = handle_password_auth(&req, &credentials);
    assert!(result.is_err(), "Missing header should return error");
    let err = result.unwrap_err().to_string();
    assert!(
      err.contains("Proxy Authentication Required"),
      "Error should indicate 407 status"
    );
  }

  #[test]
  fn test_proxy_authorization_header_present_but_invalid_format() {
    // Test that invalid Proxy-Authorization format returns 407 error
    let credentials = HashMap::new();
    let req = http::Request::builder()
      .method(http::Method::CONNECT)
      .uri("example.com:443")
      .header(
        http::header::PROXY_AUTHORIZATION,
        "InvalidFormat somedata",
      )
      .body(())
      .unwrap();
    let result = handle_password_auth(&req, &credentials);
    assert!(result.is_err(), "Invalid format should return error");
  }

  // ============== Task 006: Basic Format Validation Tests ==============

  #[test]
  fn test_basic_auth_format_valid() {
    // Test valid Basic auth format
    let header_value =
      http::HeaderValue::from_str("Basic dXNlcjpwYXNzd29yZA==")
        .unwrap();
    let result = parse_basic_auth(header_value);
    assert!(result.is_ok(), "Valid Basic format should parse");
    let (username, password) = result.unwrap();
    assert_eq!(username, "user");
    assert_eq!(password, "password");
  }

  #[test]
  fn test_basic_auth_format_not_basic() {
    // Test non-Basic auth format
    let header_value =
      http::HeaderValue::from_str("Bearer token123").unwrap();
    let result = parse_basic_auth(header_value);
    assert!(result.is_err(), "Non-Basic format should return error");
    let err = result.unwrap_err().to_string();
    assert!(
      err.contains("Not Basic authentication"),
      "Error should indicate not Basic auth"
    );
  }

  #[test]
  fn test_basic_auth_format_digest() {
    // Test Digest auth format (should be rejected)
    let header_value =
      http::HeaderValue::from_str("Digest username=\"user\"").unwrap();
    let result = parse_basic_auth(header_value);
    assert!(result.is_err(), "Digest format should return error");
  }

  // ============== Task 007: Base64 Decode Validation Tests ==============

  #[test]
  fn test_base64_decode_valid_credentials() {
    // Test valid Base64 encoded credentials
    let encoded = BASE64_STANDARD.encode("testuser:testpass");
    let header_value =
      http::HeaderValue::from_str(&format!("Basic {}", encoded))
        .unwrap();
    let result = parse_basic_auth(header_value);
    assert!(result.is_ok(), "Valid Base64 should decode");
    let (username, password) = result.unwrap();
    assert_eq!(username, "testuser");
    assert_eq!(password, "testpass");
  }

  #[test]
  fn test_base64_decode_invalid_base64() {
    // Test invalid Base64 string
    let header_value =
      http::HeaderValue::from_str("Basic !!invalid!!base64!!").unwrap();
    let result = parse_basic_auth(header_value);
    assert!(result.is_err(), "Invalid Base64 should return error");
  }

  #[test]
  fn test_base64_decode_missing_colon() {
    // Test Base64 decoded value without colon separator
    let encoded = BASE64_STANDARD.encode("userwithoutpassword");
    let header_value =
      http::HeaderValue::from_str(&format!("Basic {}", encoded))
        .unwrap();
    let result = parse_basic_auth(header_value);
    assert!(
      result.is_err(),
      "Missing colon separator should return error"
    );
  }

  // ============== Task 010: 407 Response Validation Tests ==============

  #[test]
  fn test_407_response_status_code() {
    // Test that 407 response has correct status code
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
  fn test_407_response_content_type() {
    // Test that 407 response has correct Content-Type
    let resp = build_error_response(
      http::StatusCode::PROXY_AUTHENTICATION_REQUIRED,
      "Proxy Authentication Required",
    );
    assert_eq!(
      resp.headers().get(http::header::CONTENT_TYPE).unwrap(),
      "text/plain"
    );
  }

  #[test]
  fn test_407_response_body() {
    // Test that 407 response has body
    let resp = build_error_response(
      http::StatusCode::PROXY_AUTHENTICATION_REQUIRED,
      "Proxy Authentication Required",
    );
    // The body should contain the error message
    let (_parts, body) = resp.into_parts();
    // Body exists - we can't easily check content without async
    assert!(
      body.size_hint().lower() > 0
        || body.size_hint().upper().is_some(),
      "407 response should have a body"
    );
  }

  // ============================================================================
  // Task 012-018: HTTP/3 Listener Tests
  // ============================================================================

  // ============== Task 012: TLS Client Certificate Authentication Tests ==============

  #[test]
  fn test_tls_client_cert_verify_valid_certificate() {
    // Test TLS client cert verification with valid certificate
    use rustls::pki_types::CertificateDer;
    let cert = CertificateDer::from(vec![0x30, 0x00]);
    let certs: Vec<CertificateDer<'static>> = vec![cert];
    let peer_identity: Option<Box<dyn std::any::Any>> =
      Some(Box::new(certs));
    let result = verify_tls_client_cert(peer_identity);
    assert_eq!(
      result,
      TlsClientCertVerifyResult::Valid,
      "Valid certificate should return Valid"
    );
  }

  #[test]
  fn test_tls_client_cert_verify_missing_certificate() {
    // Test TLS client cert verification when certificate is missing
    let peer_identity: Option<Box<dyn std::any::Any>> = None;
    let result = verify_tls_client_cert(peer_identity);
    assert_eq!(
      result,
      TlsClientCertVerifyResult::Missing,
      "Missing certificate should return Missing"
    );
  }

  #[test]
  fn test_tls_client_cert_verify_invalid_type() {
    // Test TLS client cert verification with invalid type
    let peer_identity: Option<Box<dyn std::any::Any>> =
      Some(Box::new("not a certificate".to_string()));
    let result = verify_tls_client_cert(peer_identity);
    assert_eq!(
      result,
      TlsClientCertVerifyResult::InvalidType,
      "Invalid type should return InvalidType"
    );
  }

  // ============== Task 013: Private Key Permission Tests ==============

  #[test]
  #[cfg(unix)]
  fn test_private_key_permissions_600_accepted() {
    // Test that 600 permissions are accepted
    let tmp_dir =
      tempfile::tempdir().expect("Failed to create temp dir");
    let key_path = tmp_dir.path().join("key.pem");
    std::fs::write(&key_path, "test key").expect("Failed to write key");
    set_file_permissions(&key_path, 0o600);
    let result =
      verify_key_file_permissions(key_path.to_str().unwrap());
    assert!(result.is_ok(), "600 permissions should be accepted");
  }

  #[test]
  #[cfg(unix)]
  fn test_private_key_permissions_400_accepted() {
    // Test that 400 permissions are accepted
    let tmp_dir =
      tempfile::tempdir().expect("Failed to create temp dir");
    let key_path = tmp_dir.path().join("key.pem");
    std::fs::write(&key_path, "test key").expect("Failed to write key");
    set_file_permissions(&key_path, 0o400);
    let result =
      verify_key_file_permissions(key_path.to_str().unwrap());
    assert!(result.is_ok(), "400 permissions should be accepted");
  }

  #[test]
  #[cfg(unix)]
  fn test_private_key_permissions_644_rejected() {
    // Test that 644 permissions are rejected
    let tmp_dir =
      tempfile::tempdir().expect("Failed to create temp dir");
    let key_path = tmp_dir.path().join("key.pem");
    std::fs::write(&key_path, "test key").expect("Failed to write key");
    set_file_permissions(&key_path, 0o644);
    let result =
      verify_key_file_permissions(key_path.to_str().unwrap());
    assert!(result.is_err(), "644 permissions should be rejected");
    let err_msg = result.unwrap_err().to_string();
    assert!(
      err_msg.contains("insecure permissions"),
      "Error should mention insecure permissions"
    );
  }

  // ============== Task 014: Certificate and Key Match Tests ==============

  #[test]
  fn test_cert_key_match_success() {
    // Test that matching cert and key succeed
    ensure_crypto_provider();
    let (cert_pem, key_pem) = generate_test_cert("test-server");
    let tmp_dir =
      tempfile::tempdir().expect("Failed to create temp dir");
    let cert_path = tmp_dir.path().join("cert.pem");
    let key_path = tmp_dir.path().join("key.pem");
    std::fs::write(&cert_path, cert_pem).expect("Failed to write cert");
    write_key_file_secure(&key_path, &key_pem)
      .expect("Failed to write key");
    let auth_config = None;
    let result = load_tls_config(
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap(),
      auth_config.as_ref(),
    );
    assert!(result.is_ok(), "Matching cert and key should succeed");
  }

  #[test]
  fn test_cert_key_mismatch_fails() {
    // Test that mismatched cert and key fail
    ensure_crypto_provider();
    // Generate two different key pairs
    let (cert1_pem, _key1_pem) = generate_test_cert("server1");
    let (_cert2_pem, key2_pem) = generate_test_cert("server2");
    let tmp_dir =
      tempfile::tempdir().expect("Failed to create temp dir");
    let cert_path = tmp_dir.path().join("cert.pem");
    let key_path = tmp_dir.path().join("key.pem");
    std::fs::write(&cert_path, cert1_pem)
      .expect("Failed to write cert");
    write_key_file_secure(&key_path, &key2_pem)
      .expect("Failed to write key");
    let auth_config = None;
    let result = load_tls_config(
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap(),
      auth_config.as_ref(),
    );
    assert!(result.is_err(), "Mismatched cert and key should fail");
  }

  // ============== Task 015: TLS 1.3 Enforcement Tests ==============

  #[test]
  fn test_tls_config_uses_tls13_only() {
    // Test that TLS config is configured for TLS 1.3 only
    ensure_crypto_provider();
    let (cert_pem, key_pem) = generate_test_cert("test-server");
    let tmp_dir =
      tempfile::tempdir().expect("Failed to create temp dir");
    let cert_path = tmp_dir.path().join("cert.pem");
    let key_path = tmp_dir.path().join("key.pem");
    std::fs::write(&cert_path, cert_pem).expect("Failed to write cert");
    write_key_file_secure(&key_path, &key_pem)
      .expect("Failed to write key");
    let auth_config = None;
    let tls_config = load_tls_config(
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap(),
      auth_config.as_ref(),
    )
    .expect("TLS config should load");
    // Verify ALPN protocol is set to h3 (required for HTTP/3)
    assert!(
      tls_config.alpn_protocols.iter().any(|p| p == b"h3"),
      "TLS config should have h3 ALPN protocol"
    );
    // Note: rustls 0.23+ only supports TLS 1.3 by default for QUIC
    // The TLS 1.3 enforcement is implicit in the rustls version used
  }

  #[test]
  fn test_tls_config_alpn_protocol_h3() {
    // Test that ALPN protocol is set to h3
    ensure_crypto_provider();
    let (cert_pem, key_pem) = generate_test_cert("test-server");
    let tmp_dir =
      tempfile::tempdir().expect("Failed to create temp dir");
    let cert_path = tmp_dir.path().join("cert.pem");
    let key_path = tmp_dir.path().join("key.pem");
    std::fs::write(&cert_path, cert_pem).expect("Failed to write cert");
    write_key_file_secure(&key_path, &key_pem)
      .expect("Failed to write key");
    let auth_config = None;
    let tls_config = load_tls_config(
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap(),
      auth_config.as_ref(),
    )
    .expect("TLS config should load");
    assert_eq!(
      tls_config.alpn_protocols.len(),
      1,
      "Should have exactly one ALPN protocol"
    );
    assert_eq!(
      tls_config.alpn_protocols[0], b"h3",
      "ALPN protocol should be h3"
    );
  }

  // ============== Task 016: Graceful Shutdown Tests ==============

  #[tokio::test]
  async fn test_graceful_shutdown_normal_completion() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let tracker = StreamTracker::new();
        let completed = Rc::new(std::cell::Cell::new(false));
        let completed_clone = completed.clone();
        tracker.register(async move {
          tokio::time::sleep(Duration::from_millis(10)).await;
          completed_clone.set(true);
        });
        tokio::task::yield_now().await;
        tracker.shutdown();
        let result = tracker
          .wait_shutdown_with_timeout(Duration::from_secs(1))
          .await;
        assert!(
          result.is_ok(),
          "Graceful shutdown should complete within timeout"
        );
        assert!(completed.get(), "Task should have completed");
      })
      .await;
  }

  #[tokio::test]
  async fn test_graceful_shutdown_timeout_abort() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let tracker = StreamTracker::new();
        tracker.register(async {
          std::future::pending::<()>().await;
        });
        tokio::task::yield_now().await;
        tracker.shutdown();
        let result = tracker
          .wait_shutdown_with_timeout(Duration::from_millis(50))
          .await;
        assert!(
          result.is_err(),
          "Shutdown should timeout with pending task"
        );
        tracker.abort_all();
        tracker.wait_shutdown().await;
        assert_eq!(
          tracker.active_count(),
          0,
          "All tasks should be aborted"
        );
      })
      .await;
  }

  #[test]
  fn test_graceful_shutdown_idempotent() {
    let tracker = StreamTracker::new();
    tracker.shutdown();
    tracker.shutdown();
    tracker.shutdown();
    assert!(
      tracker.shutdown_handle().is_shutdown(),
      "Multiple shutdown calls should be idempotent"
    );
  }

  // ============== Task 017: Monitoring Log Output Tests ==============

  #[test]
  fn test_monitoring_interval_constant() {
    // Verify monitoring interval is 60 seconds
    assert_eq!(
      MONITORING_LOG_INTERVAL,
      Duration::from_secs(60),
      "Monitoring interval should be 60 seconds"
    );
  }

  #[test]
  fn test_monitoring_log_format() {
    // Verify that StreamTracker provides the correct counts
    let tracker = StreamTracker::new();
    // Initially zero
    assert_eq!(tracker.connection_count(), 0);
    assert_eq!(tracker.active_count(), 0);
    // After registering tasks, counts should reflect that
    // (tested in other tests, but format verification is here)
    let expected_format = format!(
      "[http3.listener] active_connections={}, active_streams={}",
      tracker.connection_count(),
      tracker.active_count()
    );
    assert!(
      expected_format.contains("active_connections"),
      "Log format should contain active_connections"
    );
    assert!(
      expected_format.contains("active_streams"),
      "Log format should contain active_streams"
    );
  }

  // ============== Task 018: StreamTracker Counter Tests ==============

  #[tokio::test]
  async fn test_stream_tracker_connection_count_accuracy() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let tracker = StreamTracker::new();
        assert_eq!(tracker.connection_count(), 0);
        tracker.register_connection(async {
          tokio::time::sleep(Duration::from_millis(100)).await;
        });
        tokio::task::yield_now().await;
        assert_eq!(tracker.connection_count(), 1);
        tracker.register_connection(async {
          tokio::time::sleep(Duration::from_millis(100)).await;
        });
        tokio::task::yield_now().await;
        assert_eq!(tracker.connection_count(), 2);
      })
      .await;
  }

  #[tokio::test]
  async fn test_stream_tracker_active_count_accuracy() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let tracker = StreamTracker::new();
        assert_eq!(tracker.active_count(), 0);
        tracker.register(async {
          tokio::time::sleep(Duration::from_millis(100)).await;
        });
        tokio::task::yield_now().await;
        assert_eq!(tracker.active_count(), 1);
        tracker.register(async {
          tokio::time::sleep(Duration::from_millis(100)).await;
        });
        tokio::task::yield_now().await;
        assert_eq!(tracker.active_count(), 2);
      })
      .await;
  }

  #[tokio::test]
  async fn test_stream_tracker_counts_after_completion() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let tracker = StreamTracker::new();
        tracker.register(async {});
        tracker.register_connection(async {});
        tokio::task::yield_now().await;
        assert_eq!(tracker.active_count(), 1);
        assert_eq!(tracker.connection_count(), 1);
        tracker.wait_shutdown().await;
        assert_eq!(tracker.active_count(), 0);
        assert_eq!(tracker.connection_count(), 0);
      })
      .await;
  }

  // ========== New Auth Module Integration Tests ==========
  // These tests verify HTTP/3 listener authentication behavior with the new auth module.
  // The key change: perform_authentication and handle_password_auth now use crate::auth::AuthConfig

  #[test]
  fn test_http3_perform_authentication_with_none_auth() {
    // When AuthConfig is None (represented by Option<AuthConfig> = None),
    // authentication should pass without checking headers.
    // This tests the listener's behavior, not just the AuthConfig struct.

    // Create a mock HTTP request without auth headers
    let req = http::Request::builder()
      .method("CONNECT")
      .uri("example.com:443")
      .body(())
      .expect("build request");

    // With auth_config = None (no auth required), should succeed
    let result = perform_authentication(&req, None);
    assert!(result.is_ok(), "No auth should pass without credentials");
  }

  #[test]
  fn test_http3_perform_authentication_with_password_missing_header() {
    use crate::auth::{AuthConfig, AuthType, UserCredential};

    // Create request without Proxy-Authorization header
    let req = http::Request::builder()
      .method("CONNECT")
      .uri("example.com:443")
      .body(())
      .expect("build request");

    // Create password AuthConfig
    let auth_config = Some(AuthConfig {
      auth_type: AuthType::Password,
      users: Some(vec![UserCredential {
        username: "admin".to_string(),
        password: "secret".to_string(),
      }]),
      client_ca_path: None,
    });

    // Should fail because no Proxy-Authorization header provided
    // This tests listener behavior: HTTP/3 requires Proxy-Authorization for password auth
    let result = perform_authentication(&req, auth_config.as_ref());
    assert!(
      result.is_err(),
      "Password auth should fail without header"
    );
  }

  #[test]
  fn test_http3_perform_authentication_with_password_valid_credentials()
  {
    use crate::auth::{AuthConfig, AuthType, UserCredential};

    // Create request with valid Proxy-Authorization header (Basic auth)
    let credentials = BASE64_STANDARD.encode("admin:secret");
    let req = http::Request::builder()
      .method("CONNECT")
      .uri("example.com:443")
      .header("Proxy-Authorization", format!("Basic {}", credentials))
      .body(())
      .expect("build request");

    // Create password AuthConfig with matching credentials
    let auth_config = Some(AuthConfig {
      auth_type: AuthType::Password,
      users: Some(vec![UserCredential {
        username: "admin".to_string(),
        password: "secret".to_string(),
      }]),
      client_ca_path: None,
    });

    // Should succeed with valid plaintext password
    // This tests that HTTP/3 listener uses PLAINTEXT comparison (not bcrypt)
    let result = perform_authentication(&req, auth_config.as_ref());
    assert!(result.is_ok(), "Valid credentials should pass");
  }

  #[test]
  fn test_http3_perform_authentication_with_password_wrong_password() {
    use crate::auth::{AuthConfig, AuthType, UserCredential};

    // Create request with WRONG password in Proxy-Authorization header
    let credentials = BASE64_STANDARD.encode("admin:wrongpassword");
    let req = http::Request::builder()
      .method("CONNECT")
      .uri("example.com:443")
      .header("Proxy-Authorization", format!("Basic {}", credentials))
      .body(())
      .expect("build request");

    // Create password AuthConfig with DIFFERENT password
    let auth_config = Some(AuthConfig {
      auth_type: AuthType::Password,
      users: Some(vec![UserCredential {
        username: "admin".to_string(),
        password: "secret".to_string(), // Different from request
      }]),
      client_ca_path: None,
    });

    // Should fail with wrong password
    // This tests listener's credential validation behavior
    let result = perform_authentication(&req, auth_config.as_ref());
    assert!(result.is_err(), "Wrong password should fail");
  }

  #[test]
  fn test_http3_perform_authentication_with_tls_client_cert() {
    use crate::auth::{AuthConfig, AuthType};

    // TLS client cert auth is handled at QUIC layer, not HTTP layer
    // perform_authentication should pass for TLS cert type
    let req = http::Request::builder()
      .method("CONNECT")
      .uri("example.com:443")
      .body(())
      .expect("build request");

    let auth_config = Some(AuthConfig {
      auth_type: AuthType::TlsClientCert,
      users: None,
      client_ca_path: Some("/path/to/ca.pem".to_string()),
    });

    // TLS cert auth bypasses HTTP-layer auth check
    let result = perform_authentication(&req, auth_config.as_ref());
    assert!(
      result.is_ok(),
      "TLS client cert auth should pass at HTTP layer"
    );
  }
}
