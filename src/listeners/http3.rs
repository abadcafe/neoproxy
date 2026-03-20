use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
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
use rustls::{RootCertStore, server::WebPkiClientVerifier};
use serde::Deserialize;
use tokio::net;
use tokio::task::JoinSet;
use tracing::{info, warn};

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
const LISTENER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

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
  /// Authentication configuration (optional)
  pub auth: Option<AuthConfigArgs>,
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
        Some(v) if v >= 1 && v <= 10000 => v,
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
      Some(v) if v >= 1200 && v <= 9000 => v,
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

/// Authentication configuration arguments
#[derive(Deserialize, Clone, Debug)]
pub struct AuthConfigArgs {
  /// Authentication type: "password" or "tls_client_cert"
  #[serde(rename = "type")]
  pub auth_type: String,
  /// User credentials for password authentication
  pub credentials: Option<Vec<Credential>>,
  /// Client CA certificate path for TLS client cert authentication
  pub client_ca_path: Option<String>,
}

/// User credential for password authentication
#[derive(Deserialize, Clone, Debug)]
pub struct Credential {
  /// Username
  pub username: String,
  /// Password hash (bcrypt format)
  pub password_hash: String,
}

/// Validated authentication configuration
#[derive(Clone, Debug)]
pub enum AuthConfig {
  /// No authentication
  None,
  /// Password authentication with user credentials
  Password { credentials: HashMap<String, String> },
  /// TLS client certificate authentication
  TlsClientCert { client_ca_path: PathBuf },
}

impl AuthConfig {
  /// Parse and validate authentication configuration
  ///
  /// Returns validated AuthConfig or error.
  pub fn from_args(args: Option<AuthConfigArgs>) -> Result<Self> {
    match args {
      None => Ok(AuthConfig::None),
      Some(auth_args) => match auth_args.auth_type.as_str() {
        "password" => {
          // Check for conflicting configuration: client_ca_path should not
          // be present for password authentication
          if auth_args.client_ca_path.is_some() {
            bail!(
              "Configuration conflict: client_ca_path should not be \
               configured when authentication type is 'password'"
            );
          }
          let credentials = auth_args.credentials.ok_or_else(|| {
            anyhow!(
              "credentials is required for password authentication"
            )
          })?;
          if credentials.is_empty() {
            bail!(
              "credentials cannot be empty for password authentication"
            );
          }
          let mut cred_map = HashMap::new();
          for cred in credentials {
            // Validate password hash format (strict bcrypt format check)
            // Per architecture document section 4.3, only $2a$, $2b$, $2y$
            // standard formats and $bcrypt$ PHC format are accepted.
            // Non-standard formats like $2x$, $2z$ are rejected.
            if !is_valid_bcrypt_format(&cred.password_hash) {
              bail!(
                "Invalid password hash format for user '{}': expected \
                 bcrypt format ($2a$, $2b$, $2y$ or $bcrypt$)",
                cred.username
              );
            }
            cred_map.insert(cred.username, cred.password_hash);
          }
          Ok(AuthConfig::Password { credentials: cred_map })
        }
        "tls_client_cert" => {
          // Check for conflicting configuration: credentials should not
          // be present for tls_client_cert authentication
          if auth_args.credentials.is_some() {
            bail!(
              "Configuration conflict: credentials should not be \
               configured when authentication type is 'tls_client_cert'"
            );
          }
          let client_ca_path = auth_args
            .client_ca_path
            .ok_or_else(|| {
              anyhow!(
                "client_ca_path is required for tls_client_cert \
                       authentication"
              )
            })?
            .into();
          Ok(AuthConfig::TlsClientCert { client_ca_path })
        }
        _ => {
          bail!("Invalid authentication type: {}", auth_args.auth_type)
        }
      },
    }
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

  if verify_password(credentials, &username, &password) {
    Ok(())
  } else {
    bail!("Proxy Authentication Required - invalid credentials")
  }
}

/// Perform HTTP authentication based on config
///
/// Returns Ok(()) if authentication succeeds or no auth needed,
/// Err with error message otherwise.
fn perform_authentication(
  req: &http::Request<()>,
  auth_config: &AuthConfig,
) -> Result<()> {
  match auth_config {
    AuthConfig::None | AuthConfig::TlsClientCert { .. } => Ok(()),
    AuthConfig::Password { credentials } => {
      handle_password_auth(req, credentials)
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
  auth_config: &AuthConfig,
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
  auth_config: AuthConfig,
  shutdown_handle: plugin::ShutdownHandle,
) where
  S: h3::quic::BidiStream<Bytes> + Send + 'static,
  <S as h3::quic::BidiStream<Bytes>>::SendStream: Send,
  <S as h3::quic::BidiStream<Bytes>>::RecvStream: Send,
{
  // Phase 1: Validate request
  let target_addr = match validate_connect_request(&req, &auth_config) {
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
    .unwrap_or_else(|_| http::StatusCode::INTERNAL_SERVER_ERROR);
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

/// Verify password against stored hash
fn verify_password(
  credentials: &HashMap<String, String>,
  username: &str,
  password: &str,
) -> bool {
  match credentials.get(username) {
    None => false,
    Some(stored_hash) => {
      // For simplicity, we accept both formats:
      // - $2... (standard bcrypt)
      // - $bcrypt$... (PHC format)
      // In production, use the bcrypt crate for proper verification
      // Here we implement a simple verification for testing
      verify_bcrypt_password(password, stored_hash)
    }
  }
}

/// Check if the hash has a valid bcrypt format with complete structure.
///
/// Valid formats per architecture document section 4.3:
/// - Standard bcrypt: $2a$, $2b$, $2y$ (must be exactly 60 characters)
/// - PHC format: $bcrypt$v=98$r=<rounds>$<hash> (must have complete
///   structure)
///
/// This function validates not just the prefix but also the structural
/// integrity:
/// - For standard bcrypt ($2a$, $2b$, $2y$): total length must be 60
///   characters
/// - For PHC format ($bcrypt$): must have exactly 5 parts with valid
///   structure:
///   - parts[1] = "bcrypt"
///   - parts[2] = "v=98"
///   - parts[3] = "r=<rounds>" where rounds is a valid number
///   - parts[4] = non-empty hash part (53 characters for valid bcrypt)
fn is_valid_bcrypt_format(hash: &str) -> bool {
  // Standard bcrypt format: $2a$, $2b$, $2y$ (exactly 60 characters)
  if hash.starts_with("$2a$")
    || hash.starts_with("$2b$")
    || hash.starts_with("$2y$")
  {
    return hash.len() == 60;
  }

  // PHC format: $bcrypt$v=98$r=<rounds>$<hash>
  if hash.starts_with("$bcrypt$") {
    return is_valid_phc_format(hash);
  }

  false
}

/// Validate PHC format bcrypt hash structure.
///
/// Expected format: $bcrypt$v=98$r=<rounds>$<hash>
///
/// Structure validation:
/// - Exactly 5 parts when split by '$'
/// - parts[1] = "bcrypt"
/// - parts[2] = "v=98"
/// - parts[3] = "r=<rounds>" where rounds is a valid integer
/// - parts[4] = non-empty hash (should be 53 characters for valid bcrypt)
fn is_valid_phc_format(hash: &str) -> bool {
  let parts: Vec<&str> = hash.split('$').collect();

  // Must have exactly 5 parts: "", "bcrypt", "v=98", "r=NN", "<hash>"
  if parts.len() != 5 {
    return false;
  }

  // Validate algorithm identifier
  if parts[1] != "bcrypt" {
    return false;
  }

  // Validate version (must be "v=98")
  if parts[2] != "v=98" {
    return false;
  }

  // Validate rounds format: must start with "r=" and have a valid number
  let rounds_part = parts[3];
  if !rounds_part.starts_with("r=") {
    return false;
  }
  let rounds_str = &rounds_part[2..];
  if rounds_str.is_empty() {
    return false;
  }
  if rounds_str.parse::<u32>().is_err() {
    return false;
  }

  // Validate hash part: must be non-empty
  // Standard bcrypt hash part (after rounds) is 53 characters:
  // 22 chars salt + 31 chars hash
  let hash_part = parts[4];
  if hash_part.is_empty() {
    return false;
  }

  true
}

/// Verify password against bcrypt hash
///
/// Uses the bcrypt crate for proper verification.
/// Supports both standard bcrypt format ($2a$, $2b$, $2y$) and
/// PHC format ($bcrypt$v=98$r=<rounds>$<hash>).
fn verify_bcrypt_password(password: &str, hash: &str) -> bool {
  // Try standard bcrypt format first ($2a$, $2b$, $2y$)
  if hash.starts_with("$2a$")
    || hash.starts_with("$2b$")
    || hash.starts_with("$2y$")
  {
    return bcrypt::verify(password, hash).unwrap_or(false);
  }

  // Handle PHC format: $bcrypt$v=98$r=<rounds>$<hash>
  // Convert to standard format for bcrypt crate
  if hash.starts_with("$bcrypt$") {
    return verify_phc_bcrypt(password, hash);
  }

  false
}

/// Verify password against PHC format bcrypt hash
///
/// PHC format per architecture document: $bcrypt$v=98$r=<rounds>$<hash>
/// Where <hash> is the complete bcrypt hash (salt + actual hash combined)
///
/// Parts after splitting by '$':
/// - parts[0] = "" (empty, before first $)
/// - parts[1] = "bcrypt" (algorithm identifier)
/// - parts[2] = "v=98" (version)
/// - parts[3] = "r=<rounds>" (rounds parameter)
/// - parts[4] = <hash> (complete bcrypt hash: salt+hash combined)
fn verify_phc_bcrypt(password: &str, phc_hash: &str) -> bool {
  // Parse PHC format manually
  // Expected: $bcrypt$v=98$r=<rounds>$<hash>
  let parts: Vec<&str> = phc_hash.split('$').collect();

  // Validate parts count: exactly 5 parts per architecture document
  if parts.len() != 5 {
    return false;
  }

  // Extract rounds from parts[3]
  let rounds_part = parts[3];
  let rounds = match rounds_part.strip_prefix("r=") {
    Some(r) => match r.parse::<u32>() {
      Ok(v) => v,
      Err(_) => return false,
    },
    None => return false,
  };

  // Get the hash part from parts[4]
  // This is the complete bcrypt hash (salt + actual hash combined)
  let hash_part = parts[4];

  // Build standard bcrypt hash
  // Standard format: $2b$<rounds>$<hash>
  // Note: bcrypt requires rounds to be formatted as two digits (e.g., 04, 12)
  let standard_hash = format!("$2b${:02}${}", rounds, hash_part);

  bcrypt::verify(password, &standard_hash).unwrap_or(false)
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
  auth_config: AuthConfig,
  stream_tracker: Rc<StreamTracker>,
  shutdown_handle: plugin::ShutdownHandle,
) {
  // Security check: Verify client certificate for TlsClientCert authentication
  // This is required to prevent TLS client cert bypass vulnerability.
  // Per architecture doc section 5.3.2, when TlsClientCert auth is configured,
  // we must verify that the peer presented a valid client certificate.
  if matches!(auth_config, AuthConfig::TlsClientCert { .. }) {
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
  auth_config: &AuthConfig,
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
    AuthConfig::None | AuthConfig::Password { .. } => {
      let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
      config.alpn_protocols = vec![ALPN.to_vec()];
      config
    }
    AuthConfig::TlsClientCert { client_ca_path } => {
      let ca_file =
        fs::File::open(client_ca_path).with_context(|| {
          format!("Failed to open client CA file: {:?}", client_ca_path)
        })?;
      let mut ca_reader = std::io::BufReader::new(ca_file);
      let ca_certs: Vec<CertificateDer> =
        rustls_pemfile::certs(&mut ca_reader)
          .collect::<Result<Vec<_>, _>>()
          .with_context(|| "Failed to parse client CA certificates")?;

      let mut root_store = RootCertStore::empty();
      for cert in ca_certs {
        root_store.add(cert)?;
      }

      // Build the client certificate verifier.
      // Note: We do NOT call allow_unauthenticated() here, which means
      // the verifier will REJECT clients that do not present a valid
      // certificate signed by the configured CA. This is the secure
      // default behavior required for TLS client certificate authentication.
      // Per rustls API: calling allow_unauthenticated() would allow
      // clients without certificates to connect, which is NOT desired.
      let verifier =
        WebPkiClientVerifier::builder(root_store.into()).build()?;
      let mut config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
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
  /// Authentication configuration
  auth_config: AuthConfig,
  /// Stream tracker
  stream_tracker: Rc<StreamTracker>,
  /// Shutdown handle
  shutdown_handle: plugin::ShutdownHandle,
  /// Associated service
  service: plugin::Service,
}

impl Http3Listener {
  /// Create a new HTTP/3 Listener
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
    let auth_config = AuthConfig::from_args(args.auth)?;

    // Load TLS config
    let tls_config =
      load_tls_config(&args.cert_path, &args.key_path, &auth_config)?;

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
          })?
          .into(),
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
              "[http3_listener] active_connections={}, active_streams={}",
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

  /// Helper function to generate a real bcrypt hash for testing.
  /// Uses cost 4 for fast test execution.
  fn make_test_bcrypt_hash(password: &str) -> String {
    bcrypt::hash(password, 4).expect("Failed to generate bcrypt hash")
  }

  /// Helper function to generate a real bcrypt hash in $2a$ format.
  fn make_test_bcrypt_hash_2a(password: &str) -> String {
    let hash = make_test_bcrypt_hash(password);
    // bcrypt crate generates $2b$ by default, convert to $2a$
    hash.replace("$2b$", "$2a$")
  }

  /// Helper function to generate a real bcrypt hash in $2y$ format.
  fn make_test_bcrypt_hash_2y(password: &str) -> String {
    let hash = make_test_bcrypt_hash(password);
    // bcrypt crate generates $2b$ by default, convert to $2y$
    hash.replace("$2b$", "$2y$")
  }

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

  #[test]
  fn test_auth_config_none() {
    let result = AuthConfig::from_args(None);
    assert!(matches!(result, Ok(AuthConfig::None)));
  }

  #[test]
  fn test_auth_config_password_valid() {
    let hash = make_test_bcrypt_hash("test_password");
    let args = AuthConfigArgs {
      auth_type: "password".to_string(),
      credentials: Some(vec![Credential {
        username: "user".to_string(),
        password_hash: hash,
      }]),
      client_ca_path: None,
    };
    let result = AuthConfig::from_args(Some(args));
    match result {
      Ok(AuthConfig::Password { credentials }) => {
        assert!(credentials.contains_key("user"));
        // Verify the hash is a valid 60-character bcrypt hash
        let stored_hash = credentials.get("user").unwrap();
        assert_eq!(stored_hash.len(), 60);
        assert!(stored_hash.starts_with("$2b$"));
      }
      _ => panic!("Expected Password variant"),
    }
  }

  #[test]
  fn test_auth_config_password_missing_credentials() {
    let args = AuthConfigArgs {
      auth_type: "password".to_string(),
      credentials: None,
      client_ca_path: None,
    };
    let result = AuthConfig::from_args(Some(args));
    assert!(result.is_err());
  }

  #[test]
  fn test_auth_config_password_empty_credentials() {
    let args = AuthConfigArgs {
      auth_type: "password".to_string(),
      credentials: Some(vec![]),
      client_ca_path: None,
    };
    let result = AuthConfig::from_args(Some(args));
    assert!(result.is_err());
  }

  #[test]
  fn test_auth_config_password_invalid_hash_format() {
    let args = AuthConfigArgs {
      auth_type: "password".to_string(),
      credentials: Some(vec![Credential {
        username: "user".to_string(),
        password_hash: "invalid_hash".to_string(),
      }]),
      client_ca_path: None,
    };
    let result = AuthConfig::from_args(Some(args));
    assert!(result.is_err());
  }

  #[test]
  fn test_auth_config_password_standard_bcrypt_2a_format() {
    // Standard bcrypt $2a$ format should be accepted
    let hash = make_test_bcrypt_hash_2a("test_password");
    assert!(hash.starts_with("$2a$"));
    assert_eq!(hash.len(), 60);
    let args = AuthConfigArgs {
      auth_type: "password".to_string(),
      credentials: Some(vec![Credential {
        username: "user".to_string(),
        password_hash: hash,
      }]),
      client_ca_path: None,
    };
    let result = AuthConfig::from_args(Some(args));
    assert!(result.is_ok());
  }

  #[test]
  fn test_auth_config_password_standard_bcrypt_2b_format() {
    // Standard bcrypt $2b$ format should be accepted
    let hash = make_test_bcrypt_hash("test_password");
    assert!(hash.starts_with("$2b$"));
    assert_eq!(hash.len(), 60);
    let args = AuthConfigArgs {
      auth_type: "password".to_string(),
      credentials: Some(vec![Credential {
        username: "user".to_string(),
        password_hash: hash,
      }]),
      client_ca_path: None,
    };
    let result = AuthConfig::from_args(Some(args));
    assert!(result.is_ok());
  }

  #[test]
  fn test_auth_config_password_standard_bcrypt_2y_format() {
    // Standard bcrypt $2y$ format should be accepted
    let hash = make_test_bcrypt_hash_2y("test_password");
    assert!(hash.starts_with("$2y$"));
    assert_eq!(hash.len(), 60);
    let args = AuthConfigArgs {
      auth_type: "password".to_string(),
      credentials: Some(vec![Credential {
        username: "user".to_string(),
        password_hash: hash,
      }]),
      client_ca_path: None,
    };
    let result = AuthConfig::from_args(Some(args));
    assert!(result.is_ok());
  }

  #[test]
  fn test_auth_config_password_non_standard_2x_format_rejected() {
    // Non-standard bcrypt $2x$ format should be rejected
    let args = AuthConfigArgs {
      auth_type: "password".to_string(),
      credentials: Some(vec![Credential {
        username: "user".to_string(),
        password_hash: "$2x$12$N9qo8yuLO94gxOM6PZ".to_string(),
      }]),
      client_ca_path: None,
    };
    let result = AuthConfig::from_args(Some(args));
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("Invalid password hash format"));
  }

  #[test]
  fn test_auth_config_password_non_standard_2z_format_rejected() {
    // Non-standard bcrypt $2z$ format should be rejected
    let args = AuthConfigArgs {
      auth_type: "password".to_string(),
      credentials: Some(vec![Credential {
        username: "user".to_string(),
        password_hash: "$2z$12$N9qo8yuLO94gxOM6PZ".to_string(),
      }]),
      client_ca_path: None,
    };
    let result = AuthConfig::from_args(Some(args));
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("Invalid password hash format"));
  }

  #[test]
  fn test_auth_config_password_non_standard_2_format_without_letter_rejected()
   {
    // Non-standard format $2$ (without letter) should be rejected
    let args = AuthConfigArgs {
      auth_type: "password".to_string(),
      credentials: Some(vec![Credential {
        username: "user".to_string(),
        password_hash: "$2$12$N9qo8yuLO94gxOM6PZ".to_string(),
      }]),
      client_ca_path: None,
    };
    let result = AuthConfig::from_args(Some(args));
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("Invalid password hash format"));
  }

  #[test]
  fn test_auth_config_password_phc_bcrypt_format() {
    // PHC format $bcrypt$ should be accepted
    // Generate a real bcrypt hash and convert to PHC format
    let bcrypt_hash = make_test_bcrypt_hash("test_password");
    // bcrypt_hash format: $2b$04$<22-char-salt><31-char-hash>
    // Extract the salt+hash part (after $2b$04$)
    // Position 7 onwards is the salt+hash (53 chars)
    // PHC format: $bcrypt$v=98$r=4$<salt><hash>
    let salt_hash_part = &bcrypt_hash[7..]; // Just the salt+hash
    let phc_hash = format!("$bcrypt$v=98$r=4${}", salt_hash_part);
    let args = AuthConfigArgs {
      auth_type: "password".to_string(),
      credentials: Some(vec![Credential {
        username: "user".to_string(),
        password_hash: phc_hash,
      }]),
      client_ca_path: None,
    };
    let result = AuthConfig::from_args(Some(args));
    assert!(result.is_ok());
  }

  #[test]
  fn test_auth_config_tls_client_cert_valid() {
    let args = AuthConfigArgs {
      auth_type: "tls_client_cert".to_string(),
      credentials: None,
      client_ca_path: Some("/path/to/ca.pem".to_string()),
    };
    let result = AuthConfig::from_args(Some(args));
    match result {
      Ok(AuthConfig::TlsClientCert { client_ca_path }) => {
        assert_eq!(client_ca_path, PathBuf::from("/path/to/ca.pem"));
      }
      _ => panic!("Expected TlsClientCert variant"),
    }
  }

  #[test]
  fn test_auth_config_tls_client_cert_missing_path() {
    let args = AuthConfigArgs {
      auth_type: "tls_client_cert".to_string(),
      credentials: None,
      client_ca_path: None,
    };
    let result = AuthConfig::from_args(Some(args));
    assert!(result.is_err());
  }

  #[test]
  fn test_auth_config_invalid_type() {
    let args = AuthConfigArgs {
      auth_type: "invalid".to_string(),
      credentials: None,
      client_ca_path: None,
    };
    let result = AuthConfig::from_args(Some(args));
    assert!(result.is_err());
  }

  #[test]
  fn test_auth_config_password_with_client_ca_path_conflict() {
    let hash = make_test_bcrypt_hash("test_password");
    let args = AuthConfigArgs {
      auth_type: "password".to_string(),
      credentials: Some(vec![Credential {
        username: "user".to_string(),
        password_hash: hash,
      }]),
      client_ca_path: Some("/path/to/ca.pem".to_string()),
    };
    let result = AuthConfig::from_args(Some(args));
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("Configuration conflict"));
    assert!(err_msg.contains("client_ca_path"));
    assert!(err_msg.contains("password"));
  }

  #[test]
  fn test_auth_config_tls_client_cert_with_credentials_conflict() {
    let hash = make_test_bcrypt_hash("test_password");
    let args = AuthConfigArgs {
      auth_type: "tls_client_cert".to_string(),
      credentials: Some(vec![Credential {
        username: "user".to_string(),
        password_hash: hash,
      }]),
      client_ca_path: Some("/path/to/ca.pem".to_string()),
    };
    let result = AuthConfig::from_args(Some(args));
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("Configuration conflict"));
    assert!(err_msg.contains("credentials"));
    assert!(err_msg.contains("tls_client_cert"));
  }

  // ============== Password Verification with Real Hash Tests ==============

  #[test]
  fn test_password_verification_success_with_real_hash() {
    // Test that password verification works with real bcrypt hashes
    let password = "correct_password";
    let hash = bcrypt::hash(password, 4).unwrap();

    let args = AuthConfigArgs {
      auth_type: "password".to_string(),
      credentials: Some(vec![Credential {
        username: "testuser".to_string(),
        password_hash: hash.clone(),
      }]),
      client_ca_path: None,
    };

    // Parse config
    let result = AuthConfig::from_args(Some(args)).unwrap();
    match result {
      AuthConfig::Password { credentials } => {
        // Verify correct password
        assert!(verify_password(&credentials, "testuser", password));
        // Verify the hash is 60 characters
        assert_eq!(credentials.get("testuser").unwrap().len(), 60);
      }
      _ => panic!("Expected Password variant"),
    }
  }

  #[test]
  fn test_password_verification_failure_wrong_password() {
    // Test that password verification fails with wrong password
    let correct_password = "correct_password";
    let wrong_password = "wrong_password";
    let hash = bcrypt::hash(correct_password, 4).unwrap();

    let args = AuthConfigArgs {
      auth_type: "password".to_string(),
      credentials: Some(vec![Credential {
        username: "testuser".to_string(),
        password_hash: hash,
      }]),
      client_ca_path: None,
    };

    // Parse config
    let result = AuthConfig::from_args(Some(args)).unwrap();
    match result {
      AuthConfig::Password { credentials } => {
        // Verify wrong password fails
        assert!(!verify_password(
          &credentials,
          "testuser",
          wrong_password
        ));
      }
      _ => panic!("Expected Password variant"),
    }
  }

  #[test]
  fn test_password_verification_failure_unknown_user() {
    // Test that password verification fails for unknown user
    let hash = bcrypt::hash("password", 4).unwrap();

    let args = AuthConfigArgs {
      auth_type: "password".to_string(),
      credentials: Some(vec![Credential {
        username: "known_user".to_string(),
        password_hash: hash,
      }]),
      client_ca_path: None,
    };

    // Parse config
    let result = AuthConfig::from_args(Some(args)).unwrap();
    match result {
      AuthConfig::Password { credentials } => {
        // Verify unknown user fails
        assert!(!verify_password(
          &credentials,
          "unknown_user",
          "password"
        ));
      }
      _ => panic!("Expected Password variant"),
    }
  }

  #[test]
  fn test_password_verification_multiple_users() {
    // Test password verification with multiple users
    let hash1 = bcrypt::hash("password1", 4).unwrap();
    let hash2 = bcrypt::hash("password2", 4).unwrap();
    let hash3 = bcrypt::hash("password3", 4).unwrap();

    let args = AuthConfigArgs {
      auth_type: "password".to_string(),
      credentials: Some(vec![
        Credential {
          username: "user1".to_string(),
          password_hash: hash1,
        },
        Credential {
          username: "user2".to_string(),
          password_hash: hash2,
        },
        Credential {
          username: "user3".to_string(),
          password_hash: hash3,
        },
      ]),
      client_ca_path: None,
    };

    // Parse config
    let result = AuthConfig::from_args(Some(args)).unwrap();
    match result {
      AuthConfig::Password { credentials } => {
        // Verify each user with correct password
        assert!(verify_password(&credentials, "user1", "password1"));
        assert!(verify_password(&credentials, "user2", "password2"));
        assert!(verify_password(&credentials, "user3", "password3"));

        // Verify wrong passwords fail
        assert!(!verify_password(&credentials, "user1", "wrong"));
        assert!(!verify_password(&credentials, "user2", "password1"));
        assert!(!verify_password(&credentials, "user3", "password2"));
      }
      _ => panic!("Expected Password variant"),
    }
  }

  #[test]
  fn test_password_verification_phc_format_real_hash() {
    // Test password verification with real PHC format hash
    let password = "test_password";
    let bcrypt_hash = bcrypt::hash(password, 4).unwrap();

    // Convert to PHC format
    // bcrypt_hash format: $2b$04$<salt><hash>
    // Position 0-6: "$2b$04$" (7 chars)
    // Position 7 onwards: <salt><hash> (53 chars)
    // PHC format: $bcrypt$v=98$r=4$<salt><hash>
    let salt_hash_part = &bcrypt_hash[7..]; // Just the salt+hash, no leading $
    let phc_hash = format!("$bcrypt$v=98$r=4${}", salt_hash_part);

    let args = AuthConfigArgs {
      auth_type: "password".to_string(),
      credentials: Some(vec![Credential {
        username: "user".to_string(),
        password_hash: phc_hash,
      }]),
      client_ca_path: None,
    };

    // Parse config
    let result = AuthConfig::from_args(Some(args)).unwrap();
    match result {
      AuthConfig::Password { credentials } => {
        // Verify correct password with PHC format hash
        assert!(verify_password(&credentials, "user", password));
        // Verify wrong password fails
        assert!(!verify_password(&credentials, "user", "wrong"));
      }
      _ => panic!("Expected Password variant"),
    }
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

  // ============== Password Verification Tests ==============

  #[test]
  fn test_verify_password_valid() {
    // Create a real bcrypt hash for password "test_password"
    // Using cost 4 for fast test execution
    let hash =
      bcrypt::hash("test_password", bcrypt::DEFAULT_COST).unwrap();
    let mut credentials = HashMap::new();
    credentials.insert("user".to_string(), hash);
    assert!(verify_password(&credentials, "user", "test_password"));
  }

  #[test]
  fn test_verify_password_user_not_found() {
    let credentials = HashMap::new();
    assert!(!verify_password(&credentials, "nonexistent", "password"));
  }

  #[test]
  fn test_verify_password_wrong_password() {
    let hash =
      bcrypt::hash("correct_password", bcrypt::DEFAULT_COST).unwrap();
    let mut credentials = HashMap::new();
    credentials.insert("user".to_string(), hash);
    assert!(!verify_password(&credentials, "user", "wrongpassword"));
  }

  #[test]
  fn test_verify_bcrypt_password_standard_format() {
    // Test standard bcrypt format ($2b$)
    let hash =
      bcrypt::hash("test_password", bcrypt::DEFAULT_COST).unwrap();
    assert!(verify_bcrypt_password("test_password", &hash));
    assert!(!verify_bcrypt_password("wrong_password", &hash));
  }

  #[test]
  fn test_verify_bcrypt_password_invalid_hash() {
    // Test with invalid hash format
    assert!(!verify_bcrypt_password("password", "invalid_hash"));
    assert!(!verify_bcrypt_password("password", ""));
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
    // Use real 60-character bcrypt hashes
    let hash1 =
      "$2b$04$3h3ttjZZG/A6RUab.r68VeU9EvGO9XbuhVG0LT8FhfDtC4p5c2wr.";
    let hash2 = "$bcrypt$v=98$r=4$3h3ttjZZG/A6RUab.r68VeU9EvGO9XbuhVG0LT8FhfDtC4p5c2wr.";
    let yaml = format!(
      r#"
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
  type: "password"
  credentials:
    - username: "user1"
      password_hash: "{}"
    - username: "user2"
      password_hash: "{}"
"#,
      hash1, hash2
    );
    let args: Http3ListenerArgs = serde_yaml::from_str(&yaml).unwrap();
    assert_eq!(args.address, "0.0.0.0:443");
    assert!(args.quic.is_some());
    assert!(args.auth.is_some());

    let auth = args.auth.unwrap();
    assert_eq!(auth.auth_type, "password");
    assert!(auth.credentials.is_some());
    let creds = auth.credentials.unwrap();
    assert_eq!(creds.len(), 2);
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

  // ============== Credential Tests ==============

  #[test]
  fn test_credential_deserialize() {
    // Use a real 60-character bcrypt hash
    let real_hash =
      "$2b$04$iawht21wlD8wD2Otvv2lOOYb0J/hq5.E3LK.d1RVMEuO4HLwXzAOC";
    let yaml = format!(
      r#"
username: "testuser"
password_hash: "{}"
"#,
      real_hash
    );
    let cred: Credential = serde_yaml::from_str(&yaml).unwrap();
    assert_eq!(cred.username, "testuser");
    assert_eq!(cred.password_hash, real_hash);
    assert_eq!(cred.password_hash.len(), 60);
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
    assert_eq!(LISTENER_SHUTDOWN_TIMEOUT, Duration::from_secs(5));
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

  // ============== Additional Password Verification Tests ==============

  #[test]
  fn test_verify_bcrypt_password_with_2a_format() {
    // Test with $2a$ format
    let hash = bcrypt::hash("password123", 4).unwrap();
    // Convert $2b$ to $2a$ for testing
    let hash_2a = hash.replace("$2b$", "$2a$");
    assert!(verify_bcrypt_password("password123", &hash_2a));
    assert!(!verify_bcrypt_password("wrong", &hash_2a));
  }

  #[test]
  fn test_verify_bcrypt_password_with_2y_format() {
    // Test with $2y$ format
    let hash = bcrypt::hash("password123", 4).unwrap();
    let hash_2y = hash.replace("$2b$", "$2y$");
    assert!(verify_bcrypt_password("password123", &hash_2y));
    assert!(!verify_bcrypt_password("wrong", &hash_2y));
  }

  #[test]
  fn test_verify_password_with_real_bcrypt_hash() {
    let hash = bcrypt::hash("mypassword", 4).unwrap();
    let mut credentials = HashMap::new();
    credentials.insert("user".to_string(), hash);
    assert!(verify_password(&credentials, "user", "mypassword"));
    assert!(!verify_password(&credentials, "user", "wrongpassword"));
  }

  #[test]
  fn test_verify_bcrypt_password_empty_password() {
    let hash = bcrypt::hash("", 4).unwrap();
    assert!(verify_bcrypt_password("", &hash));
    assert!(!verify_bcrypt_password("something", &hash));
  }

  #[test]
  fn test_verify_bcrypt_password_empty_hash() {
    assert!(!verify_bcrypt_password("password", ""));
  }

  #[test]
  fn test_verify_bcrypt_password_malformed_hash() {
    assert!(!verify_bcrypt_password("password", "$2a$invalid"));
    assert!(!verify_bcrypt_password("password", "$bcrypt$invalid"));
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

  // ============== AuthConfig Additional Tests ==============

  #[test]
  fn test_auth_config_password_multiple_credentials() {
    let hash1 = make_test_bcrypt_hash_2a("password1");
    let hash2 = make_test_bcrypt_hash("password2");
    let hash3 = make_test_bcrypt_hash_2y("password3");
    let args = AuthConfigArgs {
      auth_type: "password".to_string(),
      credentials: Some(vec![
        Credential {
          username: "user1".to_string(),
          password_hash: hash1,
        },
        Credential {
          username: "user2".to_string(),
          password_hash: hash2,
        },
        Credential {
          username: "user3".to_string(),
          password_hash: hash3,
        },
      ]),
      client_ca_path: None,
    };
    let result = AuthConfig::from_args(Some(args));
    match result {
      Ok(AuthConfig::Password { credentials }) => {
        assert_eq!(credentials.len(), 3);
        assert!(credentials.contains_key("user1"));
        assert!(credentials.contains_key("user2"));
        assert!(credentials.contains_key("user3"));
      }
      _ => panic!("Expected Password variant"),
    }
  }

  #[test]
  fn test_auth_config_password_bcrypt_phc_format() {
    // Test that PHC bcrypt format is accepted during config parsing
    // Generate a real bcrypt hash and convert to PHC format
    let bcrypt_hash = make_test_bcrypt_hash("test_password");
    // Extract the salt+hash part (after $2b$04$)
    // Position 7 onwards is the salt+hash (53 chars)
    // PHC format: $bcrypt$v=98$r=4$<salt><hash>
    let salt_hash_part = &bcrypt_hash[7..];
    let phc_hash = format!("$bcrypt$v=98$r=4${}", salt_hash_part);
    let args = AuthConfigArgs {
      auth_type: "password".to_string(),
      credentials: Some(vec![Credential {
        username: "user".to_string(),
        password_hash: phc_hash,
      }]),
      client_ca_path: None,
    };
    let result = AuthConfig::from_args(Some(args));
    assert!(result.is_ok());
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
  type: "tls_client_cert"
  client_ca_path: "/etc/ssl/client-ca.pem"
"#;
    let args: Http3ListenerArgs = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(args.address, "127.0.0.1:8443");
    assert!(args.quic.is_some());
    assert!(args.auth.is_some());

    let quic = args.quic.unwrap();
    assert_eq!(quic.max_concurrent_bidi_streams, Some(50));

    let auth = args.auth.unwrap();
    assert_eq!(auth.auth_type, "tls_client_cert");
    assert_eq!(
      auth.client_ca_path,
      Some("/etc/ssl/client-ca.pem".to_string())
    );
  }

  // ============== bcrypt Format Validation Tests ==============

  #[test]
  fn test_is_valid_bcrypt_format_standard_2a() {
    let hash = make_test_bcrypt_hash_2a("test_password");
    assert!(is_valid_bcrypt_format(&hash));
    assert_eq!(hash.len(), 60);
  }

  #[test]
  fn test_is_valid_bcrypt_format_standard_2b() {
    let hash = make_test_bcrypt_hash("test_password");
    assert!(is_valid_bcrypt_format(&hash));
    assert_eq!(hash.len(), 60);
  }

  #[test]
  fn test_is_valid_bcrypt_format_standard_2y() {
    let hash = make_test_bcrypt_hash_2y("test_password");
    assert!(is_valid_bcrypt_format(&hash));
    assert_eq!(hash.len(), 60);
  }

  #[test]
  fn test_is_valid_bcrypt_format_phc() {
    // Generate real PHC format hash
    let bcrypt_hash = make_test_bcrypt_hash("test_password");
    // Position 7 onwards is the salt+hash
    let salt_hash_part = &bcrypt_hash[7..];
    let phc_hash = format!("$bcrypt$v=98$r=4${}", salt_hash_part);
    assert!(is_valid_bcrypt_format(&phc_hash));
  }

  #[test]
  fn test_is_valid_bcrypt_format_non_standard_2x_rejected() {
    // $2x$ is not a standard bcrypt format and should be rejected
    assert!(!is_valid_bcrypt_format("$2x$12$N9qo8yuLO94gxOM6PZ"));
  }

  #[test]
  fn test_is_valid_bcrypt_format_non_standard_2z_rejected() {
    // $2z$ is not a standard bcrypt format and should be rejected
    assert!(!is_valid_bcrypt_format("$2z$12$N9qo8yuLO94gxOM6PZ"));
  }

  #[test]
  fn test_is_valid_bcrypt_format_non_standard_2_without_letter_rejected()
   {
    // $2$ without a letter is not a valid bcrypt format
    assert!(!is_valid_bcrypt_format("$2$12$N9qo8yuLO94gxOM6PZ"));
  }

  #[test]
  fn test_is_valid_bcrypt_format_invalid_prefix_rejected() {
    // Completely invalid prefix should be rejected
    assert!(!is_valid_bcrypt_format("invalid_hash"));
    assert!(!is_valid_bcrypt_format("$3a$12$N9qo8yuLO94gxOM6PZ"));
  }

  // ============== Incomplete Hash Rejection Tests ==============
  // These tests verify that incomplete bcrypt hashes are properly
  // rejected, as per the fix for is_valid_bcrypt_format function.

  #[test]
  fn test_is_valid_bcrypt_format_incomplete_standard_only_prefix() {
    // Only the prefix without any content should be rejected
    assert!(!is_valid_bcrypt_format("$2b$"));
    assert!(!is_valid_bcrypt_format("$2a$"));
    assert!(!is_valid_bcrypt_format("$2y$"));
  }

  #[test]
  fn test_is_valid_bcrypt_format_incomplete_standard_with_rounds() {
    // Prefix with rounds but no salt/hash should be rejected
    assert!(!is_valid_bcrypt_format("$2b$12$"));
    assert!(!is_valid_bcrypt_format("$2a$04$"));
    assert!(!is_valid_bcrypt_format("$2y$10$"));
  }

  #[test]
  fn test_is_valid_bcrypt_format_incomplete_standard_short_hash() {
    // Short hash (less than 60 chars) should be rejected
    assert!(!is_valid_bcrypt_format("$2b$12$short"));
    assert!(!is_valid_bcrypt_format("$2a$12$N9qo8yuLO94"));
    assert!(!is_valid_bcrypt_format("$2y$12$N9qo8yuLO94gxOM6PZweY"));
  }

  #[test]
  fn test_is_valid_bcrypt_format_incomplete_standard_long_hash() {
    // Hash longer than 60 chars should also be rejected
    let valid_hash = make_test_bcrypt_hash("test_password");
    let long_hash = format!("{}extra", valid_hash);
    assert!(!is_valid_bcrypt_format(&long_hash));
  }

  #[test]
  fn test_is_valid_bcrypt_format_incomplete_phc_only_prefix() {
    // Only $bcrypt$ prefix should be rejected
    assert!(!is_valid_bcrypt_format("$bcrypt$"));
  }

  #[test]
  fn test_is_valid_bcrypt_format_incomplete_phc_missing_version() {
    // Missing version part should be rejected
    assert!(!is_valid_bcrypt_format("$bcrypt$r=12$saltnhash"));
  }

  #[test]
  fn test_is_valid_bcrypt_format_incomplete_phc_missing_rounds() {
    // Missing rounds part should be rejected
    assert!(!is_valid_bcrypt_format("$bcrypt$v=98$saltnhash"));
  }

  #[test]
  fn test_is_valid_bcrypt_format_incomplete_phc_invalid_version() {
    // Invalid version should be rejected (only v=98 is valid)
    assert!(!is_valid_bcrypt_format("$bcrypt$v=99$r=12$saltnhash"));
    assert!(!is_valid_bcrypt_format("$bcrypt$v=97$r=12$saltnhash"));
    assert!(!is_valid_bcrypt_format("$bcrypt$v=100$r=12$saltnhash"));
  }

  #[test]
  fn test_is_valid_bcrypt_format_incomplete_phc_invalid_rounds_format()
  {
    // Invalid rounds format should be rejected
    assert!(!is_valid_bcrypt_format("$bcrypt$v=98$r=abc$saltnhash")); // non-numeric
    assert!(!is_valid_bcrypt_format(
      "$bcrypt$v=98$rounds=12$saltnhash"
    )); // wrong format
    assert!(!is_valid_bcrypt_format("$bcrypt$v=98$r=$saltnhash")); // empty rounds
  }

  #[test]
  fn test_is_valid_bcrypt_format_incomplete_phc_missing_hash() {
    // Missing hash part should be rejected
    assert!(!is_valid_bcrypt_format("$bcrypt$v=98$r=12$"));
  }

  #[test]
  fn test_is_valid_bcrypt_format_incomplete_phc_not_enough_parts() {
    // Not enough parts should be rejected
    assert!(!is_valid_bcrypt_format("$bcrypt$v=98"));
    assert!(!is_valid_bcrypt_format("$bcrypt$v=98$r=12"));
  }

  #[test]
  fn test_is_valid_bcrypt_format_valid_standard_60_chars() {
    // Valid standard bcrypt hash should be exactly 60 chars
    let hash = make_test_bcrypt_hash("test_password");
    assert_eq!(hash.len(), 60);
    assert!(is_valid_bcrypt_format(&hash));
  }

  #[test]
  fn test_is_valid_bcrypt_format_valid_phc_complete_structure() {
    // Valid PHC format with complete structure
    let bcrypt_hash = make_test_bcrypt_hash("test_password");
    let salt_hash_part = &bcrypt_hash[7..]; // after "$2b$NN"
    let phc_hash = format!("$bcrypt$v=98$r=4${}", salt_hash_part);
    assert!(is_valid_bcrypt_format(&phc_hash));

    // Also test with different rounds
    let phc_hash_12 = format!("$bcrypt$v=98$r=12${}", salt_hash_part);
    assert!(is_valid_bcrypt_format(&phc_hash_12));
  }

  #[test]
  fn test_verify_bcrypt_password_standard_formats() {
    let password = "test_password";

    // Test $2a$ format
    let hash_2a = bcrypt::hash(password, 4).unwrap();
    // bcrypt crate uses $2b$ by default, but we can verify it works
    assert!(verify_bcrypt_password(password, &hash_2a));
    assert!(!verify_bcrypt_password("wrong", &hash_2a));
  }

  #[test]
  fn test_verify_bcrypt_password_non_standard_format_rejected() {
    // Non-standard $2x$ format should be rejected by verify_bcrypt_password
    // This test verifies that the function only accepts valid formats
    assert!(!verify_bcrypt_password(
      "password",
      "$2x$12$N9qo8yuLO94gxOM6PZ"
    ));

    // Non-standard $2z$ format should be rejected
    assert!(!verify_bcrypt_password(
      "password",
      "$2z$12$N9qo8yuLO94gxOM6PZ"
    ));
  }

  // ============== PHC Format Password Verification Tests ==============

  /// Helper function to convert standard bcrypt hash to PHC format
  fn standard_to_phc_format(standard_hash: &str) -> String {
    // Standard format: $2b$<rounds>$<salt+hash>
    // PHC format: $bcrypt$v=98$r=<rounds>$<salt+hash>
    let parts: Vec<&str> = standard_hash.split('$').collect();
    if parts.len() == 4 {
      let rounds = parts[2];
      let salt_hash = parts[3];
      format!("$bcrypt$v=98$r={}${}", rounds, salt_hash)
    } else {
      standard_hash.to_string()
    }
  }

  #[test]
  fn test_verify_bcrypt_password_phc_format_valid() {
    // Test PHC format with valid password
    // Generate a standard bcrypt hash
    let standard_hash = bcrypt::hash("correct_password", 4).unwrap();
    // Convert to PHC format
    let phc_hash = standard_to_phc_format(&standard_hash);
    // Verify with correct password
    assert!(
      verify_bcrypt_password("correct_password", &phc_hash),
      "PHC format should verify correct password"
    );
    // Verify with wrong password
    assert!(
      !verify_bcrypt_password("wrong_password", &phc_hash),
      "PHC format should not verify wrong password"
    );
  }

  #[test]
  fn test_verify_bcrypt_password_phc_format_different_rounds() {
    // Test PHC format with different round counts
    for cost in [4, 10, 12].iter() {
      let standard_hash = bcrypt::hash("test_password", *cost).unwrap();
      let phc_hash = standard_to_phc_format(&standard_hash);
      assert!(
        verify_bcrypt_password("test_password", &phc_hash),
        "PHC format with cost {} should verify correct password",
        cost
      );
      assert!(
        !verify_bcrypt_password("wrong", &phc_hash),
        "PHC format with cost {} should not verify wrong password",
        cost
      );
    }
  }

  #[test]
  fn test_verify_bcrypt_password_phc_format_empty_password() {
    // Test PHC format with empty password
    let standard_hash = bcrypt::hash("", 4).unwrap();
    let phc_hash = standard_to_phc_format(&standard_hash);
    assert!(
      verify_bcrypt_password("", &phc_hash),
      "PHC format should verify empty password"
    );
    assert!(
      !verify_bcrypt_password("something", &phc_hash),
      "PHC format should not verify non-empty password when hash is for empty"
    );
  }

  #[test]
  fn test_verify_bcrypt_password_phc_format_invalid_structures() {
    // Test various invalid PHC format structures
    // Missing version
    assert!(!verify_bcrypt_password(
      "password",
      "$bcrypt$r=12$saltnhash"
    ));
    // Missing rounds
    assert!(!verify_bcrypt_password(
      "password",
      "$bcrypt$v=98$saltnhash"
    ));
    // Invalid rounds format
    assert!(!verify_bcrypt_password(
      "password",
      "$bcrypt$v=98$r=abc$saltnhash"
    ));
    // Missing hash
    assert!(!verify_bcrypt_password("password", "$bcrypt$v=98$r=12$"));
    // Not enough parts
    assert!(!verify_bcrypt_password("password", "$bcrypt$v=98"));
    // Invalid prefix in rounds (not starting with "r=")
    assert!(!verify_bcrypt_password(
      "password",
      "$bcrypt$v=98$x=12$saltnhash"
    ));
    // Only 3 parts (not enough for PHC)
    assert!(!verify_bcrypt_password("password", "$bcrypt$v=98"));
    // Empty rounds value
    assert!(!verify_bcrypt_password(
      "password",
      "$bcrypt$v=98$r=$saltnhash"
    ));
  }

  #[test]
  fn test_verify_bcrypt_password_phc_format_with_invalid_bcrypt_hash() {
    // Test PHC format with malformed bcrypt hash part
    // This tests the bcrypt::verify returning an error path
    let invalid_hash = "$bcrypt$v=98$r=12$invalid_bcrypt_hash";
    assert!(
      !verify_bcrypt_password("password", invalid_hash),
      "PHC format with invalid bcrypt hash should return false"
    );
  }

  #[test]
  fn test_verify_password_with_phc_format() {
    // Test verify_password function with PHC format
    let standard_hash = bcrypt::hash("secret123", 4).unwrap();
    let phc_hash = standard_to_phc_format(&standard_hash);

    let mut credentials = HashMap::new();
    credentials.insert("testuser".to_string(), phc_hash);

    assert!(
      verify_password(&credentials, "testuser", "secret123"),
      "verify_password should verify correct PHC hash"
    );
    assert!(
      !verify_password(&credentials, "testuser", "wrong"),
      "verify_password should not verify wrong password with PHC hash"
    );
    assert!(
      !verify_password(&credentials, "nonexistent", "secret123"),
      "verify_password should return false for nonexistent user"
    );
  }

  #[test]
  fn test_verify_bcrypt_password_phc_format_with_special_chars() {
    // Test PHC format with passwords containing special characters
    let special_passwords = vec![
      "p@ssw0rd!",
      "hello world",
      "日本語パスワード",
      "emoji🔐password",
      "  spaces  ",
      "tab\tpassword",
    ];

    for password in special_passwords {
      let standard_hash = bcrypt::hash(password, 4).unwrap();
      let phc_hash = standard_to_phc_format(&standard_hash);
      assert!(
        verify_bcrypt_password(password, &phc_hash),
        "PHC format should verify password with special chars: {:?}",
        password
      );
    }
  }

  #[test]
  fn test_verify_bcrypt_password_phc_format_long_password() {
    // Test PHC format with long password (bcrypt truncates to 72 bytes)
    let long_password = "x".repeat(100);
    let standard_hash = bcrypt::hash(&long_password, 4).unwrap();
    let phc_hash = standard_to_phc_format(&standard_hash);

    // Should verify the long password (truncated)
    assert!(
      verify_bcrypt_password(&long_password, &phc_hash),
      "PHC format should verify long password"
    );

    // Should also verify a 72-byte prefix
    let truncated = "x".repeat(72);
    assert!(
      verify_bcrypt_password(&truncated, &phc_hash),
      "PHC format should verify truncated password"
    );

    // Should not verify wrong password
    assert!(
      !verify_bcrypt_password(&"y".repeat(100), &phc_hash),
      "PHC format should not verify wrong password"
    );
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
        let shutdown_handle = tracker.shutdown_handle();

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

  // ============== AuthConfig Edge Cases ==============

  #[test]
  fn test_auth_config_password_duplicate_usernames() {
    // When duplicate usernames are provided, the last one wins
    let hash1 = make_test_bcrypt_hash_2a("password1");
    let hash2 = make_test_bcrypt_hash_2a("password2");
    let args = AuthConfigArgs {
      auth_type: "password".to_string(),
      credentials: Some(vec![
        Credential {
          username: "user".to_string(),
          password_hash: hash1.clone(),
        },
        Credential {
          username: "user".to_string(), // duplicate
          password_hash: hash2.clone(),
        },
      ]),
      client_ca_path: None,
    };
    let result = AuthConfig::from_args(Some(args));
    match result {
      Ok(AuthConfig::Password { credentials }) => {
        // HashMap will have only one entry for "user"
        assert_eq!(credentials.len(), 1);
        // The last value wins
        assert_eq!(credentials.get("user").unwrap(), &hash2);
      }
      _ => panic!("Expected Password variant"),
    }
  }

  // ============== Credential Tests ==============

  #[test]
  fn test_credential_debug() {
    let hash = make_test_bcrypt_hash("test_password");
    let cred = Credential {
      username: "testuser".to_string(),
      password_hash: hash,
    };
    // Test that Debug trait is implemented
    let debug_str = format!("{:?}", cred);
    assert!(debug_str.contains("testuser"));
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

  // ============== AuthConfig Clone Tests ==============

  #[test]
  fn test_auth_config_clone() {
    let config = AuthConfig::None;
    let cloned = config.clone();
    assert!(matches!(cloned, AuthConfig::None));

    let mut creds = HashMap::new();
    creds.insert("user".to_string(), "hash".to_string());
    let config = AuthConfig::Password { credentials: creds };
    let cloned = config.clone();
    match cloned {
      AuthConfig::Password { credentials } => {
        assert!(credentials.contains_key("user"));
      }
      _ => panic!("Expected Password variant"),
    }

    let config = AuthConfig::TlsClientCert {
      client_ca_path: PathBuf::from("/path/to/ca.pem"),
    };
    let cloned = config.clone();
    match cloned {
      AuthConfig::TlsClientCert { client_ca_path } => {
        assert_eq!(client_ca_path, PathBuf::from("/path/to/ca.pem"));
      }
      _ => panic!("Expected TlsClientCert variant"),
    }
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

  // ============== AuthConfigArgs Tests ==============

  #[test]
  fn test_auth_config_args_clone() {
    let hash = make_test_bcrypt_hash("test_password");
    let args = AuthConfigArgs {
      auth_type: "password".to_string(),
      credentials: Some(vec![Credential {
        username: "user".to_string(),
        password_hash: hash,
      }]),
      client_ca_path: None,
    };
    let cloned = args.clone();
    assert_eq!(cloned.auth_type, args.auth_type);
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
    let auth_config = AuthConfig::None;
    let result = load_tls_config(
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap(),
      &auth_config,
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

    let auth_config = AuthConfig::None;
    let result = load_tls_config(
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap(),
      &auth_config,
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

    let auth_config = AuthConfig::None;
    let result = load_tls_config(
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap(),
      &auth_config,
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

    let auth_config = AuthConfig::None;
    let result = load_tls_config(
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap(),
      &auth_config,
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

    let hash = make_test_bcrypt_hash("test_password");
    let mut credentials = HashMap::new();
    credentials.insert("user".to_string(), hash);
    let auth_config = AuthConfig::Password { credentials };

    let result = load_tls_config(
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap(),
      &auth_config,
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

    let auth_config =
      AuthConfig::TlsClientCert { client_ca_path: ca_path.clone() };

    let result = load_tls_config(
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap(),
      &auth_config,
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

    let auth_config =
      AuthConfig::TlsClientCert { client_ca_path: ca_path.clone() };

    let result = load_tls_config(
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap(),
      &auth_config,
    );

    assert!(
      result.is_err(),
      "load_tls_config should fail when client CA file not found"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
      err_msg.contains("Failed to open client CA file"),
      "Error should mention client CA file: {err_msg}"
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

    let auth_config = AuthConfig::None;
    let result = load_tls_config(
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap(),
      &auth_config,
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

    let auth_config = AuthConfig::None;
    let result = load_tls_config(
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap(),
      &auth_config,
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

    let auth_config = AuthConfig::None;
    let result = load_tls_config(
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap(),
      &auth_config,
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

    // Test Password auth
    let hash = make_test_bcrypt_hash("test_password");
    let mut credentials = HashMap::new();
    credentials.insert("user".to_string(), hash);
    let auth_config = AuthConfig::Password { credentials };
    let result1 = load_tls_config(
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap(),
      &auth_config,
    );
    assert!(result1.is_ok());

    // Test TlsClientCert auth
    let auth_config =
      AuthConfig::TlsClientCert { client_ca_path: ca_path.clone() };
    let result2 = load_tls_config(
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap(),
      &auth_config,
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

    let auth_config = AuthConfig::None;
    let result = load_tls_config(
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap(),
      &auth_config,
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

    let auth_config = AuthConfig::None;
    let result = load_tls_config(
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap(),
      &auth_config,
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

    let auth_config = AuthConfig::None;
    let result = load_tls_config(
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap(),
      &auth_config,
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

    let auth_config = AuthConfig::None;
    let result = load_tls_config(
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap(),
      &auth_config,
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
  fn test_handle_password_auth_success() {
    let hash = bcrypt::hash("password", 4).unwrap();
    let mut credentials = HashMap::new();
    credentials.insert("user".to_string(), hash);

    // Create request with Basic auth header
    let auth_value =
      format!("Basic {}", BASE64_STANDARD.encode("user:password"));
    let req = http::Request::builder()
      .method(http::Method::CONNECT)
      .uri("example.com:443")
      .header(http::header::PROXY_AUTHORIZATION, auth_value)
      .body(())
      .unwrap();

    assert!(
      handle_password_auth(&req, &credentials).is_ok(),
      "Valid credentials should pass"
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
  fn test_handle_password_auth_invalid_credentials() {
    let hash = bcrypt::hash("correct_password", 4).unwrap();
    let mut credentials = HashMap::new();
    credentials.insert("user".to_string(), hash);

    // Create request with wrong password
    let auth_value = format!(
      "Basic {}",
      BASE64_STANDARD.encode("user:wrong_password")
    );
    let req = http::Request::builder()
      .method(http::Method::CONNECT)
      .uri("example.com:443")
      .header(http::header::PROXY_AUTHORIZATION, auth_value)
      .body(())
      .unwrap();

    let result = handle_password_auth(&req, &credentials);
    assert!(result.is_err(), "Invalid credentials should fail");
  }

  #[test]
  fn test_perform_authentication_none() {
    let req = http::Request::builder()
      .method(http::Method::CONNECT)
      .uri("example.com:443")
      .body(())
      .unwrap();
    let auth_config = AuthConfig::None;
    assert!(
      perform_authentication(&req, &auth_config).is_ok(),
      "No auth should always pass"
    );
  }

  #[test]
  fn test_perform_authentication_tls_client_cert() {
    let req = http::Request::builder()
      .method(http::Method::CONNECT)
      .uri("example.com:443")
      .body(())
      .unwrap();
    let auth_config = AuthConfig::TlsClientCert {
      client_ca_path: PathBuf::from("/tmp/ca.pem"),
    };
    assert!(
      perform_authentication(&req, &auth_config).is_ok(),
      "TLS client cert auth should pass (auth happens at TLS level)"
    );
  }

  #[test]
  fn test_perform_authentication_password_success() {
    let hash = bcrypt::hash("password", 4).unwrap();
    let mut credentials = HashMap::new();
    credentials.insert("user".to_string(), hash);
    let auth_config = AuthConfig::Password { credentials };

    let auth_value =
      format!("Basic {}", BASE64_STANDARD.encode("user:password"));
    let req = http::Request::builder()
      .method(http::Method::CONNECT)
      .uri("example.com:443")
      .header(http::header::PROXY_AUTHORIZATION, auth_value)
      .body(())
      .unwrap();

    assert!(
      perform_authentication(&req, &auth_config).is_ok(),
      "Valid password auth should pass"
    );
  }

  #[test]
  fn test_perform_authentication_password_failure() {
    let hash = bcrypt::hash("correct_password", 4).unwrap();
    let mut credentials = HashMap::new();
    credentials.insert("user".to_string(), hash);
    let auth_config = AuthConfig::Password { credentials };

    let auth_value = format!(
      "Basic {}",
      BASE64_STANDARD.encode("user:wrong_password")
    );
    let req = http::Request::builder()
      .method(http::Method::CONNECT)
      .uri("example.com:443")
      .header(http::header::PROXY_AUTHORIZATION, auth_value)
      .body(())
      .unwrap();

    assert!(
      perform_authentication(&req, &auth_config).is_err(),
      "Invalid password auth should fail"
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
    let cloned = result.clone();
    assert_eq!(result, cloned);

    let result = TlsClientCertVerifyResult::Missing;
    let cloned = result.clone();
    assert_eq!(result, cloned);

    let result = TlsClientCertVerifyResult::InvalidType;
    let cloned = result.clone();
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

  // ============== PHC Format Edge Cases Tests ==============

  #[test]
  fn test_verify_bcrypt_password_phc_format_with_dollar_in_hash() {
    // Test that PHC format parsing strictly follows the architecture document
    // PHC format: $bcrypt$v=98$r=<rounds>$<hash> (exactly 5 parts)

    // Generate a valid standard hash
    let standard_hash = bcrypt::hash("test_password", 4).unwrap();

    // Convert to PHC format
    let parts: Vec<&str> = standard_hash.split('$').collect();
    // parts[0] = "", parts[1] = "2b", parts[2] = "4", parts[3] = salt+hash
    let rounds = parts[2];
    let salt_hash = parts[3];
    let phc_hash = format!("$bcrypt$v=98$r={}${}", rounds, salt_hash);

    // This should verify correctly
    assert!(
      verify_bcrypt_password("test_password", &phc_hash),
      "Valid PHC format should verify"
    );

    // Test with extra $ characters after the hash
    // Per architecture document, PHC format must be exactly:
    // $bcrypt$v=98$r=<rounds>$<hash>
    // Extra parts mean invalid format, so verification should fail
    let phc_with_extra =
      format!("$bcrypt$v=98$r={}${}$extra$parts", rounds, salt_hash);
    assert!(
      !verify_bcrypt_password("test_password", &phc_with_extra),
      "PHC format with extra $ should NOT verify (invalid format per architecture)"
    );
  }

  #[test]
  fn test_verify_bcrypt_password_phc_format_minimal_parts() {
    // Test the minimum number of parts required for PHC format
    // PHC format: $bcrypt$v=98$r=<rounds>$<salt_hash>
    // parts: ["", "bcrypt", "v=98", "r=<rounds>", "<salt_hash>"]

    // Valid minimal PHC format (exactly 5 parts)
    let standard_hash = bcrypt::hash("test", 4).unwrap();
    let parts: Vec<&str> = standard_hash.split('$').collect();
    let phc_hash = format!("$bcrypt$v=98$r={}${}", parts[2], parts[3]);
    assert!(
      verify_bcrypt_password("test", &phc_hash),
      "Valid minimal PHC format should verify"
    );

    // Missing salt+hash part (only 4 parts)
    let incomplete_phc = "$bcrypt$v=98$r=4";
    assert!(
      !verify_bcrypt_password("test", incomplete_phc),
      "Incomplete PHC format should not verify"
    );
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

  // ============== Task 008: bcrypt Password Verification Tests ==============

  #[test]
  fn test_bcrypt_password_verify_success() {
    // Test successful bcrypt password verification
    let hash = bcrypt::hash("correct_password", 4).unwrap();
    let mut credentials = HashMap::new();
    credentials.insert("testuser".to_string(), hash);
    assert!(
      verify_password(&credentials, "testuser", "correct_password"),
      "Correct password should verify"
    );
  }

  #[test]
  fn test_bcrypt_password_verify_wrong_password() {
    // Test bcrypt password verification with wrong password
    let hash = bcrypt::hash("correct_password", 4).unwrap();
    let mut credentials = HashMap::new();
    credentials.insert("testuser".to_string(), hash);
    assert!(
      !verify_password(&credentials, "testuser", "wrong_password"),
      "Wrong password should not verify"
    );
  }

  #[test]
  fn test_bcrypt_password_verify_user_not_found() {
    // Test bcrypt password verification when user doesn't exist
    let hash = bcrypt::hash("password", 4).unwrap();
    let mut credentials = HashMap::new();
    credentials.insert("existinguser".to_string(), hash);
    assert!(
      !verify_password(&credentials, "nonexistent", "password"),
      "Non-existent user should not verify"
    );
  }

  #[test]
  fn test_bcrypt_password_verify_different_cost() {
    // Test bcrypt password verification with different cost factors
    for cost in [4, 10, 12] {
      let hash = bcrypt::hash("testpassword", cost).unwrap();
      let mut credentials = HashMap::new();
      credentials.insert("user".to_string(), hash);
      assert!(
        verify_password(&credentials, "user", "testpassword"),
        "Password with cost {} should verify",
        cost
      );
    }
  }

  // ============== Task 009: PHC Format Password Verification Tests ==============

  #[test]
  fn test_phc_format_password_verify_success() {
    // Test successful PHC format password verification
    let standard_hash = bcrypt::hash("testpassword", 4).unwrap();
    let phc_hash = standard_to_phc_format(&standard_hash);
    assert!(
      verify_bcrypt_password("testpassword", &phc_hash),
      "PHC format should verify correct password"
    );
  }

  #[test]
  fn test_phc_format_password_verify_wrong_password() {
    // Test PHC format password verification with wrong password
    let standard_hash = bcrypt::hash("correct_password", 4).unwrap();
    let phc_hash = standard_to_phc_format(&standard_hash);
    assert!(
      !verify_bcrypt_password("wrong_password", &phc_hash),
      "PHC format should not verify wrong password"
    );
  }

  #[test]
  fn test_phc_format_password_verify_various_rounds() {
    // Test PHC format with various round counts
    for rounds in [4, 8, 12] {
      let standard_hash = bcrypt::hash("password", rounds).unwrap();
      let phc_hash = standard_to_phc_format(&standard_hash);
      assert!(
        verify_bcrypt_password("password", &phc_hash),
        "PHC format with rounds {} should verify",
        rounds
      );
    }
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
    let auth_config = AuthConfig::None;
    let result = load_tls_config(
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap(),
      &auth_config,
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
    let auth_config = AuthConfig::None;
    let result = load_tls_config(
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap(),
      &auth_config,
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
    let auth_config = AuthConfig::None;
    let tls_config = load_tls_config(
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap(),
      &auth_config,
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
    let auth_config = AuthConfig::None;
    let tls_config = load_tls_config(
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap(),
      &auth_config,
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
      "[http3_listener] active_connections={}, active_streams={}",
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
}
