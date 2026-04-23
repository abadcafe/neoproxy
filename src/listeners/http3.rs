#![allow(clippy::await_holding_refcell_ref)]
use std::cell::RefCell;
use std::fs;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use bytes::{Buf, Bytes};
use h3::server;
use http_body_util::BodyExt;
use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::CertificateDer;
use serde::Deserialize;
use tokio::net;
use tokio::task::JoinSet;
use tracing::{info, warn};

use crate::auth::{
  ClientCertAuth, ListenerAuthConfig, UserPasswordAuth,
};
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

/// Perform application-layer authentication
///
/// Returns Ok(()) if authentication succeeds or no auth needed,
/// Err with error message otherwise.
fn perform_application_auth(
  req: &http::Request<()>,
  user_password_auth: &UserPasswordAuth,
) -> Result<()> {
  user_password_auth
    .verify(req)
    .map_err(|e| anyhow!("Proxy Authentication Required - {}", e))
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
  user_password_auth: &UserPasswordAuth,
) -> std::result::Result<String, ValidationError> {
  // Step 1: Validate CONNECT method
  if let Err(e) = validate_connect_method(req) {
    return Err(ValidationError::MethodNotAllowed(e.to_string()));
  }

  // Step 2: Perform application-layer authentication
  if let Err(e) = perform_application_auth(req, user_password_auth) {
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
  user_password_auth: UserPasswordAuth,
  shutdown_handle: plugin::ShutdownHandle,
) where
  S: h3::quic::BidiStream<Bytes> + Send + 'static,
  <S as h3::quic::BidiStream<Bytes>>::SendStream: Send,
  <S as h3::quic::BidiStream<Bytes>>::RecvStream: Send,
{
  // Phase 1: Validate request
  let target_addr =
    match validate_connect_request(&req, &user_password_auth) {
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
) {
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
        stream_tracker.register(async move {
          match resolver.resolve_request().await {
            Ok((req, stream)) => {
              handle_h3_stream(
                req,
                stream,
                service,
                user_password_auth,
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
      &args.cert_path,
      &args.key_path,
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

            tracker_for_register.register_connection(async move {
              match conn.await {
                Ok(quinn_conn) => {
                  handle_h3_connection(
                    quinn_conn,
                    service,
                    user_password_auth_for_conn,
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
  use crate::auth::listener_auth_config::UserCredential;
  use base64::{
    Engine, engine::general_purpose::STANDARD as BASE64_STANDARD,
  };
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

  // ============== ListenerAuthConfig Tests ==============

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
}
