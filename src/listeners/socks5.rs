//! SOCKS5 listener implementation.
//!
//! This module provides a SOCKS5 protocol listener that accepts SOCKS5
//! connections and forwards them to an associated Service.
//!
//! # Design Note: Thread Safety
//!
//! Note: The `#![allow(clippy::await_holding_refcell_ref)]` attribute
//! is used because we hold RefCell references across await points in
//! the single-threaded LocalSet context, which is safe.
//!
//! The Listener uses `Socks5UpgradeTrigger::pair()` to create a linked
//! (trigger, upgrade) pair. The `Socks5OnUpgrade` is stored in
//! `http::Extensions` and the `Socks5UpgradeTrigger` is held by the
//! Listener to send SOCKS5 replies based on the Service response.

#![allow(clippy::await_holding_refcell_ref)]

use std::future::Future;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use base64::Engine;
use serde::Deserialize;
use tower::Service;
use tracing::warn;

use crate::config::SerializedArgs;
use crate::http_utils::{BytesBufBodyWrapper, RequestBody};
use crate::listener::{
  BuildListener, Listener, ListenerProps, Listening, TransportLayer,
};
use crate::listeners::utils::LISTENER_SHUTDOWN_TIMEOUT;
use crate::service::Service as RuntimeService;
use crate::shutdown::ShutdownHandle;
use crate::stream::{
  Socks5UpgradeTrigger, http_status_to_socks5_error,
};
use crate::tracker::StreamTracker;

/// Default handshake timeout in seconds.
const DEFAULT_HANDSHAKE_TIMEOUT_SECS: u64 = 3;

/// SOCKS5 listener implementation.
///
/// This listener accepts SOCKS5 connections on configured addresses
/// and forwards them to the associated Service.
pub struct Socks5Listener {
  /// Resolved listening addresses.
  addresses: Vec<SocketAddr>,
  /// Stream tracker for graceful shutdown.
  /// This also serves as the shutdown handle for the listener itself.
  stream_tracker: Rc<StreamTracker>,
  /// Associated service for handling connections.
  service: RuntimeService,
  /// Graceful shutdown timeout.
  graceful_shutdown_timeout: Duration,
  /// Handshake timeout duration.
  handshake_timeout: Duration,
  /// Service name for identification in logs.
  service_name: String,
}

impl Socks5Listener {
  /// Create a new Socks5Listener from parsed configuration.
  ///
  /// # Arguments
  ///
  /// * `addresses` - Network addresses to listen on
  /// * `args` - Parsed listener configuration
  /// * `server_routing_table` - Server routing table
  ///
  /// # Returns
  ///
  /// Returns a `Listener` on success, or an error if all addresses are
  /// invalid.
  ///
  /// # Errors
  ///
  /// Returns an error if:
  /// - All configured addresses are invalid
  /// - Configuration validation fails
  #[allow(clippy::new_ret_no_self)]
  pub fn new(
    addresses: Vec<String>,
    args: Socks5ListenerArgs,
    server_routing_table: Vec<crate::server::Server>,
  ) -> Result<Listener> {
    // Resolve addresses, skipping invalid ones
    let addresses = resolve_addresses(&addresses);

    // Check if all addresses are invalid
    if addresses.is_empty() {
      bail!(
        "all configured addresses are invalid; listener cannot start"
      );
    }

    // Get service from routing table (SOCKS5 doesn't support hostname
    // routing, so we use the first entry's service)
    let service = server_routing_table
      .first()
      .map(|e| e.service.clone())
      .unwrap_or_else(crate::server::placeholder_service);

    let service_name = server_routing_table
      .first()
      .map(|e| e.service_name())
      .unwrap_or_default();

    Ok(Listener::new(Self {
      addresses,
      stream_tracker: Rc::new(StreamTracker::new()),
      service,
      graceful_shutdown_timeout: LISTENER_SHUTDOWN_TIMEOUT,
      handshake_timeout: args.handshake_timeout,
      service_name,
    }))
  }

  /// Create a TCP listener for a single address.
  ///
  /// # Arguments
  ///
  /// * `addr` - Socket address to bind to
  /// * `service` - Service for handling connections
  /// * `stream_tracker` - Tracker for active stream tasks
  /// * `shutdown_handle` - Shutdown notification handle
  /// * `handshake_timeout` - Timeout for SOCKS5 handshake
  /// * `service_name` - Service name for access log
  ///
  /// # Returns
  ///
  /// Returns a future that runs the listener until shutdown.
  fn serve_addr(
    &self,
    addr: SocketAddr,
    service: RuntimeService,
    stream_tracker: Rc<StreamTracker>,
    shutdown_handle: ShutdownHandle,
    handshake_timeout: Duration,
    service_name: String,
  ) -> Result<std::pin::Pin<Box<dyn Future<Output = Result<()>>>>> {
    // Create TCP socket based on address type
    let socket = match addr {
      SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4()?,
      SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6()?,
    };

    // Set socket options
    socket.set_reuseaddr(true)?;
    socket.set_reuseport(true)?;

    // Bind to address
    socket.bind(addr)?;

    // Start listening
    let listener = socket.listen(1024)?;

    let accepting_fut = async move {
      // Log listener startup event (architecture requirement: record
      // listener startup)
      tracing::info!("SOCKS5 listener started on {}", addr);

      // Clone handles for use in accept loop
      let shutdown_handle = shutdown_handle;
      let stream_tracker = stream_tracker;
      let service = service;
      let service_name = service_name;

      // Define accepting and shutdown as closures for reuse in loop
      let accepting = || async {
        match listener.accept().await {
          Err(e) => {
            // Distinguish between fatal and temporary errors
            // Fatal errors should exit the accept loop
            if is_fatal_accept_error(&e) {
              tracing::error!(
                "fatal accept error on {}: {}, shutting down listener",
                addr,
                e
              );
              // Return true to signal fatal error
              true
            } else {
              // Temporary error, log and continue
              tracing::warn!(
                "temporary accept error on {}: {}, continuing",
                addr,
                e
              );
              false
            }
          }
          Ok((stream, peer_addr)) => {
            tracing::info!(
              "SOCKS5 connection established from {}",
              peer_addr
            );

            // Clone handles for use in connection handler
            let mut service = service.clone();
            let service_name = service_name.clone();

            // Register connection handler
            stream_tracker.register(async move {
              // Capture local address before handshake consumes the
              // stream
              let local_addr = match stream.local_addr() {
                Ok(addr) => addr,
                Err(e) => {
                  tracing::warn!(
                    "SOCKS5 failed to get local addr from {}: {}",
                    peer_addr,
                    e
                  );
                  return;
                }
              };

              // Step 1: Perform SOCKS5 handshake with timeout
              // protection
              let handshake_result = match perform_handshake(
                stream,
                handshake_timeout,
              )
              .await
              {
                Ok(result) => result,
                Err(e) => {
                  // Handle handshake errors
                  match e {
                    HandshakeError::Timeout => {
                      // Timeout - do not send response, just close
                      // connection
                      tracing::warn!(
                        "SOCKS5 handshake timeout from {}",
                        peer_addr
                      );
                    }
                    HandshakeError::InvalidVersion(v) => {
                      // Invalid version - do not send response
                      tracing::warn!(
                        "SOCKS5 invalid version {} from {}",
                        v,
                        peer_addr
                      );
                    }
                    HandshakeError::MethodNotAcceptable(_) => {
                      // METHOD=0xFF was already sent
                      tracing::warn!(
                        "SOCKS5 method not acceptable from {}",
                        peer_addr
                      );
                    }
                    HandshakeError::ClientDisconnected => {
                      tracing::info!(
                        "SOCKS5 connection disconnected from {}",
                        peer_addr
                      );
                    }
                    HandshakeError::IoError(e) => {
                      tracing::warn!(
                        "SOCKS5 handshake IO error from {}: {}",
                        peer_addr,
                        e
                      );
                    }
                  }
                  // Connection is already closed by the error handler
                  return;
                }
              };

              // Step 2: Read command and target address
              let command_result =
                match read_command_and_target(handshake_result.proto)
                  .await
                {
                  Ok(result) => result,
                  Err(e) => {
                    // Command error responses are already sent
                    match e {
                      CommandError::CommandNotSupported { command } => {
                        tracing::warn!(
                          "SOCKS5 command {} not supported from {}",
                          command,
                          peer_addr
                        );
                      }
                      CommandError::UnknownCommand { command } => {
                        tracing::warn!(
                          "SOCKS5 unknown command {} from {}",
                          command,
                          peer_addr
                        );
                      }
                      CommandError::ClientDisconnected => {
                        tracing::warn!(
                          "SOCKS5 client disconnected during command \
                           processing from {}",
                          peer_addr
                        );
                      }
                      CommandError::IoError(e) => {
                        tracing::warn!(
                          "SOCKS5 command read error from {}: {}",
                          peer_addr,
                          e
                        );
                      }
                    }
                    return;
                  }
                };

              // Step 3: Create upgrade pair
              let (trigger, on_upgrade) =
                Socks5UpgradeTrigger::pair(command_result.proto);

              // Step 4: Build HTTP CONNECT request with on_upgrade in
              // extensions
              let (host, port) =
                extract_host_port(&command_result.target_addr);
              let uri = format_connect_uri(&host, port);

              let mut request = http::Request::builder()
                .method(http::Method::CONNECT)
                .uri(&uri)
                .version(http::Version::HTTP_11)
                .body(RequestBody::new(BytesBufBodyWrapper::new(
                  http_body_util::Empty::<bytes::Bytes>::new(),
                )))
                .expect("failed to build CONNECT request");

              // Inject SOCKS5 credentials as Proxy-Authorization header
              // so the auth middleware can verify them
              if let (Some(username), Some(password)) =
                (&handshake_result.username, &handshake_result.password)
              {
                let credentials =
                  base64::engine::general_purpose::STANDARD
                    .encode(format!("{username}:{password}"));
                request.headers_mut().insert(
                  "Proxy-Authorization",
                  http::HeaderValue::from_str(&format!(
                    "Basic {credentials}"
                  ))
                  .unwrap(),
                );
              }

              request.extensions_mut().insert(on_upgrade);

              // Build RequestContext with connection-level keys and
              // insert into request extensions. Auth and
              // access logging are now handled by the
              // plugin layer in the service pipeline.
              let ctx = super::utils::build_request_context(
                &peer_addr,
                &local_addr,
                &service_name,
              );
              request.extensions_mut().insert(ctx);

              // Step 5: Call the associated Service
              let result = service.call(request).await;

              // Step 6: Based on Response, send SOCKS5 reply via
              // trigger
              match result {
                Ok(resp) => {
                  if resp.status() == http::StatusCode::OK {
                    if let Err(e) = trigger.send_success().await {
                      tracing::warn!(
                        "SOCKS5 failed to send success reply to {}: {}",
                        peer_addr,
                        e
                      );
                    }
                  } else {
                    let error =
                      http_status_to_socks5_error(resp.status());
                    if let Err(e) = trigger.send_error(error).await {
                      tracing::warn!(
                        "SOCKS5 failed to send error reply to {}: {}",
                        peer_addr,
                        e
                      );
                    }
                  }
                }
                Err(e) => {
                  tracing::warn!(
                    "connection from {} on {}: {}",
                    peer_addr,
                    local_addr,
                    e
                  );
                  if let Err(send_err) = trigger
                    .send_error(fast_socks5::ReplyError::GeneralFailure)
                    .await
                  {
                    tracing::warn!(
                      "SOCKS5 failed to send error reply to {}: {}",
                      peer_addr,
                      send_err
                    );
                  }
                }
              }
            });
            false
          }
        }
      };

      let shutdown = || async {
        shutdown_handle.notified().await;
      };

      // Main accept loop
      loop {
        tokio::select! {
          fatal = accepting() => {
            if fatal {
              // Fatal error, exit loop
              break;
            }
            // Continue accepting connections
          }
          _ = shutdown() => {
            // Graceful shutdown for the TcpListener
            tracing::info!("SOCKS5 listener on {} shutting down", addr);
            break;
          }
        }
      }

      // Here the TcpListener is dropped, so listening socket is closed.
      Ok(())
    };

    Ok(Box::pin(accepting_fut))
  }
}

impl Listening for Socks5Listener {
  /// Start the SOCKS5 listener.
  ///
  /// # Returns
  ///
  /// Returns a future that completes when the listener shuts down.
  /// If all addresses fail to bind, returns an error immediately.
  fn start(
    &self,
  ) -> std::pin::Pin<Box<dyn Future<Output = Result<()>>>> {
    use std::future;

    // Get the shared shutdown handle from stream tracker
    let shutdown_handle = self.stream_tracker.shutdown_handle();

    // Check if shutdown was already triggered before we even started
    if shutdown_handle.is_shutdown() {
      // Return immediately without starting any listeners
      return Box::pin(future::ready(Ok(())));
    }

    // Track which addresses successfully started
    let mut listening_tasks = Vec::new();

    for addr in &self.addresses {
      let addr = *addr;
      let service = self.service.clone();
      let stream_tracker = self.stream_tracker.clone();
      let shutdown_handle = shutdown_handle.clone();
      let handshake_timeout = self.handshake_timeout;
      let service_name = self.service_name.clone();

      match self.serve_addr(
        addr,
        service,
        stream_tracker,
        shutdown_handle,
        handshake_timeout,
        service_name,
      ) {
        Ok(fut) => {
          listening_tasks.push(fut);
        }
        Err(e) => {
          tracing::error!(
            "failed to start listener on {}: {}",
            addr,
            e
          );
          // Continue trying other addresses
        }
      }
    }

    // Check if any listeners started successfully
    if listening_tasks.is_empty() {
      return Box::pin(future::ready(Err(anyhow::anyhow!(
        "failed to start any SOCKS5 listener; all addresses failed to \
         bind"
      ))));
    }

    let stream_tracker = self.stream_tracker.clone();
    let graceful_timeout = self.graceful_shutdown_timeout;

    // Spawn all listening tasks in the stream tracker
    // We use a separate JoinSet for listening tasks
    let listening_set = std::rc::Rc::new(std::cell::RefCell::new(
      tokio::task::JoinSet::new(),
    ));

    for task in listening_tasks {
      listening_set.borrow_mut().spawn_local(task);
    }

    Box::pin(async move {
      // Wait for shutdown notification
      shutdown_handle.notified().await;

      // Wait for all listening tasks to complete
      while let Some(res) = listening_set.borrow_mut().join_next().await
      {
        match res {
          Err(e) => {
            tracing::error!("listening join error: {}", e);
          }
          Ok(res) => {
            if let Err(e) = res {
              tracing::error!("listening error: {}", e);
            }
          }
        }
      }

      // Wait for active connections with timeout
      let wait_result = tokio::time::timeout(graceful_timeout, async {
        stream_tracker.wait_shutdown().await;
      })
      .await;

      if wait_result.is_err() {
        // Timeout expired, force close remaining connections
        tracing::warn!(
          "graceful shutdown timeout ({:?}) expired, aborting {} \
           remaining connections",
          graceful_timeout,
          stream_tracker.active_count()
        );
        stream_tracker.abort_all();
      }

      Ok(())
    })
  }

  /// Stop the SOCKS5 listener.
  ///
  /// Triggers graceful shutdown notification.
  fn stop(&self) {
    self.stream_tracker.shutdown();
  }
}

/// Clone implementation for Socks5Listener.
///
/// This is needed because we need to create multiple listeners
/// (one per address), but StreamTracker uses Rc internally.
impl Clone for Socks5Listener {
  fn clone(&self) -> Self {
    Self {
      addresses: self.addresses.clone(),
      stream_tracker: self.stream_tracker.clone(),
      service: self.service.clone(),
      graceful_shutdown_timeout: self.graceful_shutdown_timeout,
      handshake_timeout: self.handshake_timeout,
      service_name: self.service_name.clone(),
    }
  }
}

/// Result of a successful SOCKS5 handshake.
///
/// Contains the authenticated protocol state and optional username
/// if password authentication was used.
pub struct HandshakeResult {
  /// The authenticated SOCKS5 protocol state.
  pub proto: fast_socks5::server::Socks5ServerProtocol<
    tokio::net::TcpStream,
    fast_socks5::server::states::Authenticated,
  >,
  /// The username if password authentication was used.
  pub username: Option<String>,
  /// The password if password authentication was used.
  pub password: Option<String>,
}

impl std::fmt::Debug for HandshakeResult {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("HandshakeResult")
      .field("username", &self.username)
      .finish_non_exhaustive()
  }
}

/// Error during SOCKS5 handshake.
///
/// This enum represents the various errors that can occur during
/// the SOCKS5 handshake process.
#[derive(Debug)]
pub enum HandshakeError {
  /// Handshake timed out.
  ///
  /// According to architecture requirements, no response should be sent
  /// when handshake times out. The connection should be closed
  /// directly.
  Timeout,

  /// Invalid SOCKS version number.
  ///
  /// According to RFC 1928, we should not send a response for invalid
  /// version numbers, just close the connection.
  InvalidVersion(u8),

  /// Authentication method not acceptable.
  ///
  /// The client requested authentication methods that the server
  /// doesn't support. According to RFC 1928, we should send
  /// METHOD=0xFF and close the connection.
  MethodNotAcceptable(Vec<u8>),

  /// Client disconnected during handshake.
  ClientDisconnected,

  /// IO error during handshake.
  IoError(std::io::Error),
}

impl std::fmt::Display for HandshakeError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Timeout => write!(f, "handshake timed out"),
      Self::InvalidVersion(v) => {
        write!(f, "invalid SOCKS version: {}", v)
      }
      Self::MethodNotAcceptable(methods) => {
        write!(f, "authentication method not acceptable: {:?}", methods)
      }
      Self::ClientDisconnected => {
        write!(f, "client disconnected during handshake")
      }
      Self::IoError(e) => write!(f, "IO error during handshake: {}", e),
    }
  }
}

impl std::error::Error for HandshakeError {}

impl From<std::io::Error> for HandshakeError {
  fn from(e: std::io::Error) -> Self {
    // Check for specific error kinds
    use std::io::ErrorKind;
    match e.kind() {
      ErrorKind::UnexpectedEof
      | ErrorKind::ConnectionReset
      | ErrorKind::BrokenPipe => Self::ClientDisconnected,
      _ => Self::IoError(e),
    }
  }
}

/// Error during SOCKS5 command processing.
///
/// This enum represents the various errors that can occur during
/// the SOCKS5 command processing phase.
#[derive(Debug)]
pub enum CommandError {
  /// Command not supported (BIND or UDP ASSOCIATE).
  ///
  /// According to architecture requirements, we send REP=0x07
  /// and close the connection.
  CommandNotSupported {
    /// The command that was not supported.
    command: u8,
  },

  /// Unknown command code.
  ///
  /// The command code is not recognized as a valid SOCKS5 command.
  UnknownCommand {
    /// The unknown command code.
    command: u8,
  },

  /// Client disconnected during command processing.
  ClientDisconnected,

  /// IO error during command processing.
  IoError(std::io::Error),
}

impl std::fmt::Display for CommandError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::CommandNotSupported { command } => {
        write!(f, "command not supported: 0x{:02x}", command)
      }
      Self::UnknownCommand { command } => {
        write!(f, "unknown command: 0x{:02x}", command)
      }
      Self::ClientDisconnected => {
        write!(f, "client disconnected during command processing")
      }
      Self::IoError(e) => {
        write!(f, "IO error during command processing: {}", e)
      }
    }
  }
}

impl std::error::Error for CommandError {}

impl From<std::io::Error> for CommandError {
  fn from(e: std::io::Error) -> Self {
    use std::io::ErrorKind;
    match e.kind() {
      ErrorKind::UnexpectedEof
      | ErrorKind::ConnectionReset
      | ErrorKind::BrokenPipe => Self::ClientDisconnected,
      _ => Self::IoError(e),
    }
  }
}

impl From<HandshakeError> for CommandError {
  fn from(e: HandshakeError) -> Self {
    match e {
      HandshakeError::Timeout => Self::IoError(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "handshake timed out",
      )),
      HandshakeError::InvalidVersion(v) => {
        Self::IoError(std::io::Error::new(
          std::io::ErrorKind::InvalidData,
          format!("invalid SOCKS version: {}", v),
        ))
      }
      HandshakeError::MethodNotAcceptable(_) => Self::IoError(
        std::io::Error::other("authentication method not acceptable"),
      ),
      HandshakeError::ClientDisconnected => Self::ClientDisconnected,
      HandshakeError::IoError(e) => Self::from(e),
    }
  }
}

impl From<fast_socks5::server::SocksServerError> for CommandError {
  fn from(e: fast_socks5::server::SocksServerError) -> Self {
    use fast_socks5::server::SocksServerError;
    match e {
      SocksServerError::UnknownCommand(cmd) => {
        Self::UnknownCommand { command: cmd }
      }
      SocksServerError::AuthMethodUnacceptable(_) => {
        Self::IoError(std::io::Error::other(
          "unexpected auth error during command processing",
        ))
      }
      SocksServerError::Io { source, .. } => Self::from(source),
      _ => Self::IoError(std::io::Error::other(e.to_string())),
    }
  }
}

/// Result of a successful SOCKS5 command read.
///
/// Contains the protocol state after command reading and the target
/// address. Note: We don't store the command because we only support
/// CONNECT.
pub struct CommandResult {
  /// The protocol state after command has been read.
  pub proto: fast_socks5::server::Socks5ServerProtocol<
    tokio::net::TcpStream,
    fast_socks5::server::states::CommandRead,
  >,
  /// The target address from the SOCKS5 request.
  pub target_addr: fast_socks5::util::target_addr::TargetAddr,
}

impl std::fmt::Debug for CommandResult {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("CommandResult")
      .field("target_addr", &self.target_addr)
      .finish_non_exhaustive()
  }
}

/// Reads SOCKS5 command and extracts target address.
///
/// This function reads the SOCKS5 command request from the client
/// and extracts the target address. It handles:
/// - CONNECT command: Returns the target address
/// - BIND command: Sends REP=0x07 and returns error
/// - UDP ASSOCIATE command: Sends REP=0x07 and returns error
///
/// # Arguments
///
/// * `proto` - The authenticated SOCKS5 protocol state
///
/// # Returns
///
/// On success, returns a `CommandResult` containing the protocol state
/// and target address. The protocol state is in `CommandRead` state,
/// ready for the Service to send the appropriate response.
///
/// On failure, returns a `CommandError`. The appropriate response
/// has already been sent to the client for these errors:
/// - `CommandNotSupported`: REP=0x07 was sent
///
/// # Example
///
/// ```ignore
/// let command_result = read_command_and_target(handshake_result.proto).await?;
/// // command_result.target_addr contains the target address
/// // command_result.proto can be used to send response
/// ```
pub async fn read_command_and_target(
  proto: fast_socks5::server::Socks5ServerProtocol<
    tokio::net::TcpStream,
    fast_socks5::server::states::Authenticated,
  >,
) -> Result<CommandResult, CommandError> {
  // Read the command request
  let (proto, cmd, target_addr) = proto.read_command().await?;

  // Check command type
  match cmd {
    fast_socks5::Socks5Command::TCPConnect => {
      // CONNECT command - this is what we support
      tracing::info!("SOCKS5 CONNECT request to {}", target_addr);
      Ok(CommandResult { proto, target_addr })
    }
    fast_socks5::Socks5Command::TCPBind => {
      // BIND command - not supported
      // Send REP=0x07 (command not supported)
      proto
        .reply_error(&fast_socks5::ReplyError::CommandNotSupported)
        .await?;

      tracing::warn!(
        "SOCKS5 BIND command not supported, sent REP=0x07"
      );

      Err(CommandError::CommandNotSupported {
        command: fast_socks5::consts::SOCKS5_CMD_TCP_BIND,
      })
    }
    fast_socks5::Socks5Command::UDPAssociate => {
      // UDP ASSOCIATE command - not supported
      // Send REP=0x07 (command not supported)
      proto
        .reply_error(&fast_socks5::ReplyError::CommandNotSupported)
        .await?;

      tracing::warn!(
        "SOCKS5 UDP ASSOCIATE command not supported, sent REP=0x07"
      );

      Err(CommandError::CommandNotSupported {
        command: fast_socks5::consts::SOCKS5_CMD_UDP_ASSOCIATE,
      })
    }
  }
}

impl From<fast_socks5::server::SocksServerError> for HandshakeError {
  fn from(e: fast_socks5::server::SocksServerError) -> Self {
    use fast_socks5::server::SocksServerError;
    match e {
      SocksServerError::UnsupportedSocksVersion(v) => {
        Self::InvalidVersion(v)
      }
      SocksServerError::AuthMethodUnacceptable(methods) => {
        Self::MethodNotAcceptable(methods)
      }
      SocksServerError::Io { source, .. } => Self::from(source),
      _ => Self::IoError(std::io::Error::other(e.to_string())),
    }
  }
}

/// Performs SOCKS5 handshake with timeout protection.
///
/// This function executes the complete SOCKS5 handshake process:
/// 1. Version negotiation
/// 2. Authentication method selection
/// 3. Authentication (if required)
///
/// # Arguments
///
/// * `stream` - The TCP stream from the client
/// * `timeout` - The maximum time allowed for handshake
///
/// # Returns
///
/// On success, returns a `HandshakeResult` containing the authenticated
/// protocol state and optional username.
///
/// On failure, returns a `HandshakeError`. The caller is responsible
/// for sending appropriate responses based on the error type:
/// - `Timeout`: Do not send response, close connection
/// - `InvalidVersion`: Do not send response, close connection
/// - `MethodNotAcceptable`: METHOD=0xFF was already sent
/// - `ClientDisconnected`: Connection already closed
/// - `IoError`: Connection should be closed
///
/// # Example
///
/// ```ignore
/// use tokio::time::timeout;
///
/// let result = perform_handshake(stream, Duration::from_secs(3), &user_password_auth).await;
/// match result {
///   Ok(handshake_result) => {
///     // Handshake succeeded, continue with command reading
///   }
///   Err(HandshakeError::Timeout) => {
///     // Do not send response, just close connection
///   }
///   Err(e) => {
///     // Handle other errors
///   }
/// }
/// ```
pub async fn perform_handshake(
  stream: tokio::net::TcpStream,
  timeout_duration: Duration,
) -> Result<HandshakeResult, HandshakeError> {
  // Wrap the entire handshake process with timeout
  let handshake_fut = async {
    // Start SOCKS5 protocol
    let proto =
      fast_socks5::server::Socks5ServerProtocol::start(stream);

    // Offer both No-Auth and Password methods, accept whichever
    // the client chooses. Credential verification is deferred to
    // the auth middleware in the service pipeline.
    let auth_state = proto
      .negotiate_auth(
        fast_socks5::server::StandardAuthentication::allow_no_auth(
          true,
        ),
      )
      .await?;

    match auth_state {
      fast_socks5::server::StandardAuthenticationStarted::NoAuthentication(
        none_state,
      ) => {
        let authenticated =
          fast_socks5::server::Socks5ServerProtocol::finish_auth(
            none_state,
          );
        Ok(HandshakeResult {
          proto: authenticated,
          username: None,
          password: None,
        })
      }
      fast_socks5::server::StandardAuthenticationStarted::PasswordAuthentication(
        auth_state,
      ) => {
        let (username, password, auth_impl) =
          auth_state.read_username_password().await?;

        // Always accept - verification is handled by auth middleware
        let finished = auth_impl.accept().await?;
        let authenticated =
          fast_socks5::server::Socks5ServerProtocol::finish_auth(
            finished,
          );

        tracing::info!(
          "SOCKS5 password auth received for user '{}'",
          username
        );

        Ok(HandshakeResult {
          proto: authenticated,
          username: Some(username),
          password: Some(password),
        })
      }
    }
  };

  // Apply timeout
  match tokio::time::timeout(timeout_duration, handshake_fut).await {
    Ok(result) => result,
    Err(_) => {
      tracing::warn!(
        "SOCKS5 handshake timed out after {:?}",
        timeout_duration
      );
      Err(HandshakeError::Timeout)
    }
  }
}

/// Default handshake timeout.
const DEFAULT_HANDSHAKE_TIMEOUT: Duration =
  Duration::from_secs(DEFAULT_HANDSHAKE_TIMEOUT_SECS);

/// SOCKS5 listener configuration arguments.
#[derive(Clone, Debug)]
pub struct Socks5ListenerArgs {
  /// Handshake timeout duration.
  pub handshake_timeout: Duration,
}

impl Default for Socks5ListenerArgs {
  fn default() -> Self {
    Self { handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT }
  }
}

/// Parses SOCKS5 listener configuration from YAML.
///
/// # Errors
///
/// Returns an error if:
/// - `handshake_timeout` is not a valid humantime format (e.g., "10s")
/// - Any other YAML parsing error occurs
pub fn parse_config(
  args: SerializedArgs,
) -> Result<Socks5ListenerArgs> {
  #[derive(Deserialize, Debug)]
  #[serde(deny_unknown_fields)]
  struct ConfigYaml {
    #[serde(
      with = "humantime_serde",
      default = "default_handshake_timeout"
    )]
    handshake_timeout: Duration,
  }

  fn default_handshake_timeout() -> Duration {
    DEFAULT_HANDSHAKE_TIMEOUT
  }

  let config: ConfigYaml = serde_yaml::from_value(args)
    .context("failed to parse SOCKS5 listener config")?;

  Ok(Socks5ListenerArgs { handshake_timeout: config.handshake_timeout })
}

/// Determines if an accept error is fatal and should stop the listener.
///
/// Fatal errors indicate a permanent problem that cannot be recovered
/// from by continuing to accept connections. Temporary errors may
/// resolve on retry.
///
/// # Fatal errors
///
/// - `InvalidInput`: Invalid input parameter (bug in code)
/// - `InvalidData`: Invalid data received
/// - `NotFound`: Resource not found (listener socket closed)
/// - `PermissionDenied`: Permission denied (SELinux/AppArmor denial, fd
///   permission)
///
/// # Temporary errors
///
/// - `WouldBlock`: Would block (should not happen in async)
/// - `Interrupted`: Interrupted by signal
/// - Connection reset, broken pipe, etc.: Network-level temporary
///   issues
fn is_fatal_accept_error(e: &std::io::Error) -> bool {
  use std::io::ErrorKind;
  matches!(
    e.kind(),
    ErrorKind::InvalidInput
      | ErrorKind::InvalidData
      | ErrorKind::NotFound
      | ErrorKind::PermissionDenied
  )
}

/// Resolves address strings to SocketAddr, logging warnings for invalid
/// ones.
///
/// # Arguments
///
/// * `addresses` - List of address strings to parse
///
/// # Returns
///
/// Vector of successfully parsed SocketAddr values.
pub fn resolve_addresses(addresses: &[String]) -> Vec<SocketAddr> {
  addresses
    .iter()
    .filter_map(|s| {
      s.parse()
        .inspect_err(|e| warn!("address '{}' invalid: {}", s, e))
        .ok()
    })
    .collect()
}

/// Formats a host and port for HTTP CONNECT URI.
///
/// IPv6 addresses are wrapped in square brackets.
///
/// # Arguments
///
/// * `host` - The host (IP address or domain)
/// * `port` - The port number
///
/// # Returns
///
/// Formatted URI string for HTTP CONNECT request.
fn format_connect_uri(host: &str, port: u16) -> String {
  // Check if already bracketed (e.g., "[::1]")
  if host.starts_with('[') {
    return format!("{}:{}", host, port);
  }

  // Try to parse as IP address
  if let Ok(addr) = host.parse::<std::net::IpAddr>() {
    match addr {
      std::net::IpAddr::V4(_) => format!("{}:{}", host, port),
      std::net::IpAddr::V6(_) => format!("[{}]:{}", host, port),
    }
  } else {
    // Domain name
    format!("{}:{}", host, port)
  }
}

/// Extracts host and port from TargetAddr.
///
/// # Arguments
///
/// * `target_addr` - The target address
///
/// # Returns
///
/// Tuple of (host_string, port).
fn extract_host_port(
  target_addr: &fast_socks5::util::target_addr::TargetAddr,
) -> (String, u16) {
  match target_addr {
    fast_socks5::util::target_addr::TargetAddr::Ip(addr) => {
      (addr.ip().to_string(), addr.port())
    }
    fast_socks5::util::target_addr::TargetAddr::Domain(
      domain,
      port,
    ) => (domain.clone(), *port),
  }
}

/// Plugin listener name.
pub fn listener_name() -> &'static str {
  "socks5"
}

/// Get listener properties for conflict detection.
pub fn props() -> ListenerProps {
  ListenerProps {
    transport_layer: TransportLayer::Tcp,
    supports_hostname_routing: false,
  }
}

/// Creates a listener builder.
///
/// Returns a builder function that parses configuration and creates
/// a Socks5Listener instance.
pub fn create_listener_builder() -> Box<dyn BuildListener> {
  Box::new(
    |addresses: Vec<String>,
     args: SerializedArgs,
     server_routing_table: Vec<crate::server::Server>| {
      // Parse configuration
      let listener_args = parse_config(args)?;

      // Create listener
      Socks5Listener::new(
        addresses,
        listener_args,
        server_routing_table,
      )
    },
  )
}

#[cfg(test)]
mod tests {
  use super::*;

  // ========== Socks5ListenerArgs Tests ==========

  #[test]
  fn test_socks5_listener_args_default() {
    let args = Socks5ListenerArgs::default();
    assert_eq!(
      args.handshake_timeout,
      Duration::from_secs(DEFAULT_HANDSHAKE_TIMEOUT_SECS)
    );
  }

  // ========== parse_config Tests ==========

  #[test]
  fn test_parse_config_valid_minimal() {
    let yaml = serde_yaml::from_str(r#"{}"#).unwrap();

    let args = parse_config(yaml).unwrap();
    assert_eq!(
      args.handshake_timeout,
      Duration::from_secs(DEFAULT_HANDSHAKE_TIMEOUT_SECS)
    );
  }

  #[test]
  fn test_parse_config_valid_with_timeout() {
    let yaml = serde_yaml::from_str(
      r#"
handshake_timeout: "5s"
"#,
    )
    .unwrap();

    let args = parse_config(yaml).unwrap();
    assert_eq!(args.handshake_timeout, Duration::from_secs(5));
  }

  // ========== Helper function tests ==========

  #[test]
  fn test_resolve_addresses_valid() {
    let addresses = vec!["127.0.0.1:1080".to_string()];
    let resolved = resolve_addresses(&addresses);
    assert_eq!(resolved.len(), 1);
  }

  #[test]
  fn test_resolve_addresses_invalid() {
    let addresses = vec!["invalid".to_string()];
    let resolved = resolve_addresses(&addresses);
    assert!(resolved.is_empty());
  }

  #[test]
  fn test_format_connect_uri_ipv4() {
    let uri = format_connect_uri("192.168.1.1", 443);
    assert_eq!(uri, "192.168.1.1:443");
  }

  #[test]
  fn test_format_connect_uri_ipv6() {
    let uri = format_connect_uri("::1", 443);
    assert_eq!(uri, "[::1]:443");
  }

  #[test]
  fn test_format_connect_uri_domain() {
    let uri = format_connect_uri("example.com", 443);
    assert_eq!(uri, "example.com:443");
  }

  #[test]
  fn test_parse_config_invalid_handshake_timeout() {
    let yaml = serde_yaml::from_str(
      r#"
handshake_timeout: "not_a_duration"
"#,
    )
    .unwrap();

    let result = parse_config(yaml);
    assert!(result.is_err(), "Should reject invalid duration format");
  }

  #[test]
  fn test_listener_name() {
    assert_eq!(listener_name(), "socks5");
  }
}
