//! SOCKS5 listener implementation.
//!
//! This module provides a SOCKS5 protocol listener that accepts SOCKS5
//! connections and forwards them to an associated Service.
//!
//! # Design Note: Thread Safety
//!
//! Note: The `#![allow(clippy::await_holding_refcell_ref)]` attribute is
//! used because we hold RefCell references across await points in the
//! single-threaded LocalSet context, which is safe.
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
use serde::Deserialize;
use tracing::warn;

use crate::auth::{ListenerAuthConfig, UserPasswordAuth};
use crate::plugin;
use crate::shutdown::StreamTracker;
use crate::stream::{
  Socks5UpgradeTrigger, http_status_to_socks5_error,
};
use tower::Service;

/// Listener shutdown timeout in seconds.
/// This is the timeout for Phase 1 of graceful shutdown.
const LISTENER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);

/// Default handshake timeout in seconds.
const DEFAULT_HANDSHAKE_TIMEOUT_SECS: u64 = 10;

/// Monitoring log interval in seconds.
const MONITORING_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// SOCKS5 listener implementation.
///
/// This listener accepts SOCKS5 connections on configured addresses
/// and forwards them to the associated Service.
pub struct Socks5Listener {
  /// Resolved listening addresses.
  addresses: Vec<SocketAddr>,
  /// Connection tracker for graceful shutdown.
  /// This also serves as the shutdown handle for the listener itself.
  connection_tracker: Rc<StreamTracker>,
  /// Associated service for handling connections.
  service: plugin::Service,
  /// Graceful shutdown timeout.
  graceful_shutdown_timeout: Duration,
  /// Handshake timeout duration.
  handshake_timeout: Duration,
  /// User password authentication.
  user_password_auth: UserPasswordAuth,
  /// Access log writer for logging request/response information.
  access_log_writer: Option<crate::access_log::AccessLogWriter>,
  /// Service name for identification in logs.
  service_name: String,
}

impl Socks5Listener {
  /// Create a new Socks5Listener from parsed configuration.
  ///
  /// # Arguments
  ///
  /// * `args` - Parsed listener configuration
  /// * `svc` - Associated service for handling connections
  ///
  /// # Returns
  ///
  /// Returns a `Listener` on success, or an error if all addresses are invalid.
  ///
  /// # Errors
  ///
  /// Returns an error if:
  /// - All configured addresses are invalid
  /// - Configuration validation fails
  #[allow(clippy::new_ret_no_self)]
  pub fn new(
    args: Socks5ListenerArgs,
    svc: plugin::Service,
    ctx: plugin::ListenerBuildContext,
  ) -> Result<plugin::Listener> {
    // Resolve addresses, skipping invalid ones
    let addresses = resolve_addresses(&args.addresses);

    // Check if all addresses are invalid
    if addresses.is_empty() {
      bail!(
        "all configured addresses are invalid; listener cannot start"
      );
    }

    Ok(plugin::Listener::new(Self {
      addresses,
      connection_tracker: Rc::new(StreamTracker::new()),
      service: svc,
      graceful_shutdown_timeout: LISTENER_SHUTDOWN_TIMEOUT,
      handshake_timeout: args.handshake_timeout,
      user_password_auth: args.user_password_auth,
      access_log_writer: ctx.access_log_writer,
      service_name: ctx.service_name,
    }))
  }

  /// Create a TCP listener for a single address.
  ///
  /// # Arguments
  ///
  /// * `addr` - Socket address to bind to
  /// * `service` - Service for handling connections
  /// * `connection_tracker` - Tracker for active connections
  /// * `shutdown_handle` - Shutdown notification handle
  /// * `handshake_timeout` - Timeout for SOCKS5 handshake
  /// * `user_password_auth` - User password authentication
  /// * `access_log_writer` - Access log writer (optional)
  /// * `service_name` - Service name for access log
  ///
  /// # Returns
  ///
  /// Returns a future that runs the listener until shutdown.
  fn serve_addr(
    &self,
    addr: SocketAddr,
    service: plugin::Service,
    connection_tracker: Rc<StreamTracker>,
    shutdown_handle: plugin::ShutdownHandle,
    handshake_timeout: Duration,
    user_password_auth: UserPasswordAuth,
    access_log_writer: Option<crate::access_log::AccessLogWriter>,
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
      // Log listener startup event (architecture requirement: record listener startup)
      tracing::info!("SOCKS5 listener started on {}", addr);

      // Clone handles for use in accept loop
      let shutdown_handle = shutdown_handle;
      let connection_tracker = connection_tracker;
      let service = service;
      let access_log_writer = access_log_writer;
      let service_name = service_name;

      // Create monitoring interval timer
      let mut monitoring_interval =
        tokio::time::interval(MONITORING_LOG_INTERVAL);
      monitoring_interval.tick().await; // Skip first immediate tick

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
            let user_password_auth = user_password_auth.clone();
            let access_log_writer = access_log_writer.clone();
            let service_name = service_name.clone();

            // Register connection handler
            connection_tracker.register(async move {
              // Capture start time for access log
              let start_time = std::time::Instant::now();

              // Step 1: Perform SOCKS5 handshake with timeout protection
              let handshake_result =
                match perform_handshake(stream, handshake_timeout, &user_password_auth)
                  .await
                {
                  Ok(result) => result,
                  Err(e) => {
                    // Handle handshake errors
                    match e {
                      HandshakeError::Timeout => {
                        // Timeout - do not send response, just close connection
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
                      HandshakeError::AuthenticationFailed { username } => {
                        // Auth failure response was already sent
                        if let Some(user) = username {
                          tracing::warn!(
                            "SOCKS5 authentication failed for user '{}' from {}",
                            user,
                            peer_addr
                          );
                        }
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
                match read_command_and_target(handshake_result.proto).await {
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
                          "SOCKS5 client disconnected during command processing from {}",
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
              let (trigger, on_upgrade) = Socks5UpgradeTrigger::pair(
                command_result.proto,
              );

              // Step 4: Build HTTP CONNECT request with on_upgrade in extensions
              let (host, port) = extract_host_port(&command_result.target_addr);
              let uri = format_connect_uri(&host, port);

              let mut request = http::Request::builder()
                .method(http::Method::CONNECT)
                .uri(&uri)
                .version(http::Version::HTTP_11)
                .body(plugin::RequestBody::new(
                  plugin::BytesBufBodyWrapper::new(
                    http_body_util::Empty::<bytes::Bytes>::new(),
                  ),
                ))
                .expect("failed to build CONNECT request");

              request.extensions_mut().insert(on_upgrade);

              // Step 5: Call the associated Service
              let result = service.call(request).await;

              // Variables for access log
              let status: u16;
              let service_metrics: crate::access_log::ServiceMetrics;

              // Step 6: Based on Response, send SOCKS5 reply via trigger
              match result {
                Ok(resp) => {
                  status = resp.status().as_u16();
                  service_metrics = resp
                    .extensions()
                    .get::<crate::access_log::ServiceMetrics>()
                    .cloned()
                    .unwrap_or_default();

                  if resp.status() == http::StatusCode::OK {
                    if let Err(e) = trigger.send_success().await {
                      tracing::warn!(
                        "SOCKS5 failed to send success reply to {}: {}",
                        peer_addr,
                        e
                      );
                    }
                  } else {
                    let error = http_status_to_socks5_error(resp.status());
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
                  status = 500;
                  service_metrics = crate::access_log::ServiceMetrics::new();

                  tracing::error!(
                    "SOCKS5 service error from {}: {}",
                    peer_addr,
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

              // Record access log after Step 6
              if let Some(ref writer) = access_log_writer {
                let duration = start_time.elapsed();
                let auth_type = if handshake_result.username.is_some() {
                  crate::access_log::AuthType::Password
                } else {
                  crate::access_log::AuthType::None
                };

                record_access_log(
                  writer,
                  peer_addr,
                  handshake_result.username,
                  auth_type,
                  "CONNECT".to_string(),
                  command_result.target_addr.to_string(),
                  status,
                  duration,
                  service_name,
                  service_metrics,
                );
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
          _ = monitoring_interval.tick() => {
            // Log monitoring info
            tracing::info!(
              "[socks5] active_connections={}",
              connection_tracker.active_count()
            );
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

impl plugin::Listening for Socks5Listener {
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

    // Get the shared shutdown handle from connection tracker
    let shutdown_handle = self.connection_tracker.shutdown_handle();

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
      let connection_tracker = self.connection_tracker.clone();
      let shutdown_handle = shutdown_handle.clone();
      let handshake_timeout = self.handshake_timeout;
      let user_password_auth = self.user_password_auth.clone();
      let access_log_writer = self.access_log_writer.clone();
      let service_name = self.service_name.clone();

      match self.serve_addr(
        addr,
        service,
        connection_tracker,
        shutdown_handle,
        handshake_timeout,
        user_password_auth,
        access_log_writer,
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
        "failed to start any SOCKS5 listener; all addresses failed to bind"
      ))));
    }

    let connection_tracker = self.connection_tracker.clone();
    let graceful_timeout = self.graceful_shutdown_timeout;

    // Spawn all listening tasks in the connection tracker
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
        connection_tracker.wait_shutdown().await;
      })
      .await;

      if wait_result.is_err() {
        // Timeout expired, force close remaining connections
        tracing::warn!(
          "graceful shutdown timeout ({:?}) expired, aborting {} \
           remaining connections",
          graceful_timeout,
          connection_tracker.active_count()
        );
        connection_tracker.abort_all();
      }

      Ok(())
    })
  }

  /// Stop the SOCKS5 listener.
  ///
  /// Triggers graceful shutdown notification.
  fn stop(&self) {
    self.connection_tracker.shutdown();
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
      connection_tracker: self.connection_tracker.clone(),
      service: self.service.clone(),
      graceful_shutdown_timeout: self.graceful_shutdown_timeout,
      handshake_timeout: self.handshake_timeout,
      user_password_auth: self.user_password_auth.clone(),
      access_log_writer: self.access_log_writer.clone(),
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
  /// when handshake times out. The connection should be closed directly.
  Timeout,

  /// Invalid SOCKS version number.
  ///
  /// According to RFC 1928, we should not send a response for invalid
  /// version numbers, just close the connection.
  InvalidVersion(u8),

  /// Authentication method not acceptable.
  ///
  /// The client requested authentication methods that the server doesn't support.
  /// According to RFC 1928, we should send METHOD=0xFF and close the connection.
  MethodNotAcceptable(Vec<u8>),

  /// Authentication failed.
  ///
  /// The username/password combination was invalid.
  /// According to RFC 1929, we should send auth failure response and close connection.
  AuthenticationFailed {
    /// The username that failed authentication (for logging).
    username: Option<String>,
  },

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
      Self::AuthenticationFailed { username } => {
        if let Some(u) = username {
          write!(f, "authentication failed for user '{}'", u)
        } else {
          write!(f, "authentication failed")
        }
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
      HandshakeError::AuthenticationFailed { .. } => {
        Self::IoError(std::io::Error::new(
          std::io::ErrorKind::PermissionDenied,
          "authentication failed",
        ))
      }
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
/// Contains the protocol state after command reading and the target address.
/// Note: We don't store the command because we only support CONNECT.
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
      SocksServerError::AuthenticationRejected => {
        Self::AuthenticationFailed { username: None }
      }
      SocksServerError::EmptyUsername
      | SocksServerError::EmptyPassword => {
        Self::AuthenticationFailed { username: None }
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
/// * `user_password_auth` - The user password authentication
///
/// # Returns
///
/// On success, returns a `HandshakeResult` containing the authenticated
/// protocol state and optional username.
///
/// On failure, returns a `HandshakeError`. The caller is responsible for
/// sending appropriate responses based on the error type:
/// - `Timeout`: Do not send response, close connection
/// - `InvalidVersion`: Do not send response, close connection
/// - `MethodNotAcceptable`: METHOD=0xFF was already sent
/// - `AuthenticationFailed`: Auth failure response was already sent
/// - `ClientDisconnected`: Connection already closed
/// - `IoError`: Connection should be closed
///
/// # Example
///
/// ```ignore
/// use tokio::time::timeout;
///
/// let result = perform_handshake(stream, Duration::from_secs(10), &user_password_auth).await;
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
  user_password_auth: &UserPasswordAuth,
) -> Result<HandshakeResult, HandshakeError> {
  // Wrap the entire handshake process with timeout
  let handshake_fut = async {
    // Start SOCKS5 protocol
    let proto =
      fast_socks5::server::Socks5ServerProtocol::start(stream);

    // Determine if authentication is required
    let requires_auth =
      user_password_auth.verify_credentials("", "").is_err();

    if !requires_auth {
      // No authentication required
      let auth_state = proto
        .negotiate_auth(&[fast_socks5::server::NoAuthentication])
        .await?;

      // Finish authentication (no credentials for no-auth)
      let authenticated =
        fast_socks5::server::Socks5ServerProtocol::finish_auth(
          auth_state,
        );

      Ok(HandshakeResult { proto: authenticated, username: None })
    } else {
      // Password authentication required
      let auth_state = proto
        .negotiate_auth(&[fast_socks5::server::PasswordAuthentication])
        .await?;

      // Read username and password
      let (username, password, auth_impl) =
        auth_state.read_username_password().await?;

      // Verify credentials using UserPasswordAuth
      if user_password_auth
        .verify_credentials(&username, &password)
        .is_ok()
      {
        // Accept authentication
        let finished = auth_impl.accept().await?;
        let authenticated =
          fast_socks5::server::Socks5ServerProtocol::finish_auth(
            finished,
          );

        tracing::info!(
          "SOCKS5 authentication succeeded for user '{}'",
          username
        );

        Ok(HandshakeResult {
          proto: authenticated,
          username: Some(username),
        })
      } else {
        // Reject authentication - this sends the failure response
        auth_impl.reject().await?;

        tracing::warn!(
          "SOCKS5 authentication failed for user '{}'",
          username
        );

        Err(HandshakeError::AuthenticationFailed {
          username: Some(username),
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

/// SOCKS5 listener configuration arguments.
#[derive(Clone, Debug)]
pub struct Socks5ListenerArgs {
  /// List of listening addresses as strings.
  pub addresses: Vec<String>,
  /// Handshake timeout duration.
  pub handshake_timeout: Duration,
  /// User password authentication.
  pub user_password_auth: UserPasswordAuth,
}

impl Default for Socks5ListenerArgs {
  fn default() -> Self {
    Self {
      addresses: Vec::new(),
      handshake_timeout: Duration::from_secs(
        DEFAULT_HANDSHAKE_TIMEOUT_SECS,
      ),
      user_password_auth: UserPasswordAuth::none(),
    }
  }
}

/// Parses SOCKS5 listener configuration from YAML.
///
/// # Arguments
///
/// * `args` - The serialized YAML configuration
///
/// # Returns
///
/// The parsed `Socks5ListenerArgs` on success, or an error if
/// configuration is invalid.
///
/// # Errors
///
/// Returns an error if:
/// - `addresses` field is missing or empty
/// - `auth` includes `client_ca_path` (SOCKS5 only supports password auth)
/// - `auth` is "password" but `users` is empty
/// - `handshake_timeout` is not a valid string format (e.g., "10s")
/// - Username length is not in range 1-255 bytes
/// - Any other YAML parsing error occurs
pub fn parse_config(
  args: plugin::SerializedArgs,
) -> Result<Socks5ListenerArgs> {
  #[derive(Deserialize, Debug)]
  struct ConfigYaml {
    addresses: Vec<String>,
    #[serde(default)]
    handshake_timeout: Option<String>,
    #[serde(default)]
    auth: Option<serde_yaml::Value>,
  }

  let config: ConfigYaml = serde_yaml::from_value(args)
    .context("failed to parse SOCKS5 listener config")?;

  // Validate addresses
  if config.addresses.is_empty() {
    bail!("addresses field is missing or empty");
  }

  // Parse handshake timeout (string format like "10s")
  let handshake_timeout =
    parse_handshake_timeout(config.handshake_timeout)?;

  // Parse auth - SOCKS5 only supports password type (users field)
  let user_password_auth = match config.auth {
    None => UserPasswordAuth::none(),
    Some(yaml) => {
      let auth_config: ListenerAuthConfig =
        serde_yaml::from_value(yaml)
          .context("failed to parse auth config")?;

      // Validate the auth config
      auth_config
        .validate()
        .context("auth config validation failed")?;

      // SOCKS5 only supports password auth, reject client_ca_path
      if auth_config.client_ca_path.is_some() {
        bail!(
          "client_ca_path is not supported for SOCKS5 listener; only password authentication is supported"
        );
      }

      UserPasswordAuth::from_config(&auth_config)
    }
  };

  Ok(Socks5ListenerArgs {
    addresses: config.addresses,
    handshake_timeout,
    user_password_auth,
  })
}

/// Parses handshake timeout string format.
///
/// # Arguments
///
/// * `timeout_str` - Optional timeout string (e.g., "10s")
///
/// # Returns
///
/// Parsed Duration on success, or an error if format is invalid.
///
/// # Errors
///
/// Returns an error if:
/// - String does not end with 's'
/// - Numeric part is not a valid number
/// - Numeric part would overflow
fn parse_handshake_timeout(
  timeout_str: Option<String>,
) -> Result<Duration> {
  match timeout_str {
    None => Ok(Duration::from_secs(DEFAULT_HANDSHAKE_TIMEOUT_SECS)),
    Some(s) => {
      // Validate format: must end with 's' (seconds)
      if !s.ends_with('s') {
        bail!(
          "invalid handshake_timeout format '{}': expected format like \"10s\"",
          s
        );
      }

      // Strip 's' suffix and parse number
      let num_str = &s[..s.len() - 1];
      let secs: u64 = num_str.parse().with_context(|| {
        format!("invalid handshake_timeout value: {}", s)
      })?;

      Ok(Duration::from_secs(secs))
    }
  }
}

/// Determines if an accept error is fatal and should stop the listener.
///
/// Fatal errors indicate a permanent problem that cannot be recovered from
/// by continuing to accept connections. Temporary errors may resolve on retry.
///
/// # Fatal errors
///
/// - `InvalidInput`: Invalid input parameter (bug in code)
/// - `InvalidData`: Invalid data received
/// - `NotFound`: Resource not found (listener socket closed)
/// - `PermissionDenied`: Permission denied (SELinux/AppArmor denial, fd permission)
///
/// # Temporary errors
///
/// - `WouldBlock`: Would block (should not happen in async)
/// - `Interrupted`: Interrupted by signal
/// - Connection reset, broken pipe, etc.: Network-level temporary issues
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

/// Resolves address strings to SocketAddr, logging warnings for invalid ones.
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

/// Creates a listener builder.
///
/// Returns a builder function that parses configuration and creates
/// a Socks5Listener instance.
pub fn create_listener_builder() -> Box<dyn plugin::BuildListener> {
  Box::new(
    |args: plugin::SerializedArgs,
     svc: plugin::Service,
     ctx: plugin::ListenerBuildContext| {
      // Parse configuration
      let listener_args = parse_config(args)?;

      // Create listener
      Socks5Listener::new(listener_args, svc, ctx)
    },
  )
}

/// Record an access log entry for a SOCKS5 request.
///
/// Delegates to the common implementation in `super::common::record_socks5_access_log`.
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
  super::common::record_socks5_access_log(
    writer,
    client_addr,
    user,
    auth_type,
    method,
    target,
    status,
    duration,
    service_name,
    service_metrics,
  );
}

#[cfg(test)]
mod tests {
  use super::*;

  // ========== StreamTracker Tests ==========

  #[test]
  fn test_stream_tracker_new() {
    let tracker = StreamTracker::new();
    assert_eq!(tracker.active_count(), 0);
  }

  #[test]
  fn test_stream_tracker_default() {
    let tracker = StreamTracker::default();
    assert_eq!(tracker.active_count(), 0);
  }

  #[test]
  fn test_stream_tracker_in_rc() {
    // Verify Rc<StreamTracker> can be cloned
    let tracker = Rc::new(StreamTracker::new());
    let cloned = tracker.clone();
    assert_eq!(cloned.active_count(), 0);

    // Verify shutdown handles are shared
    tracker.shutdown();
    assert!(tracker.shutdown_handle().is_shutdown());
    assert!(cloned.shutdown_handle().is_shutdown());
  }

  #[tokio::test]
  async fn test_stream_tracker_register() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let tracker = StreamTracker::new();
        tracker.register(async {});
        // Need to yield for the task to be spawned
        tokio::task::yield_now().await;
        assert_eq!(tracker.active_count(), 1);
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

  // ========== Socks5ListenerArgs Tests ==========

  #[test]
  fn test_socks5_listener_args_default() {
    let args = Socks5ListenerArgs::default();
    assert!(args.addresses.is_empty());
    assert_eq!(args.handshake_timeout, Duration::from_secs(10));
  }

  #[test]
  fn test_socks5_listener_args_clone() {
    let args = Socks5ListenerArgs {
      addresses: vec!["127.0.0.1:1080".to_string()],
      handshake_timeout: Duration::from_secs(5),
      user_password_auth: UserPasswordAuth::none(),
    };
    let cloned = args.clone();
    assert_eq!(args.addresses, cloned.addresses);
    assert_eq!(args.handshake_timeout, cloned.handshake_timeout);
  }

  // ========== parse_config Tests ==========

  #[test]
  fn test_parse_config_valid_minimal() {
    let yaml = serde_yaml::from_str(
      r#"
addresses:
  - "127.0.0.1:1080"
"#,
    )
    .unwrap();

    let args = parse_config(yaml).unwrap();
    assert_eq!(args.addresses, vec!["127.0.0.1:1080"]);
    assert_eq!(args.handshake_timeout, Duration::from_secs(10));
  }

  #[test]
  fn test_parse_config_valid_with_timeout() {
    let yaml = serde_yaml::from_str(
      r#"
addresses:
  - "127.0.0.1:1080"
handshake_timeout: "5s"
"#,
    )
    .unwrap();

    let args = parse_config(yaml).unwrap();
    assert_eq!(args.handshake_timeout, Duration::from_secs(5));
  }

  #[test]
  fn test_parse_config_with_password_auth() {
    let yaml = serde_yaml::from_str(
      r#"
addresses:
  - "127.0.0.1:1080"
auth:
  users:
    - username: alice
      password: secret123
"#,
    )
    .unwrap();

    let args = parse_config(yaml).unwrap();
    // Verify auth was parsed
    assert!(
      args
        .user_password_auth
        .verify_credentials("alice", "secret123")
        .is_ok()
    );
    assert!(
      args
        .user_password_auth
        .verify_credentials("alice", "wrong")
        .is_err()
    );
  }

  #[test]
  fn test_parse_config_rejects_client_ca_path() {
    let yaml = serde_yaml::from_str(
      r#"
addresses:
  - "127.0.0.1:1080"
auth:
  client_ca_path: /path/to/ca.pem
"#,
    )
    .unwrap();

    let result = parse_config(yaml);
    assert!(result.is_err(), "Should reject client_ca_path for SOCKS5");
  }

  #[test]
  fn test_parse_config_missing_addresses() {
    let yaml = serde_yaml::from_str(
      r#"
handshake_timeout: "5s"
"#,
    )
    .unwrap();

    let result = parse_config(yaml);
    assert!(result.is_err());
  }

  #[test]
  fn test_parse_config_empty_addresses() {
    let yaml = serde_yaml::from_str(
      r#"
addresses: []
"#,
    )
    .unwrap();

    let result = parse_config(yaml);
    assert!(result.is_err());
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
  fn test_parse_handshake_timeout_default() {
    let result = parse_handshake_timeout(None).unwrap();
    assert_eq!(result, Duration::from_secs(10));
  }

  #[test]
  fn test_parse_handshake_timeout_valid() {
    let result =
      parse_handshake_timeout(Some("5s".to_string())).unwrap();
    assert_eq!(result, Duration::from_secs(5));
  }

  #[test]
  fn test_parse_handshake_timeout_invalid_format() {
    let result = parse_handshake_timeout(Some("5".to_string()));
    assert!(result.is_err());
  }

  #[test]
  fn test_listener_name() {
    assert_eq!(listener_name(), "socks5");
  }

  #[test]
  fn test_listening_trait_implementation() {
    fn assert_listening<T: plugin::Listening>() {}
    assert_listening::<Socks5Listener>();
  }

  // ========== Access Log Tests ==========

  #[test]
  fn test_record_access_log_writes_entry() {
    let dir = tempfile::tempdir().unwrap();
    let config = crate::access_log::AccessLogConfig {
      enabled: true,
      path_prefix: "socks5test.log".to_string(),
      format: crate::access_log::config::LogFormat::Text,
      buffer: crate::access_log::config::HumanBytes(64),
      flush: crate::access_log::config::HumanDuration(
        std::time::Duration::from_millis(100),
      ),
      max_size: crate::access_log::config::HumanBytes(1024 * 1024),
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
      if name.starts_with("socks5test.log") {
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
