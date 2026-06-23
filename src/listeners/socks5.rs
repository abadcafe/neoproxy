//! SOCKS5 listener implementation.
//!
//! This module provides a SOCKS5 protocol listener that accepts SOCKS5
//! connections and forwards them to an associated Service.
//!
//! # Submodules
//!
//! - `handshake` — SOCKS5 handshake protocol (version negotiation,
//!   authentication)
//! - `command` — SOCKS5 command processing (CONNECT/BIND/UDP ASSOCIATE)

#![allow(clippy::await_holding_refcell_ref)]

mod command;
mod handshake;

#[cfg(test)]
mod command_tests;
#[cfg(test)]
mod handshake_tests;

use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use base64::Engine;
use command::{CommandError, read_command_and_target};
use handshake::{
  DEFAULT_HANDSHAKE_TIMEOUT, HandshakeError, perform_handshake,
};
use serde::Deserialize;
use tower::Service;

use super::tcp_listener_base::TcpListenerBase;
use crate::config::SerializedArgs;
use crate::http_utils::{BytesBufBodyWrapper, RequestBody};
use crate::listener::{
  BuildListener, Listener, ListenerProps, Listening, TransportLayer,
};
use crate::service::Service as RuntimeService;
use crate::stream::{
  Socks5UpgradeTrigger, http_status_to_socks5_error,
};

/// SOCKS5 listener implementation.
///
/// This listener accepts SOCKS5 connections on configured addresses
/// and forwards them to the associated Service.
struct Socks5Listener {
  /// Resolved listening addresses.
  addresses: Vec<SocketAddr>,
  /// Shared lifecycle management (shutdown, join, graceful shutdown).
  base: TcpListenerBase,
  /// Associated service for handling connections.
  service: RuntimeService,
  /// Handshake timeout duration.
  handshake_timeout: Duration,
  /// Service name for identification in logs.
  service_name: String,
}

impl Socks5Listener {
  /// Create a new Socks5Listener from parsed configuration.
  #[allow(clippy::new_ret_no_self)]
  fn new(
    addresses: Vec<String>,
    args: Socks5ListenerArgs,
    server_routing_table: Vec<crate::server::Server>,
  ) -> Result<Listener> {
    let addresses = resolve_addresses(&addresses)?;

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
      base: TcpListenerBase::new(),
      service,
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
    handshake_timeout: Duration,
    service_name: String,
  ) -> Result<std::pin::Pin<Box<dyn Future<Output = Result<()>>>>> {
    let listener = super::tcp_bind::create_tcp_listener(addr)?;
    let stream_tracker = self.base.stream_tracker();
    let shutdown_handle = self.base.shutdown_handle();

    let accepting_fut = async move {
      tracing::info!("SOCKS5 listener started on {}", addr);

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
              let ctx = crate::context::build_request_context(
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
    let shutdown_handle = self.base.shutdown_handle();

    if shutdown_handle.is_shutdown() {
      return Box::pin(future::ready(Ok(())));
    }

    let mut tasks = Vec::new();

    for addr in &self.addresses {
      match self.serve_addr(
        *addr,
        self.service.clone(),
        self.handshake_timeout,
        self.service_name.clone(),
      ) {
        Ok(f) => tasks.push(f),
        Err(e) => {
          tracing::error!(
            "failed to start listener on {}: {}",
            addr,
            e
          );
        }
      }
    }

    if tasks.is_empty() {
      return Box::pin(future::ready(Err(anyhow::anyhow!(
        "failed to start any SOCKS5 listener; all addresses failed to \
         bind"
      ))));
    }

    self.base.start_with_tasks(tasks)
  }

  fn stop(&self) {
    self.base.stop();
  }
}

impl Clone for Socks5Listener {
  fn clone(&self) -> Self {
    Self {
      addresses: self.addresses.clone(),
      base: TcpListenerBase::new(),
      service: self.service.clone(),
      handshake_timeout: self.handshake_timeout,
      service_name: self.service_name.clone(),
    }
  }
}

/// SOCKS5 listener configuration arguments.
#[derive(Clone, Debug)]
struct Socks5ListenerArgs {
  /// Handshake timeout duration.
  handshake_timeout: Duration,
}

impl Default for Socks5ListenerArgs {
  fn default() -> Self {
    Self { handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT }
  }
}

/// Parses SOCKS5 listener configuration from YAML.
fn parse_config(args: SerializedArgs) -> Result<Socks5ListenerArgs> {
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

/// Resolves address strings to SocketAddr.
fn resolve_addresses(addresses: &[String]) -> Result<Vec<SocketAddr>> {
  addresses
    .iter()
    .map(|addr| {
      addr
        .parse::<SocketAddr>()
        .with_context(|| format!("Invalid address: {}", addr))
    })
    .collect()
}

/// Formats a host and port for HTTP CONNECT URI.
fn format_connect_uri(host: &str, port: u16) -> String {
  if host.starts_with('[') {
    return format!("{}:{}", host, port);
  }
  if let Ok(addr) = host.parse::<std::net::IpAddr>() {
    match addr {
      std::net::IpAddr::V4(_) => format!("{}:{}", host, port),
      std::net::IpAddr::V6(_) => format!("[{}]:{}", host, port),
    }
  } else {
    format!("{}:{}", host, port)
  }
}

/// Extracts host and port from TargetAddr.
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
  ListenerProps::new(TransportLayer::Tcp, false)
}

/// Creates a listener builder.
pub fn create_listener_builder() -> Box<dyn BuildListener> {
  Box::new(
    |addresses: Vec<String>,
     args: SerializedArgs,
     server_routing_table: Vec<crate::server::Server>| {
      let listener_args = parse_config(args)?;
      Socks5Listener::new(
        addresses,
        listener_args,
        server_routing_table,
      )
    },
  )
}
