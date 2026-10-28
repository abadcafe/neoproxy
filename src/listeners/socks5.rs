//! module: listeners::socks5
//! responsibility: adapt SOCKS5 sessions to routed CONNECT services
//! public operations: listener_name, props, create_listener_builder
//! data entities: Socks5Listener, Socks5ListenerArgs
//! tests: socks5_tests.rs

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

mod command;
mod handshake;
mod session;
#[cfg(test)]
mod session_tests;
mod upgrade;
#[cfg(test)]
mod upgrade_tests;

#[cfg(test)]
mod command_tests;
#[cfg(test)]
mod handshake_tests;

use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use handshake::DEFAULT_HANDSHAKE_TIMEOUT;
use serde::Deserialize;

use super::tcp_accept::AcceptRetryDelay;
use super::tcp_listener_base::TcpListenerBase;
use crate::config::{ListenerPropertyValues, SerializedArgs};
use crate::listener::{
  BuildListener, Listener, Listening, TransportLayer,
};
use crate::service::Service as RuntimeService;

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// SOCKS5 listener implementation.
///
/// This listener accepts SOCKS5 connections on configured addresses
/// and forwards them to the associated Service.
struct Socks5Listener {
  tcp_options: crate::tcp_options::TcpOptions,
  /// Resolved listening addresses.
  addresses: Vec<SocketAddr>,
  /// Shared lifecycle management (shutdown, join, graceful shutdown).
  base: TcpListenerBase,
  /// Associated service for handling connections.
  service: RuntimeService,
  /// Handshake timeout duration.
  socks5_handshake_timeout: Duration,
  /// Deadline for reading the client CONNECT command, not upstream
  /// dialing.
  socks5_connect_timeout: Duration,
  tcp_accept_retry_delay: AcceptRetryDelay,
  /// Service name for identification in logs.
  service_name: String,
}

impl Socks5Listener {
  /// Create a new Socks5Listener from parsed configuration.
  fn build(
    addresses: Vec<String>,
    args: Socks5ListenerArgs,
    server_routing_table: Vec<crate::server::Server>,
  ) -> Result<Listener> {
    for (name, timeout) in [
      ("socks5_handshake_timeout", args.socks5_handshake_timeout),
      ("socks5_connect_timeout", args.socks5_connect_timeout),
    ] {
      anyhow::ensure!(
        !timeout.is_zero()
          && std::time::Instant::now().checked_add(timeout).is_some(),
        "{name} must be positive and representable"
      );
    }
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
      tcp_options: args.tcp_options,
      addresses,
      base: TcpListenerBase::new().with_tcp_options(args.tcp_options),
      service,
      socks5_handshake_timeout: args.socks5_handshake_timeout,
      socks5_connect_timeout: args.socks5_connect_timeout,
      tcp_accept_retry_delay: args.tcp_accept_retry_delay,
      service_name,
    }))
  }
}

impl Listening for Socks5Listener {
  fn start(
    &self,
  ) -> Result<std::pin::Pin<Box<dyn Future<Output = Result<()>>>>> {
    let service = self.service.clone();
    let service_name = self.service_name.clone();
    let socks5_handshake_timeout = self.socks5_handshake_timeout;
    let socks5_connect_timeout = self.socks5_connect_timeout;
    self.base.start(
      &self.addresses,
      "SOCKS5",
      self.tcp_accept_retry_delay,
      move |connection| {
        session::serve(
          connection,
          service.clone(),
          socks5_handshake_timeout,
          socks5_connect_timeout,
          service_name.clone(),
        )
      },
    )
  }

  fn stop(&self) {
    self.base.stop();
  }
}

impl Clone for Socks5Listener {
  fn clone(&self) -> Self {
    Self {
      tcp_options: self.tcp_options,
      addresses: self.addresses.clone(),
      base: TcpListenerBase::new().with_tcp_options(self.tcp_options),
      service: self.service.clone(),
      socks5_handshake_timeout: self.socks5_handshake_timeout,
      socks5_connect_timeout: self.socks5_connect_timeout,
      tcp_accept_retry_delay: self.tcp_accept_retry_delay,
      service_name: self.service_name.clone(),
    }
  }
}

/// SOCKS5 listener configuration arguments.
#[derive(Clone, Debug)]
struct Socks5ListenerArgs {
  tcp_options: crate::tcp_options::TcpOptions,
  /// Handshake timeout duration.
  socks5_handshake_timeout: Duration,
  /// Deadline for reading the client CONNECT command, not upstream
  /// dialing.
  socks5_connect_timeout: Duration,
  tcp_accept_retry_delay: AcceptRetryDelay,
}

impl Default for Socks5ListenerArgs {
  fn default() -> Self {
    Self {
      tcp_options: Default::default(),
      socks5_handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
      socks5_connect_timeout: DEFAULT_CONNECT_TIMEOUT,
      tcp_accept_retry_delay: Default::default(),
    }
  }
}

/// Parses SOCKS5 listener configuration from YAML.
fn parse_config(args: SerializedArgs) -> Result<Socks5ListenerArgs> {
  #[derive(Deserialize, Debug)]
  #[serde(deny_unknown_fields)]
  struct ConfigYaml {
    #[serde(flatten)]
    tcp_options: crate::tcp_options::TcpOptions,
    #[serde(
      with = "humantime_serde",
      default = "default_socks5_handshake_timeout"
    )]
    socks5_handshake_timeout: Duration,
    #[serde(
      with = "humantime_serde",
      default = "default_socks5_connect_timeout"
    )]
    socks5_connect_timeout: Duration,
    #[serde(default)]
    tcp_accept_retry_delay: AcceptRetryDelay,
  }

  fn default_socks5_handshake_timeout() -> Duration {
    DEFAULT_HANDSHAKE_TIMEOUT
  }

  fn default_socks5_connect_timeout() -> Duration {
    DEFAULT_CONNECT_TIMEOUT
  }

  let config: ConfigYaml = serde_yaml::from_value(args)
    .context("failed to parse SOCKS5 listener config")?;

  Ok(Socks5ListenerArgs {
    tcp_options: config.tcp_options,
    socks5_handshake_timeout: config.socks5_handshake_timeout,
    socks5_connect_timeout: config.socks5_connect_timeout,
    tcp_accept_retry_delay: config.tcp_accept_retry_delay,
  })
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

/// Plugin listener name.
pub(crate) fn listener_name() -> &'static str {
  "socks5"
}

/// Get listener properties for conflict detection.
pub(crate) fn props() -> ListenerPropertyValues {
  ListenerPropertyValues::new(TransportLayer::Tcp, false, false)
}

/// Creates a listener builder.
pub(crate) fn create_listener_builder() -> Box<dyn BuildListener> {
  Box::new(
    |addresses: Vec<String>,
     args: SerializedArgs,
     server_routing_table: Vec<crate::server::Server>| {
      let listener_args = parse_config(args)?;
      Socks5Listener::build(
        addresses,
        listener_args,
        server_routing_table,
      )
    },
  )
}
