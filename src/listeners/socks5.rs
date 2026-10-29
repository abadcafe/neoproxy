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

use anyhow::{Context, Result};
use serde::Deserialize;

use super::header_deadline::HeaderDeadline;
use super::tcp_accept::AcceptRetryDelay;
use super::tcp_listener_base::TcpListenerBase;
use crate::config::{ListenerPropertyValues, SerializedArgs};
use crate::listener::{
  BuildListener, Listener, Listening, TransportLayer,
};
use crate::server::ServerRouter;

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
  /// Shared hostname router used by the request dispatcher.
  server_router: ServerRouter,
  /// Total deadline for negotiation, credentials and CONNECT command.
  header_read_timeout: HeaderDeadline,
  tcp_accept_retry_delay: AcceptRetryDelay,
}

impl Socks5Listener {
  /// Create a new Socks5Listener from parsed configuration.
  fn build(
    addresses: Vec<String>,
    args: Socks5ListenerArgs,
    server_routing_table: Vec<crate::server::Server>,
  ) -> Result<Listener> {
    let addresses = resolve_addresses(&addresses)?;

    let server_router = ServerRouter::build(server_routing_table);

    Ok(Listener::new(Self {
      tcp_options: args.tcp_options,
      addresses,
      base: TcpListenerBase::new().with_tcp_options(args.tcp_options),
      server_router,
      header_read_timeout: args.header_read_timeout,
      tcp_accept_retry_delay: args.tcp_accept_retry_delay,
    }))
  }
}

impl Listening for Socks5Listener {
  fn start(
    &self,
  ) -> Result<std::pin::Pin<Box<dyn Future<Output = Result<()>>>>> {
    let server_router = self.server_router.clone();
    let header_read_timeout = self.header_read_timeout;
    self.base.start(
      &self.addresses,
      "SOCKS5",
      self.tcp_accept_retry_delay,
      move |connection| {
        session::serve(
          connection,
          server_router.clone(),
          tokio::time::Instant::now() + header_read_timeout.duration(),
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
      server_router: self.server_router.clone(),
      header_read_timeout: self.header_read_timeout,
      tcp_accept_retry_delay: self.tcp_accept_retry_delay,
    }
  }
}

/// SOCKS5 listener configuration arguments.
#[derive(Clone, Debug, Default)]
struct Socks5ListenerArgs {
  tcp_options: crate::tcp_options::TcpOptions,
  /// Total deadline for negotiation, credentials and CONNECT command.
  header_read_timeout: HeaderDeadline,
  tcp_accept_retry_delay: AcceptRetryDelay,
}

/// Parses SOCKS5 listener configuration from YAML.
fn parse_config(args: SerializedArgs) -> Result<Socks5ListenerArgs> {
  #[derive(Deserialize, Debug)]
  #[serde(deny_unknown_fields)]
  struct ConfigYaml {
    #[serde(flatten)]
    tcp_options: crate::tcp_options::TcpOptions,
    #[serde(default)]
    header_read_timeout: HeaderDeadline,
    #[serde(default)]
    tcp_accept_retry_delay: AcceptRetryDelay,
  }

  let config: ConfigYaml = serde_yaml::from_value(args)
    .context("failed to parse SOCKS5 listener config")?;

  Ok(Socks5ListenerArgs {
    tcp_options: config.tcp_options,
    header_read_timeout: config.header_read_timeout,
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
  ListenerPropertyValues::new(TransportLayer::Tcp, false)
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
