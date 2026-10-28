//! module: listeners::http
//! responsibility: serve routed HTTP connections over TCP
//! public operations: listener_name, props, create_listener_builder
//! data entities: HttpListenerArgs, HttpListener
//! tests: http_service_tests.rs, http_tests.rs

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;

use anyhow::{Context, Result};
use serde::Deserialize;
use tracing::warn;

use crate::config::{ListenerPropertyValues, SerializedArgs};
use crate::listener::{
  BuildListener, Listener, Listening, TransportLayer,
};
use crate::listeners::http_service::HttpService;
use crate::listeners::tcp_accept::AcceptRetryDelay;
use crate::listeners::tcp_listener_base::TcpListenerBase;
use crate::server::{Server, ServerRouter};

/// HTTP Listener configuration arguments.
#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default, deny_unknown_fields)]
struct HttpListenerArgs {
  #[serde(flatten)]
  tcp_options: crate::tcp_options::TcpOptions,
  header_read_timeout: super::header_deadline::HeaderDeadline,
  tcp_accept_retry_delay: AcceptRetryDelay,
}

/// HTTP Listener implementation with shared-address routing support.
struct HttpListener {
  /// Listening addresses
  addresses: Vec<SocketAddr>,
  /// Server routing table for hostname-based routing
  server_router: ServerRouter,
  /// Shared TCP listener base for lifecycle management
  base: TcpListenerBase,
  header_deadline: super::header_deadline::HeaderDeadline,
  tcp_accept_retry_delay: AcceptRetryDelay,
}

impl HttpListener {
  /// Create an HttpListener from parsed configuration.
  fn from_args(
    addresses: Vec<String>,
    server_routing_table: Vec<Server>,
    args: HttpListenerArgs,
  ) -> Result<Self> {
    // Parse addresses - any invalid address is an error
    let addresses: Vec<SocketAddr> = addresses
      .iter()
      .map(|addr| {
        addr
          .parse::<SocketAddr>()
          .with_context(|| format!("Invalid address: {}", addr))
      })
      .collect::<Result<Vec<_>>>()?;

    Ok(Self {
      addresses,
      server_router: ServerRouter::build(server_routing_table),
      base: TcpListenerBase::new().with_tcp_options(args.tcp_options),
      header_deadline: args.header_read_timeout,
      tcp_accept_retry_delay: args.tcp_accept_retry_delay,
    })
  }

  fn build(
    addresses: Vec<String>,
    sargs: SerializedArgs,
    server_routing_table: Vec<Server>,
  ) -> Result<Listener> {
    let args: HttpListenerArgs = serde_yaml::from_value(sargs)?;
    Ok(Listener::new(Self::from_args(
      addresses,
      server_routing_table,
      args,
    )?))
  }
}

impl Listening for HttpListener {
  fn start(&self) -> Result<Pin<Box<dyn Future<Output = Result<()>>>>> {
    let server_router = self.server_router.clone();
    let header_deadline = self.header_deadline;
    self.base.start(
      &self.addresses,
      "HTTP",
      self.tcp_accept_retry_delay,
      move |connection| {
        let service = HttpService::new_http(
          server_router.clone(),
          connection.peer_addr,
          connection.local_addr,
        );
        async move {
          if let Err(error) = super::http_connection::serve(
            connection.stream,
            service,
            header_deadline,
            connection.shutdown,
          )
          .await
          {
            warn!(
              "connection from {} on {}: {error}",
              connection.peer_addr, connection.local_addr
            );
          }
        }
      },
    )
  }

  fn stop(&self) {
    self.base.stop()
  }
}

pub(crate) fn listener_name() -> &'static str {
  "http"
}

/// Get listener properties for conflict detection.
pub(crate) fn props() -> ListenerPropertyValues {
  ListenerPropertyValues::new(TransportLayer::Tcp, true, false)
}

pub(crate) fn create_listener_builder() -> Box<dyn BuildListener> {
  Box::new(HttpListener::build)
}
