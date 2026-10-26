use std::future;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;

use anyhow::{Context, Result};
use serde::Deserialize;
use tracing::{info, warn};

use crate::config::SerializedArgs;
use crate::listener::{
  BuildListener, Listener, ListenerProps, Listening, TransportLayer,
};
use crate::listeners::http_service::HttpServiceAdaptor;
use crate::listeners::tcp_accept::{self, AcceptRetryDelay};
use crate::listeners::tcp_listener_base::TcpListenerBase;
use crate::server::{Server, ServerRouter};

/// HTTP Listener configuration arguments.
#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default, deny_unknown_fields)]
struct HttpListenerArgs {
  header_read_timeout: super::header_deadline::HeaderDeadline,
  accept_retry_delay: AcceptRetryDelay,
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
  accept_retry_delay: AcceptRetryDelay,
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
      base: TcpListenerBase::new(),
      header_deadline: args.header_read_timeout,
      accept_retry_delay: args.accept_retry_delay,
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

  fn serve_addr(
    &self,
    addr: SocketAddr,
  ) -> Result<Pin<Box<dyn Future<Output = Result<()>>>>> {
    let listener = super::tcp_bind::create_tcp_listener(addr)?;
    let stream_tracker = self.base.stream_tracker();
    let shutdown_handle = self.base.shutdown_handle();
    let server_router = self.server_router.clone();
    let header_deadline = self.header_deadline;
    let accept_retry_delay = self.accept_retry_delay;
    let accepting_fut = async move {
      // Log listener startup event
      info!("HTTP listener started on {}", addr);

      let shutdown = || shutdown_handle.notified();
      let accepting = || async {
        match tcp_accept::accept(addr, accept_retry_delay, || {
          listener.accept()
        })
        .await
        {
          Err(error) => return Err(error),
          Ok((stream, raddr)) => {
            let local_addr = stream.local_addr().ok();
            let svc = HttpServiceAdaptor::new_http(
              server_router.clone(),
              Some(raddr),
              local_addr,
            );
            let connection_shutdown = shutdown_handle.clone();
            stream_tracker.register(async move {
              if let Err(error) = super::http_connection::serve(
                stream,
                svc,
                header_deadline,
                connection_shutdown,
              )
              .await
              {
                warn!(
                  "connection from {raddr} on {local_addr:?}: {error}"
                );
              }
            });
          }
        }
        Ok::<(), std::io::Error>(())
      };

      loop {
        tokio::select! {
          result = accepting() => result.with_context(|| format!("HTTP accept failed on {addr}"))?,
          _ = shutdown() => {
            // Graceful shutdown for the TcpListener.
            info!("HTTP listener on {} shutting down", addr);
            break
          },
        }
      }

      // Here the TcpListener is dropped, so listening socket is closed.
      Ok(())
    };

    Ok(Box::pin(accepting_fut))
  }
}

impl Listening for HttpListener {
  fn start(&self) -> Pin<Box<dyn Future<Output = Result<()>>>> {
    let mut tasks = Vec::new();
    for addr in &self.addresses {
      let addr = *addr;
      match self.serve_addr(addr) {
        Ok(f) => tasks.push(f),
        Err(e) => return Box::pin(future::ready(Err(e))),
      }
    }
    self.base.start_with_tasks(tasks)
  }

  fn stop(&self) {
    self.base.stop()
  }
}

pub(crate) fn listener_name() -> &'static str {
  "http"
}

/// Get listener properties for conflict detection.
pub(crate) fn props() -> ListenerProps {
  ListenerProps::new(TransportLayer::Tcp, true)
}

pub(crate) fn create_listener_builder() -> Box<dyn BuildListener> {
  Box::new(HttpListener::build)
}
