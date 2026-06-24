#![allow(clippy::await_holding_refcell_ref)]
use std::future;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;

use anyhow::{Context, Result};
use hyper_util::rt as rt_util;
use hyper_util::server::conn::auto as conn_util;
use serde::Deserialize;
use tracing::{error, info, warn};

use crate::config::SerializedArgs;
use crate::listener::{
  BuildListener, Listener, ListenerProps, Listening, TransportLayer,
};
use crate::listeners::http_service::HttpServiceAdaptor;
use crate::listeners::tcp_listener_base::TcpListenerBase;
use crate::server::Server;

/// Executor for spawning tasks on the current tokio LocalSet.
#[derive(Clone)]
struct TokioLocalExecutor;

impl<F> hyper::rt::Executor<F> for TokioLocalExecutor
where
  F: Future + 'static,
{
  fn execute(&self, fut: F) {
    tokio::task::spawn_local(fut);
  }
}

/// HTTP Listener configuration arguments.
#[derive(Deserialize, Default, Clone, Debug)]
struct HttpListenerArgs {}

/// HTTP Listener implementation with shared-address routing support.
struct HttpListener {
  /// Listening addresses
  addresses: Vec<SocketAddr>,
  /// Server routing table for hostname-based routing
  server_routing_table: Vec<Server>,
  /// Shared TCP listener base for lifecycle management
  base: TcpListenerBase,
}

impl HttpListener {
  /// Create an HttpListener from parsed configuration.
  fn from_args(
    addresses: Vec<String>,
    server_routing_table: Vec<Server>,
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
      server_routing_table,
      base: TcpListenerBase::new(),
    })
  }

  #[allow(clippy::new_ret_no_self)]
  fn new(
    addresses: Vec<String>,
    sargs: SerializedArgs,
    server_routing_table: Vec<Server>,
  ) -> Result<Listener> {
    let _args: HttpListenerArgs = serde_yaml::from_value(sargs)?;
    Ok(Listener::new(Self::from_args(addresses, server_routing_table)?))
  }

  fn serve_addr(
    &self,
    addr: SocketAddr,
  ) -> Result<Pin<Box<dyn Future<Output = Result<()>>>>> {
    let listener = super::tcp_bind::create_tcp_listener(addr)?;
    let stream_tracker = self.base.stream_tracker();
    let shutdown_handle = self.base.shutdown_handle();
    let server_routing_table = self.server_routing_table.clone();
    let accepting_fut = async move {
      // Log listener startup event
      info!("HTTP listener started on {}", addr);

      let shutdown = async move || shutdown_handle.notified().await;
      let accepting = || async {
        match listener.accept().await {
          Err(e) => {
            error!("accepting new connection failed: {e}");
          }
          Ok((stream, raddr)) => {
            let local_addr = stream.local_addr().ok();
            let io = rt_util::TokioIo::new(stream);
            let svc = HttpServiceAdaptor::new_http(
              server_routing_table.clone(),
              Some(raddr),
              local_addr,
            );
            let builder = conn_util::Builder::new(TokioLocalExecutor);
            stream_tracker.register(async move {
              // Do not need any graceful shutdown actions here for
              // connections. The `Service`s should do this instead.
              let conn =
                builder.serve_connection_with_upgrades(io, svc);
              if let Err(e) = conn.await {
                warn!("connection from {raddr} on {local_addr:?}: {e}");
              }
            });
          }
        }
      };

      loop {
        tokio::select! {
          _ = accepting() => {},
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
  Box::new(HttpListener::new)
}
