use std::cell::RefCell;
use std::collections::HashMap;
use std::future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::rc::Rc;

use anyhow::Result;
use hyper::{body as hyper_body, service as hyper_svc};
use hyper_util::rt as rt_util;
use hyper_util::server::conn::auto as conn_util;
use serde::Deserialize;
use tokio::{net, task};
use tower::util as tower_util;
use tracing::{error, warn};

use crate::plugin;

struct HyperServiceAdaptor {
  s: plugin::Service,
}

impl HyperServiceAdaptor {
  fn new(s: plugin::Service) -> Self {
    Self { s: s }
  }
}

impl hyper_svc::Service<hyper::Request<hyper_body::Incoming>>
  for HyperServiceAdaptor
{
  type Error = anyhow::Error;
  type Future = Pin<Box<dyn Future<Output = Result<plugin::Response>>>>;
  type Response = plugin::Response;

  fn call(
    &self,
    req: http::Request<hyper_body::Incoming>,
  ) -> Self::Future {
    let (parts, body) = req.into_parts();
    let req = plugin::Request::from_parts(
      parts,
      plugin::RequestBody::new(plugin::BytesBufBodyWrapper::new(body)),
    );
    let s = self.s.clone();
    Box::pin(tower_util::Oneshot::new(s, req))
  }
}

#[derive(Clone)]
pub struct TokioLocalExecutor {}

impl<F> hyper::rt::Executor<F> for TokioLocalExecutor
where
  F: Future + 'static,
{
  fn execute(&self, fut: F) {
    task::spawn_local(fut);
  }
}

#[derive(Deserialize, Default, Clone, Debug)]
struct HyperListenerArgs {
  addresses: Vec<String>,
  protocols: Vec<String>,
  hostnames: Vec<String>,
}

struct HyperListener {
  addresses: Vec<SocketAddr>,
  _protocols: Vec<String>,
  _hostnames: Vec<String>,
  listening_set: Rc<RefCell<task::JoinSet<Result<()>>>>,
  conn_serving_set: Rc<RefCell<task::JoinSet<Result<()>>>>,
  shutdown_handle: plugin::ShutdownHandle,
  service: plugin::Service,
}

impl HyperListener {
  fn new(
    sargs: plugin::SerializedArgs,
    svc: plugin::Service,
  ) -> Result<plugin::Listener> {
    let args: HyperListenerArgs = serde_yaml::from_value(sargs)?;
    Ok(plugin::Listener::new(Self {
      addresses: args
        .addresses
        .iter()
        .filter_map(|s| {
          s.parse()
            .inspect_err(|e| warn!("address '{s}' invalid: {e}"))
            .ok()
        })
        .collect(),
      _protocols: args.protocols,
      _hostnames: args.hostnames,
      listening_set: Rc::new(RefCell::new(task::JoinSet::new())),
      conn_serving_set: Rc::new(RefCell::new(task::JoinSet::new())),
      shutdown_handle: plugin::ShutdownHandle::new(),
      service: svc,
    }))
  }

  fn serve_addr(
    &self,
    addr: SocketAddr,
    svc: plugin::Service,
  ) -> Result<Pin<Box<dyn Future<Output = Result<()>>>>> {
    let socket = net::TcpSocket::new_v4()?;
    socket.set_reuseaddr(true)?;
    socket.set_reuseport(true)?;
    socket.bind(addr)?;
    let listener = socket.listen(1024)?;
    let conn_serving_set = self.conn_serving_set.clone();
    let notifier = self.shutdown_handle.clone();
    let accepting_fut = async move {
      let shutdown = async move || notifier.notified().await;
      let accepting = async move || match listener.accept().await {
        Err(e) => {
          error!("accepting new connection failed: {e}");
        }
        Ok((stream, _raddr)) => {
          let io = rt_util::TokioIo::new(stream);
          let svc = HyperServiceAdaptor::new(svc.clone());
          let builder = conn_util::Builder::new(TokioLocalExecutor {});
          conn_serving_set.borrow_mut().spawn_local(async move {
            // Do not need any graceful shutdown actions here for
            // connections. The `Service`s should do this instead.
            let conn = builder.serve_connection_with_upgrades(io, svc);
            conn.await.map_err(|e| anyhow::Error::from_boxed(e))
          });
        }
      };

      loop {
        tokio::select! {
          _ = accepting() => {},
          _ = shutdown() => {
            // Graceful shutdown for the TcpListener.
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

impl plugin::Listening for HyperListener {
  fn start(&self) -> Pin<Box<dyn Future<Output = Result<()>>>> {
    let listening_set = self.listening_set.clone();
    for addr in &self.addresses {
      let addr = addr.clone();
      let service = self.service.clone();
      let serve_addr_fut = match self.serve_addr(addr, service) {
        Err(e) => return Box::pin(future::ready(Err(e))),
        Ok(f) => f,
      };
      listening_set.borrow_mut().spawn_local(serve_addr_fut);
    }

    let conn_serving_set = self.conn_serving_set.clone();
    let shutdown = self.shutdown_handle.clone();
    Box::pin(async move {
      // Waiting for graceful shutdown.
      shutdown.notified().await;

      while let Some(res) = listening_set.borrow_mut().join_next().await
      {
        match res {
          Err(e) => {
            error!("listening join error: {e}")
          }
          Ok(res) => match res {
            Err(e) => {
              error!("listening error: {e}")
            }
            Ok(_) => {}
          },
        }
      }

      while let Some(res) =
        conn_serving_set.borrow_mut().join_next().await
      {
        match res {
          Err(e) => {
            error!("connection join error: {e}")
          }
          Ok(res) => match res {
            Err(e) => {
              error!("connection error: {e}")
            }
            Ok(_) => {}
          },
        }
      }

      Ok(())
    })
  }

  fn stop(&self) {
    self.shutdown_handle.shutdown()
  }
}

struct HyperPlugin {
  listener_builders:
    HashMap<&'static str, Box<dyn plugin::BuildListener>>,
}

impl HyperPlugin {
  fn new() -> Self {
    let builder: Box<dyn plugin::BuildListener> =
      Box::new(HyperListener::new);
    let listener_factories = HashMap::from([("listener", builder)]);

    Self { listener_builders: listener_factories }
  }
}

impl plugin::Plugin for HyperPlugin {
  fn listener_builder(
    &self,
    name: &str,
  ) -> Option<&Box<dyn plugin::BuildListener>> {
    self.listener_builders.get(name)
  }
}

pub fn plugin_name() -> &'static str {
  "hyper"
}

pub fn create_plugin() -> Box<dyn plugin::Plugin> {
  Box::new(HyperPlugin::new())
}
