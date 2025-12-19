use std::cell::RefCell;
use std::collections::HashMap;
use std::future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;

use anyhow::Result;
use hyper::{body as hyper_body, service as hyper_svc};
use hyper_util::rt as rt_util;
use hyper_util::server::conn::auto as conn_util;
use serde::Deserialize;
use tokio::{net, sync, task};
use tower::util as tower_util;
use tracing::{error, info};

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
    req: hyper::Request<hyper_body::Incoming>,
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

struct HyperListenerCloser {
  shutdown: Arc<sync::Notify>,
}

impl plugin::ListenerCloserTrait for HyperListenerCloser {
  fn shutdown(&self) {
    self.shutdown.notify_waiters()
  }
}

struct HyperListener {
  addresses: Vec<SocketAddr>,
  _protocols: Vec<String>,
  _hostnames: Vec<String>,
  listening_join_set: Rc<RefCell<task::JoinSet<Result<()>>>>,
  conn_join_set: Rc<RefCell<task::JoinSet<Result<()>>>>,
  shutdown: Arc<sync::Notify>,
  service: plugin::Service,
}

impl HyperListener {
  fn new(
    sargs: plugin::SerializedArgs,
    svc: plugin::Service,
  ) -> Result<(plugin::Listener, plugin::ListenerCloser)> {
    let args: HyperListenerArgs = serde_yaml::from_value(sargs)?;
    let shutdown = Arc::new(sync::Notify::new());
    Ok((
      Box::new(Self {
        addresses: args
          .addresses
          .iter()
          .filter_map(|s| {
            s.parse()
              .inspect_err(|e| error!("address '{s}' invalid: {e}"))
              .ok()
          })
          .collect(),
        _protocols: args.protocols,
        _hostnames: args.hostnames,
        listening_join_set: Rc::new(RefCell::new(task::JoinSet::new())),
        conn_join_set: Rc::new(RefCell::new(task::JoinSet::new())),
        shutdown: shutdown.clone(),
        service: svc,
      }),
      Box::new(HyperListenerCloser { shutdown: shutdown }),
    ))
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
    let conn_join_set = self.conn_join_set.clone();
    let notifier = self.shutdown.clone();
    let accepting_fut = async move {
      let accepting = async move || match listener.accept().await {
        Err(e) => {
          todo!()
        }
        Ok((stream, _raddr)) => {
          let io = rt_util::TokioIo::new(stream);
          let svc = HyperServiceAdaptor::new(svc.clone());
          let builder = conn_util::Builder::new(TokioLocalExecutor {});
          conn_join_set.borrow_mut().spawn_local(async move {
            let conn = builder.serve_connection(io, svc);
            conn.await.map_err(|e| anyhow::Error::from_boxed(e))
          });
        }
      };

      let shutdown = async || notifier.notified().await;

      loop {
        tokio::select! {
          _ = accepting() => {},
          _ = shutdown() => { break },
        }
      }
      // here the TcpListener dropped so the socket closed.
      Ok(())
    };

    Ok(Box::pin(accepting_fut))
  }
}

impl plugin::ListenerTrait for HyperListener {
  fn serve(&mut self) -> Pin<Box<dyn Future<Output = Result<()>>>> {
    let listening_join_set = self.listening_join_set.clone();
    for addr in &self.addresses {
      let addr = addr.clone();
      let service = self.service.clone();
      let serve_addr_fut = match self.serve_addr(addr, service) {
        Err(e) => return Box::pin(future::ready(Err(e))),
        Ok(f) => f,
      };
      listening_join_set.borrow_mut().spawn_local(serve_addr_fut);
    }

    let conn_join_set = self.conn_join_set.clone();
    let shutdown = self.shutdown.clone();
    Box::pin(async move {
      shutdown.notified().await;

      while let Some(res) =
        listening_join_set.borrow_mut().join_next().await
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

      while let Some(res) = conn_join_set.borrow_mut().join_next().await
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

      Ok(())
    })
  }
}

struct HyperPlugin {}

impl<'a> plugin::Plugin<'a> for HyperPlugin {
  fn name(&self) -> &'a str {
    "hyper"
  }

  fn listener_factories(
    &self,
  ) -> HashMap<&'a str, Box<dyn plugin::ListenerFactory>> {
    let boxed: Box<dyn plugin::ListenerFactory> =
      Box::new(HyperListener::new);
    HashMap::from([("hyper", boxed)])
  }
}

pub fn create_plugin() -> Box<dyn plugin::Plugin<'static>> {
  Box::new(HyperPlugin {})
}
