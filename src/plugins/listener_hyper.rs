use std::cell::RefCell;
use std::collections::HashMap;
use std::net as std_net;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;

use anyhow::Result;
use hyper::Request as HyperRequest;
use hyper::body::Incoming as HyperIncoming;
use hyper::service::Service as HyperService;
use hyper_util::rt as rt_util;
use hyper_util::server::conn::auto as conn_util;
use serde::Deserialize;
use tokio::sync::Notify;
use tokio::{net, task};
use tower::util::Oneshot;
use tracing::error;

use crate::plugin;

struct HyperServiceAdaptor {
  s: plugin::Service,
}

impl HyperServiceAdaptor {
  fn new(s: plugin::Service) -> Self {
    Self { s: s }
  }
}

impl HyperService<HyperRequest<HyperIncoming>> for HyperServiceAdaptor {
  type Error = anyhow::Error;
  type Future = Pin<Box<dyn Future<Output = Result<plugin::Response>>>>;
  type Response = plugin::Response;

  fn call(&self, req: HyperRequest<HyperIncoming>) -> Self::Future {
    let (parts, body) = req.into_parts();
    let req = plugin::Request::from_parts(
      parts,
      plugin::RequestBody::new(plugin::BytesBufBodyWrapper::new(body)),
    );
    let s = self.s.clone();
    Box::pin(Oneshot::new(s, req))
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
struct HyperArgs {
  addresses: Vec<String>,
  protocols: Vec<String>,
  hostnames: Vec<String>,
}

struct HyperListenerCloser {
  shutdown: Arc<Notify>,
}

impl plugin::ListenerCloserTrait for HyperListenerCloser {
  fn shutdown(&self) {
    self.shutdown.notify_waiters()
  }
}

struct HyperListener {
  addresses: Vec<std_net::SocketAddr>,
  _protocols: Vec<String>,
  _hostnames: Vec<String>,
  listening_join_set: RefCell<task::JoinSet<Result<()>>>,
  conn_join_set: RefCell<task::JoinSet<Result<()>>>,
  shutdown: Arc<Notify>,
  service: plugin::Service,
}

impl HyperListener {
  fn new(
    sargs: plugin::SerializedArgs,
    svc: plugin::Service,
  ) -> Result<(plugin::Listener, plugin::ListenerCloser)> {
    let args: HyperArgs = serde_yaml::from_value(sargs)?;
    let shutdown = Arc::new(Notify::new());
    Ok((
      Box::new(Self {
        addresses: args
          .addresses
          .iter()
          .filter_map(|a| {
            a.parse()
              .inspect_err(|e| {
                error!("parse listening address '{a}' failed: {e}")
              })
              .ok()
          })
          .collect(),
        _protocols: args.protocols,
        _hostnames: args.hostnames,
        listening_join_set: RefCell::new(task::JoinSet::new()),
        conn_join_set: RefCell::new(task::JoinSet::new()),
        shutdown: shutdown.clone(),
        service: svc,
      }),
      Box::new(HyperListenerCloser { shutdown: shutdown }),
    ))
  }

  async fn serve_addr(
    self: Rc<Self>,
    addr: std_net::SocketAddr,
    svc: plugin::Service,
  ) -> Result<()> {
    let socket = net::TcpSocket::new_v4()?;
    socket.set_reuseaddr(true)?;
    socket.set_reuseport(true)?;
    socket.bind(addr)?;
    let listener = socket.listen(1024)?;
    let accepting = async || match listener.accept().await {
      Err(e) => {
        todo!()
      }
      Ok((stream, _raddr)) => {
        let io = rt_util::TokioIo::new(stream);
        let svc = HyperServiceAdaptor::new(svc.clone());
        let builder = conn_util::Builder::new(TokioLocalExecutor {});
        let mut conn_join_set = self.conn_join_set.borrow_mut();
        conn_join_set.spawn_local(async move {
          let conn = builder.serve_connection(io, svc);
          conn.await.map_err(|e| anyhow::Error::from_boxed(e))
        });
      }
    };

    let notifier = self.shutdown.clone();
    let shutdown = async || notifier.notified().await;

    loop {
      tokio::select! {
        _ = accepting() => {},
        _ = shutdown() => { break },
      }
    }

    // here the TcpListener dropped so the socket closed.
    Ok(())
  }
}

impl plugin::ListenerTrait for HyperListener {
  fn serve(
    self: Rc<Self>,
  ) -> Pin<Box<dyn Future<Output = Result<()>>>> {
    Box::pin(async move {
      for addr in &self.clone().addresses {
        let addr = addr.clone();
        let service = self.clone().service.clone();
        self
          .listening_join_set
          .borrow_mut()
          .spawn_local(self.clone().serve_addr(addr, service));
      }

      self.shutdown.notified().await;

      while let Some(res) =
        self.listening_join_set.borrow_mut().join_next().await
      {
        match res {
          Err(e) => {
            println!("listening join error: {e}")
          }
          Ok(res) => match res {
            Err(e) => {
              println!("listening error: {e}")
            }
            Ok(_) => {}
          },
        }
      }

      while let Some(res) =
        self.conn_join_set.borrow_mut().join_next().await
      {
        match res {
          Err(e) => {
            println!("listening join error: {e}")
          }
          Ok(res) => match res {
            Err(e) => {
              println!("listening error: {e}")
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
