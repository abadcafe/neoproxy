use std::cell::RefCell;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use anyhow::{Result, anyhow};
use http_body_util::BodyExt;
use serde::Deserialize;
use tokio::net;
use tracing::{info, warn};

use super::utils;
use crate::plugin;

#[derive(Deserialize)]
struct ConnectTcpServiceArgs {}

#[derive(Clone)]
struct ConnectTcpService {
  transfering_set: Rc<RefCell<utils::TransferingSet>>,
}

impl ConnectTcpService {
  fn new(
    sargs: plugin::SerializedArgs,
    ts: Rc<RefCell<utils::TransferingSet>>,
  ) -> Result<plugin::Service> {
    Ok(plugin::Service::new(Self { transfering_set: ts }))
  }
}

impl tower::Service<plugin::Request> for ConnectTcpService {
  type Error = anyhow::Error;
  type Future = Pin<Box<dyn Future<Output = Result<Self::Response>>>>;
  type Response = plugin::Response;

  fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
    Poll::Ready(Ok(()))
  }

  fn call(&mut self, req: plugin::Request) -> Self::Future {
    let (req_headers, req_body) = req.into_parts();
    let ts = self.transfering_set.clone();
    Box::pin(async move {
      let (host, port) = utils::is_connect_method(&req_headers)?;
      let addrs: Vec<SocketAddr> =
        net::lookup_host(format!("{host}:{port}")).await?.collect();
      if addrs.len() == 0 {
        Err(anyhow!("no ip addresses resolved for {host}"))?;
      }

      let dest_stream = net::TcpStream::connect(addrs[0]).await?;
      let (receiving_stream, sending_stream) = dest_stream.into_split();
      let receiving_stream = utils::FramingReaderStream::new(
        tokio_util::io::ReaderStream::new(receiving_stream),
      );
      let resp_body = http_body_util::StreamBody::new(receiving_stream);
      let resp =
        plugin::Response::new(plugin::ResponseBody::new(resp_body));

      let req_body_stream = req_body
        // the anyhow::Error is hyper::Error actually.
        .map_err(|e| std::io::Error::other(e))
        .into_data_stream();
      let reader = tokio_util::io::StreamReader::new(req_body_stream);
      ts.borrow().new_transfering(reader, sending_stream)?;

      Ok(resp)
    })
  }
}

struct ConnectTcpPlugin {
  transfering_set: Rc<RefCell<utils::TransferingSet>>,
  service_builders:
    HashMap<&'static str, Box<dyn plugin::BuildService>>,
}

impl ConnectTcpPlugin {
  fn new() -> ConnectTcpPlugin {
    let ts = Rc::new(RefCell::new(utils::TransferingSet::new()));
    let ts_clone = ts.clone();

    let builder: Box<dyn plugin::BuildService> =
      Box::new(move |a| ConnectTcpService::new(a, ts.clone()));
    let service_builders = HashMap::from([("connect_tcp", builder)]);

    Self { transfering_set: ts_clone, service_builders }
  }
}

impl plugin::Plugin for ConnectTcpPlugin {
  fn service_builder(
    &self,
    name: &str,
  ) -> Option<&Box<dyn plugin::BuildService>> {
    self.service_builders.get(name)
  }

  fn finalize(&mut self) -> Pin<Box<dyn Future<Output = Result<()>>>> {
    let ts_clone = self.transfering_set.clone();
    Box::pin(async move { ts_clone.borrow_mut().stop().await })
  }
}

pub fn plugin_name() -> &'static str {
  "connect_tcp"
}

pub fn create_plugin() -> Box<dyn plugin::Plugin> {
  Box::new(ConnectTcpPlugin::new())
}
