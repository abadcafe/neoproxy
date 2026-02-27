use std::collections::HashMap;
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::Result;
use http_body_util::{BodyExt, Full};
use hyper::Response;

use crate::plugin;

#[derive(Clone)]
struct EchoService {}

impl EchoService {
  fn new(_args: plugin::SerializedArgs) -> Result<plugin::Service> {
    Ok(plugin::Service::new(Self {}))
  }
}

impl tower::Service<plugin::Request> for EchoService {
  type Error = anyhow::Error;
  type Future = Pin<Box<dyn Future<Output = Result<plugin::Response>>>>;
  type Response = plugin::Response;

  fn poll_ready(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<Result<(), Self::Error>> {
    cx.waker().clone().wake();
    Poll::Ready(Ok(()))
  }

  fn call(&mut self, req: plugin::Request) -> Self::Future {
    let fut = async {
      let req_body = req.collect().await?.to_bytes();
      let full = Full::new(req_body);
      let bytes_buf = plugin::BytesBufBodyWrapper::new(full);
      let resp_body = plugin::ResponseBody::new(bytes_buf);
      let resp =
        Response::builder().status(200).body(resp_body).unwrap();
      Ok(resp)
    };
    Box::pin(fut)
  }
}

struct EchoPlugin {
  service_builders:
    HashMap<&'static str, Box<dyn plugin::BuildService>>,
}

impl EchoPlugin {
  fn new() -> Self {
    let builder: Box<dyn plugin::BuildService> =
      Box::new(move |a| EchoService::new(a));
    let service_builders = HashMap::from([("echo", builder)]);
    Self { service_builders }
  }
}

impl plugin::Plugin for EchoPlugin {
  fn service_builder(
    &self,
    name: &str,
  ) -> Option<&Box<dyn plugin::BuildService>> {
    self.service_builders.get(name)
  }
}

pub fn plugin_name() -> &'static str {
  "echo"
}

pub fn create_plugin() -> Box<dyn plugin::Plugin> {
  Box::new(EchoPlugin::new())
}
