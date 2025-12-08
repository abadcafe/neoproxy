use std::collections::HashMap;
use std::pin::Pin;

use anyhow::Result;
use bytes::Bytes;
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
  type Future =
    Pin<Box<dyn Future<Output = Result<plugin::Response>> + Send>>;
  type Response = plugin::Response;

  fn poll_ready(
    &mut self,
    cx: &mut std::task::Context<'_>,
  ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
    cx.waker().clone().wake();
    std::task::Poll::Ready(Ok(()))
  }

  fn call(&mut self, req: plugin::Request) -> Self::Future {
    let fut = async {
      let rb = req.collect().await?.to_bytes();
      let buf = Bytes::from(rb);
      let full = Full::new(buf);
      let body =
        plugin::ResponseBody::new(plugin::BytesBufBody::new(full));
      let resp = Response::builder().status(200).body(body).unwrap();
      Ok(resp)
    };
    Box::pin(fut)
  }
}

struct EchoPlugin {}

impl<'a> plugin::Plugin<'a> for EchoPlugin {
  fn name(&self) -> &'a str {
    "echo"
  }

  fn service_factories(
    &self,
  ) -> HashMap<&'a str, Box<dyn plugin::ServiceFactory>> {
    let boxed: Box<dyn plugin::ServiceFactory> =
      Box::new(EchoService::new);
    HashMap::from([("echo", boxed)])
  }
}

pub fn create_plugin() -> Box<dyn plugin::Plugin<'static>> {
  Box::new(EchoPlugin {})
}
