//! Echo plugin — returns request body as response.
//!
//! module: echo
//! responsibilities: echo service that echoes request body back
//! public operations: plugin_name, create_plugin
//! data entities: EchoPlugin, EchoService
//! tests: echo_tests.rs

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::Result;
use http_body_util::{BodyExt, Full};

use crate::config::SerializedArgs;
use crate::http_utils::{
  BytesBufBodyWrapper, Request, Response, ResponseBody,
};
use crate::plugin::Plugin;
use crate::service::{BuildService, Service};

#[derive(Clone)]
pub(crate) struct EchoService {}

impl EchoService {
  #[allow(clippy::new_ret_no_self)]
  pub(crate) fn new(_args: SerializedArgs) -> Result<Service> {
    Ok(Service::new(Self {}))
  }
}

impl tower::Service<Request> for EchoService {
  type Error = anyhow::Error;
  type Future = Pin<Box<dyn Future<Output = Result<Response>>>>;
  type Response = Response;

  fn poll_ready(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<Result<(), Self::Error>> {
    cx.waker().wake_by_ref();
    Poll::Ready(Ok(()))
  }

  fn call(&mut self, req: Request) -> Self::Future {
    let fut = async {
      let req_body = req.collect().await?.to_bytes();
      let full = Full::new(req_body);
      let bytes_buf = BytesBufBodyWrapper::new(full);
      let resp_body = ResponseBody::new(bytes_buf);
      let mut resp = Response::new(resp_body);
      *resp.status_mut() = http::StatusCode::OK;
      Ok(resp)
    };
    Box::pin(fut)
  }
}

pub(crate) struct EchoPlugin {
  service_builders: HashMap<&'static str, Box<dyn BuildService>>,
}

impl EchoPlugin {
  pub(crate) fn new() -> Self {
    let builder: Box<dyn BuildService> = Box::new(EchoService::new);
    let service_builders = HashMap::from([("echo", builder)]);
    Self { service_builders }
  }
}

impl Plugin for EchoPlugin {
  fn service_builder(
    &self,
    name: &str,
  ) -> Option<&dyn BuildService> {
    self.service_builders.get(name).map(|b| b.as_ref())
  }
}

pub fn plugin_name() -> &'static str {
  "echo"
}

pub fn create_plugin(
  _config: Option<&SerializedArgs>,
) -> Result<Box<dyn Plugin>> {
  Ok(Box::new(EchoPlugin::new()))
}
