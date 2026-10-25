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

use crate::config::SerializedArgs;
use crate::http_message::{Request, Response};
use crate::plugin::Plugin;
use crate::service::{BuildService, Service};

#[derive(Clone)]
pub(crate) struct EchoService {}

impl EchoService {
  pub(crate) fn build(args: SerializedArgs) -> Result<Service> {
    let _: crate::config::EmptyArgs = serde_yaml::from_value(args)?;
    Ok(Service::new(Self {}))
  }
}

impl tower::Service<Request> for EchoService {
  type Error = anyhow::Error;
  type Future = Pin<Box<dyn Future<Output = Result<Response>>>>;
  type Response = Response;

  fn poll_ready(
    &mut self,
    _cx: &mut Context<'_>,
  ) -> Poll<Result<(), Self::Error>> {
    Poll::Ready(Ok(()))
  }

  fn call(&mut self, req: Request) -> Self::Future {
    Box::pin(async move { Ok(Response::new(req.into_body())) })
  }
}

pub(crate) struct EchoPlugin {
  service_builders: HashMap<&'static str, Box<dyn BuildService>>,
}

impl EchoPlugin {
  pub(crate) fn new() -> Self {
    let builder: Box<dyn BuildService> = Box::new(EchoService::build);
    let service_builders = HashMap::from([("echo", builder)]);
    Self { service_builders }
  }
}

impl Plugin for EchoPlugin {
  fn service_builder(&self, name: &str) -> Option<&dyn BuildService> {
    self.service_builders.get(name).map(|b| b.as_ref())
  }
}

pub(crate) fn plugin_name() -> &'static str {
  "echo"
}

pub(crate) fn create_plugin(
  config: Option<&SerializedArgs>,
) -> Result<Box<dyn Plugin>> {
  if let Some(config) = config {
    let _: crate::config::EmptyArgs =
      serde_yaml::from_value(config.clone())?;
  }
  Ok(Box::new(EchoPlugin::new()))
}
