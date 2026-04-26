use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::Result;
use http_body_util::{BodyExt, Full};

use crate::http_types::{
  BytesBufBodyWrapper, Request,  Response, ResponseBody,
};
use crate::plugin;

#[derive(Clone)]
struct EchoService {}

impl EchoService {
  #[allow(clippy::new_ret_no_self)]
  fn new(_args: plugin::SerializedArgs) -> Result<plugin::Service> {
    Ok(plugin::Service::new(Self {}))
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

struct EchoPlugin {
  service_builders:
    HashMap<&'static str, Box<dyn plugin::BuildService>>,
}

impl EchoPlugin {
  fn new() -> Self {
    let builder: Box<dyn plugin::BuildService> =
      Box::new(EchoService::new);
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

#[cfg(test)]
mod tests {
  use super::*;
  use crate::http_types::RequestBody;
  use crate::plugin::Plugin;
  use bytes::Bytes;
  use futures::task::noop_waker;
  use http_body_util::BodyExt;
  use std::task::{Context, Poll};
  use tower::Service;

  // ============== EchoService Tests ==============

  #[test]
  fn test_echo_service_new() {
    let result = EchoService::new(serde_yaml::Value::Null);
    assert!(result.is_ok());
  }

  #[test]
  fn test_echo_service_poll_ready() {
    let mut service =
      EchoService::new(serde_yaml::Value::Null).unwrap();
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let result = Service::poll_ready(&mut service, &mut cx);
    assert!(matches!(result, Poll::Ready(Ok(()))));
  }

  fn make_echo_request(body: &[u8]) -> Request {
    let full = Full::new(Bytes::from(body.to_vec()));
    let bytes_buf = BytesBufBodyWrapper::new(full);
    let body = RequestBody::new(bytes_buf);
    http::Request::builder()
      .method(http::Method::POST)
      .uri("/echo")
      .body(body)
      .unwrap()
  }

  #[tokio::test]
  async fn test_echo_service_call_empty_body() {
    let mut service =
      EchoService::new(serde_yaml::Value::Null).unwrap();
    let req = make_echo_request(b"");
    let fut = service.call(req);
    let resp = fut.await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert!(body.is_empty());
  }

  #[tokio::test]
  async fn test_echo_service_call_with_body() {
    let mut service =
      EchoService::new(serde_yaml::Value::Null).unwrap();
    let req = make_echo_request(b"hello world");
    let fut = service.call(req);
    let resp = fut.await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, Bytes::from("hello world"));
  }

  #[tokio::test]
  async fn test_echo_service_call_large_body() {
    let mut service =
      EchoService::new(serde_yaml::Value::Null).unwrap();
    let large_data = vec![0u8; 1024 * 1024]; // 1MB
    let req = make_echo_request(&large_data);
    let fut = service.call(req);
    let resp = fut.await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body.len(), large_data.len());
  }

  // ============== EchoPlugin Tests ==============

  #[test]
  fn test_plugin_name() {
    assert_eq!(plugin_name(), "echo");
  }

  #[test]
  fn test_create_plugin() {
    let plugin = create_plugin();
    assert!(plugin.service_builder("echo").is_some());
  }

  #[test]
  fn test_echo_plugin_service_builder_valid_name() {
    let plugin = EchoPlugin::new();
    let builder = plugin.service_builder("echo");
    assert!(builder.is_some());
  }

  #[test]
  fn test_echo_plugin_service_builder_invalid_name() {
    let plugin = EchoPlugin::new();
    let builder = plugin.service_builder("invalid");
    assert!(builder.is_none());
  }

  #[test]
  fn test_echo_plugin_new_creates_builder() {
    let plugin = EchoPlugin::new();
    let builder = plugin.service_builder("echo").unwrap();
    let service = builder(serde_yaml::Value::Null);
    assert!(service.is_ok());
  }
}
