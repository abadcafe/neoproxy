use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::Result;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Response;
use tracing::error;

use crate::plugin;

/// Build a standard 500 Internal Server Error response.
///
/// This function creates an HTTP 500 response with:
/// - Status: 500 Internal Server Error
/// - Content-Type: text/plain
/// - Body: "Internal Server Error"
///
/// The error_message parameter is intended for logging purposes,
/// but the response body is fixed to avoid exposing internal
/// error details to clients.
pub fn build_500_response(_error_message: &str) -> plugin::Response {
  let full = Full::new(Bytes::from("Internal Server Error"));
  let bytes_buf = plugin::BytesBufBodyWrapper::new(full);
  let body = plugin::ResponseBody::new(bytes_buf);
  let mut resp = plugin::Response::new(body);
  *resp.status_mut() = http::StatusCode::INTERNAL_SERVER_ERROR;
  resp.headers_mut().insert(
    http::header::CONTENT_TYPE,
    http::header::HeaderValue::from_static("text/plain"),
  );
  resp
}

/// Service error handling wrapper.
///
/// Wraps a future that produces a response, handling any errors
/// by logging them at ERROR level and returning a 500 response.
///
/// # Example
/// ```ignore
/// let result = handle_service_error(async {
///     // Service logic that may fail
///     Ok(response)
/// }).await;
/// ```
pub async fn handle_service_error<F>(f: F) -> Result<plugin::Response>
where
  F: Future<Output = Result<plugin::Response>>,
{
  match f.await {
    Ok(resp) => Ok(resp),
    Err(e) => {
      error!("Service error: {e}");
      Ok(build_500_response(&e.to_string()))
    }
  }
}

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

#[cfg(test)]
mod tests {
  use super::*;
  use crate::plugin::Plugin;
  use http_body_util::BodyExt;
  use std::task::{Context, Poll, RawWaker, RawWakerVTable};
  use tower::Service;

  fn dummy_waker() -> std::task::Waker {
    fn dummy_clone(_: *const ()) -> RawWaker {
      RawWaker::new(std::ptr::null(), &VTABLE)
    }
    fn dummy(_: *const ()) {}
    static VTABLE: RawWakerVTable =
      RawWakerVTable::new(dummy_clone, dummy, dummy, dummy);
    unsafe {
      std::task::Waker::from_raw(RawWaker::new(
        std::ptr::null(),
        &VTABLE,
      ))
    }
  }

  // ============== build_500_response Tests ==============

  #[test]
  fn test_build_500_response_status_code() {
    let resp = build_500_response("test error");
    assert_eq!(resp.status(), http::StatusCode::INTERNAL_SERVER_ERROR);
  }

  #[test]
  fn test_build_500_response_content_type() {
    let resp = build_500_response("test error");
    let content_type = resp.headers().get(http::header::CONTENT_TYPE);
    assert!(content_type.is_some());
    assert_eq!(content_type.unwrap().to_str().unwrap(), "text/plain");
  }

  #[tokio::test]
  async fn test_build_500_response_body() {
    let resp = build_500_response("test error");
    let body = resp.into_body();
    let bytes = body.collect().await.unwrap().to_bytes();
    assert_eq!(bytes, Bytes::from("Internal Server Error"));
  }

  #[test]
  fn test_build_500_response_empty_message() {
    let resp = build_500_response("");
    assert_eq!(resp.status(), http::StatusCode::INTERNAL_SERVER_ERROR);
  }

  #[test]
  fn test_build_500_response_long_message() {
    let long_message = "This is a very long error message \
      that should not appear in the response body";
    let resp = build_500_response(long_message);
    assert_eq!(resp.status(), http::StatusCode::INTERNAL_SERVER_ERROR);
  }

  // ============== handle_service_error Tests ==============

  #[tokio::test]
  async fn test_handle_service_error_success() {
    // Create a successful 200 response
    let full = Full::new(Bytes::from("success"));
    let bytes_buf = plugin::BytesBufBodyWrapper::new(full);
    let body = plugin::ResponseBody::new(bytes_buf);
    let success_response =
      http::Response::builder().status(200).body(body).unwrap();

    let result: Result<plugin::Response> =
      handle_service_error(async { Ok(success_response) }).await;
    assert!(result.is_ok());
    let resp = result.unwrap();
    // The success response should be returned as-is
    assert_eq!(resp.status(), http::StatusCode::OK);
  }

  #[tokio::test]
  async fn test_handle_service_error_returns_ok_result() {
    // handle_service_error always returns Ok, even when inner fails
    let result: Result<plugin::Response> =
      handle_service_error(async {
        Err(anyhow::anyhow!("service error"))
      })
      .await;
    assert!(result.is_ok());
  }

  #[tokio::test]
  async fn test_handle_service_error_returns_500_on_error() {
    let result: Result<plugin::Response> =
      handle_service_error(async {
        Err(anyhow::anyhow!("service error"))
      })
      .await;
    assert!(result.is_ok());
    let resp = result.unwrap();
    assert_eq!(resp.status(), http::StatusCode::INTERNAL_SERVER_ERROR);
  }

  #[tokio::test]
  async fn test_handle_service_error_body_on_error() {
    let result: Result<plugin::Response> =
      handle_service_error(async {
        Err(anyhow::anyhow!("detailed error message"))
      })
      .await;
    let resp = result.unwrap();
    let body = resp.into_body();
    let bytes = body.collect().await.unwrap().to_bytes();
    // Body should be generic message, not the detailed error
    assert_eq!(bytes, Bytes::from("Internal Server Error"));
  }

  #[tokio::test]
  async fn test_handle_service_error_content_type_on_error() {
    let result: Result<plugin::Response> =
      handle_service_error(async { Err(anyhow::anyhow!("error")) })
        .await;
    let resp = result.unwrap();
    let content_type = resp.headers().get(http::header::CONTENT_TYPE);
    assert!(content_type.is_some());
    assert_eq!(content_type.unwrap().to_str().unwrap(), "text/plain");
  }

  #[tokio::test]
  async fn test_handle_service_error_preserves_successful_response() {
    // Create a custom 200 response
    let full = Full::new(Bytes::from("hello"));
    let bytes_buf = plugin::BytesBufBodyWrapper::new(full);
    let body = plugin::ResponseBody::new(bytes_buf);
    let custom_resp =
      http::Response::builder().status(200).body(body).unwrap();

    let result: Result<plugin::Response> =
      handle_service_error(async { Ok(custom_resp) }).await;
    assert!(result.is_ok());
    let resp = result.unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(bytes, Bytes::from("hello"));
  }

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
    let waker = dummy_waker();
    let mut cx = Context::from_waker(&waker);
    let result = Service::poll_ready(&mut service, &mut cx);
    assert!(matches!(result, Poll::Ready(Ok(()))));
  }

  fn make_echo_request(body: &[u8]) -> plugin::Request {
    let full = Full::new(Bytes::from(body.to_vec()));
    let bytes_buf = plugin::BytesBufBodyWrapper::new(full);
    let body = plugin::RequestBody::new(bytes_buf);
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
