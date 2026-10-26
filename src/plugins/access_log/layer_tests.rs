use std::sync::Arc;
use std::time::Instant;

use super::layer::{
  AccessLogLayer, DeliveryError, LogSink, build_log_entry,
};
use super::tracing_capture::TracingCapture;
use crate::context::RequestContext;
use crate::http_message::Response;

fn make_ok_result() -> anyhow::Result<Response> {
  Ok(crate::http_message::build_empty_response(http::StatusCode::OK))
}

fn make_err_result() -> anyhow::Result<Response> {
  Err(anyhow::anyhow!("connection refused"))
}

#[test]
fn test_build_log_entry_success_status() {
  let ctx = RequestContext::new();
  let entry = build_log_entry(
    &make_ok_result(),
    Instant::now(),
    ctx,
    &[],
    "GET",
    "http://example.com/",
  );
  assert_eq!(entry.status, 200);
  assert!(entry.err.is_none());
}

#[test]
fn test_build_log_entry_error_status_and_message() {
  let ctx = RequestContext::new();
  let entry = build_log_entry(
    &make_err_result(),
    Instant::now(),
    ctx,
    &[],
    "CONNECT",
    "example.com:443",
  );
  assert_eq!(entry.status, 500);
  assert!(entry.err.is_some());
  assert!(entry.err.unwrap().contains("connection refused"));
}

#[test]
fn test_build_log_entry_extracts_client_ip() {
  let ctx = crate::context::build_request_context(
    &"192.168.1.100:54321".parse().unwrap(),
    &"10.0.0.1:8080".parse().unwrap(),
    "tunnel",
  );
  let entry = build_log_entry(
    &make_ok_result(),
    Instant::now(),
    ctx,
    &[],
    "GET",
    "/",
  );
  assert_eq!(entry.client_ip, "192.168.1.100");
  assert_eq!(entry.client_port, 54321);
}

#[test]
fn test_build_log_entry_extracts_server_ip() {
  let ctx = crate::context::build_request_context(
    &"192.168.1.100:54321".parse().unwrap(),
    &"10.0.0.1:8080".parse().unwrap(),
    "tunnel",
  );
  let entry = build_log_entry(
    &make_ok_result(),
    Instant::now(),
    ctx,
    &[],
    "GET",
    "/",
  );
  assert_eq!(entry.server_ip, "10.0.0.1");
  assert_eq!(entry.server_port, 8080);
}

#[test]
fn test_build_log_entry_extracts_service_name() {
  let ctx = crate::context::build_request_context(
    &"192.168.1.100:54321".parse().unwrap(),
    &"10.0.0.1:8080".parse().unwrap(),
    "tunnel",
  );
  let entry = build_log_entry(
    &make_ok_result(),
    Instant::now(),
    ctx,
    &[],
    "CONNECT",
    "example.com:443",
  );
  assert_eq!(entry.service, "tunnel");
}

#[test]
fn test_build_log_entry_extracts_extensions() {
  let ctx = RequestContext::new();
  ctx.set(
    crate::context::fields::auth::USER,
    std::sync::Arc::from("admin"),
  );
  ctx.set(
    crate::context::fields::upstream::CONNECT_TIME,
    std::time::Duration::from_millis(42),
  );
  let entry = build_log_entry(
    &make_ok_result(),
    Instant::now(),
    ctx,
    &["basic_auth.user".to_string(), "upstream.connect_ms".to_string()],
    "GET",
    "/",
  );
  assert_eq!(
    entry.extensions.get("basic_auth.user"),
    Some(&crate::context::value::ContextValue::from("admin"))
  );
  assert_eq!(
    entry.extensions.get("upstream.connect_ms"),
    Some(&crate::context::value::ContextValue::from(
      std::time::Duration::from_millis(42)
    ))
  );
}

#[test]
fn test_build_log_entry_missing_context_defaults() {
  let ctx = RequestContext::new();
  let entry = build_log_entry(
    &make_ok_result(),
    Instant::now(),
    ctx,
    &[],
    "GET",
    "/",
  );
  assert_eq!(entry.client_ip, "");
  assert_eq!(entry.client_port, 0);
  assert_eq!(entry.server_ip, "");
  assert_eq!(entry.server_port, 0);
  assert_eq!(entry.service, "");
  assert!(entry.extensions.is_empty());
}

#[test]
fn test_build_log_entry_preserves_method_and_target() {
  let ctx = RequestContext::new();
  let entry = build_log_entry(
    &make_ok_result(),
    Instant::now(),
    ctx,
    &[],
    "CONNECT",
    "example.com:443",
  );
  assert_eq!(entry.method, "CONNECT");
  assert_eq!(entry.target, "example.com:443");
}

#[test]
fn test_build_log_entry_extensions_only_includes_requested_keys() {
  let ctx = RequestContext::new();
  ctx.set(
    crate::context::fields::auth::USER,
    std::sync::Arc::from("admin"),
  );
  ctx.set(
    crate::context::fields::auth::AUTH_TYPE,
    std::sync::Arc::from("password"),
  );
  let entry = build_log_entry(
    &make_ok_result(),
    Instant::now(),
    ctx,
    &["basic_auth.user".to_string()],
    "GET",
    "/",
  );
  assert_eq!(entry.extensions.len(), 1);
  assert!(entry.extensions.contains_key("basic_auth.user"));
  assert!(!entry.extensions.contains_key("basic_auth.auth_type"));
}

#[test]
fn test_build_log_entry_preserves_full_key_no_stripping() {
  let ctx = RequestContext::new();
  ctx.set(
    crate::context::fields::auth::USER,
    std::sync::Arc::from("admin"),
  );
  ctx.set(
    crate::context::fields::auth::PROXY_ID,
    std::sync::Arc::from("auditor"),
  );
  let entry = build_log_entry(
    &make_ok_result(),
    Instant::now(),
    ctx,
    &["basic_auth.user".to_string(), "proxy_id".to_string()],
    "GET",
    "/",
  );
  assert_eq!(
    entry.extensions.len(),
    2,
    "Both extension entries must be preserved"
  );
  assert_eq!(
    entry.extensions.get("basic_auth.user"),
    Some(&crate::context::value::ContextValue::from("admin")),
    "auth.user must map to 'admin'"
  );
  assert_eq!(
    entry.extensions.get("proxy_id"),
    Some(&crate::context::value::ContextValue::from("auditor")),
    "audit.user must map to 'auditor'"
  );
}

#[test]
fn test_build_log_entry_no_dot_key_preserved_as_is() {
  let ctx = RequestContext::new();
  ctx.set(
    crate::context::fields::auth::PROXY_ID,
    std::sync::Arc::from("value"),
  );
  let entry = build_log_entry(
    &make_ok_result(),
    Instant::now(),
    ctx,
    &["proxy_id".to_string()],
    "GET",
    "/",
  );
  assert_eq!(entry.extensions.len(), 1);
  assert_eq!(
    entry.extensions.get("proxy_id"),
    Some(&crate::context::value::ContextValue::from("value"))
  );
}

fn empty_request() -> crate::http_message::Request {
  use http_body_util::BodyExt;

  let body: crate::http_message::RequestBody =
    http_body_util::Empty::<bytes::Bytes>::new()
      .map_err(|e: std::convert::Infallible| anyhow::anyhow!("{}", e))
      .boxed_unsync();
  http::Request::builder()
    .method("GET")
    .uri("http://example.com/")
    .body(body)
    .unwrap()
}

struct FailingSink {
  error: DeliveryError,
}
impl LogSink for FailingSink {
  fn record(
    &self,
    _entry: super::context::AccessLogEntry,
  ) -> Result<(), DeliveryError> {
    Err(self.error)
  }
}

#[tokio::test]
async fn test_access_log_layer_warns_when_sink_full() {
  use tower::ServiceExt;

  let (capture, _guard) = TracingCapture::new();

  let access_log_layer = AccessLogLayer::new(
    Arc::new(FailingSink { error: DeliveryError::Full }),
    vec![],
  );
  let mut service = tower::Layer::layer(
    &access_log_layer,
    crate::server::placeholder_service(),
  );
  let svc = service.ready().await.unwrap();
  let _ = tower::Service::call(svc, empty_request()).await;

  let output = capture.output();
  assert!(
    output.contains("sink full"),
    "tracing should capture 'sink full' warning from middleware, got: \
     {:?}",
    &output[..output.len().min(500)]
  );
}

#[tokio::test]
async fn test_access_log_layer_warns_when_sink_stopped() {
  use tower::ServiceExt;

  let (capture, _guard) = TracingCapture::new();

  let access_log_layer = AccessLogLayer::new(
    Arc::new(FailingSink { error: DeliveryError::Stopped }),
    vec![],
  );
  let mut service = tower::Layer::layer(
    &access_log_layer,
    crate::server::placeholder_service(),
  );
  let svc = service.ready().await.unwrap();
  let _ = tower::Service::call(svc, empty_request()).await;

  let output = capture.output();
  assert!(
    output.contains("sink stopped"),
    "tracing should capture 'sink stopped' warning from middleware, \
     got: {:?}",
    &output[..output.len().min(500)]
  );
}

#[tokio::test]
async fn test_access_log_layer_preserves_service_failure() {
  use tower::ServiceExt;
  let layer = AccessLogLayer::new(
    Arc::new(FailingSink { error: DeliveryError::Full }),
    vec![],
  );
  let service =
    tower::Layer::layer(&layer, crate::server::placeholder_service());
  let result = service.oneshot(empty_request()).await;
  assert!(
    result.is_err(),
    "observability must preserve the service result"
  );
  assert_eq!(result.unwrap_err().to_string(), "placeholder");
}
