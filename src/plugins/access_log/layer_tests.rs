use std::time::Instant;

use super::layer::{AccessLogLayer, build_log_entry};
use super::registry::LogEntry;
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
    vec![],
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
    vec![],
    "CONNECT",
    "example.com:443",
  );
  assert_eq!(entry.status, 500);
  assert!(entry.err.is_some());
  assert!(entry.err.unwrap().contains("connection refused"));
}

#[test]
fn test_build_log_entry_extracts_client_ip() {
  let ctx = RequestContext::new();
  ctx.insert("client.ip", "192.168.1.100");
  ctx.insert("client.port", "54321");
  let entry = build_log_entry(
    &make_ok_result(),
    Instant::now(),
    ctx,
    vec![],
    "GET",
    "/",
  );
  assert_eq!(entry.client_ip, "192.168.1.100");
  assert_eq!(entry.client_port, 54321);
}

#[test]
fn test_build_log_entry_extracts_server_ip() {
  let ctx = RequestContext::new();
  ctx.insert("server.ip", "10.0.0.1");
  ctx.insert("server.port", "8080");
  let entry = build_log_entry(
    &make_ok_result(),
    Instant::now(),
    ctx,
    vec![],
    "GET",
    "/",
  );
  assert_eq!(entry.server_ip, "10.0.0.1");
  assert_eq!(entry.server_port, 8080);
}

#[test]
fn test_build_log_entry_extracts_service_name() {
  let ctx = RequestContext::new();
  ctx.insert("service.name", "tunnel");
  let entry = build_log_entry(
    &make_ok_result(),
    Instant::now(),
    ctx,
    vec![],
    "CONNECT",
    "example.com:443",
  );
  assert_eq!(entry.service, "tunnel");
}

#[test]
fn test_build_log_entry_extracts_extensions() {
  let ctx = RequestContext::new();
  ctx.insert("basic_auth.user", "admin");
  ctx.insert("connect_tcp.connect_ms", "42");
  let entry = build_log_entry(
    &make_ok_result(),
    Instant::now(),
    ctx,
    vec![
      "basic_auth.user".to_string(),
      "connect_tcp.connect_ms".to_string(),
    ],
    "GET",
    "/",
  );
  assert_eq!(
    entry.extensions.get("basic_auth.user"),
    Some(&"admin".to_string())
  );
  assert_eq!(
    entry.extensions.get("connect_tcp.connect_ms"),
    Some(&"42".to_string())
  );
}

#[test]
fn test_build_log_entry_missing_context_defaults() {
  let ctx = RequestContext::new();
  let entry = build_log_entry(
    &make_ok_result(),
    Instant::now(),
    ctx,
    vec![],
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
    vec![],
    "CONNECT",
    "example.com:443",
  );
  assert_eq!(entry.method, "CONNECT");
  assert_eq!(entry.target, "example.com:443");
}

#[test]
fn test_build_log_entry_invalid_port_defaults_to_zero() {
  let ctx = RequestContext::new();
  ctx.insert("client.port", "not_a_number");
  ctx.insert("server.port", "99999");
  let entry = build_log_entry(
    &make_ok_result(),
    Instant::now(),
    ctx,
    vec![],
    "GET",
    "/",
  );
  assert_eq!(entry.client_port, 0);
  assert_eq!(entry.server_port, 0);
}

#[test]
fn test_build_log_entry_extensions_only_includes_requested_keys() {
  let ctx = RequestContext::new();
  ctx.insert("basic_auth.user", "admin");
  ctx.insert("other.key", "value");
  let entry = build_log_entry(
    &make_ok_result(),
    Instant::now(),
    ctx,
    vec!["basic_auth.user".to_string()],
    "GET",
    "/",
  );
  assert_eq!(entry.extensions.len(), 1);
  assert!(entry.extensions.contains_key("basic_auth.user"));
  assert!(!entry.extensions.contains_key("other.key"));
}

#[test]
fn test_build_log_entry_preserves_full_key_no_stripping() {
  let ctx = RequestContext::new();
  ctx.insert("auth.user", "admin");
  ctx.insert("audit.user", "auditor");
  let entry = build_log_entry(
    &make_ok_result(),
    Instant::now(),
    ctx,
    vec!["auth.user".to_string(), "audit.user".to_string()],
    "GET",
    "/",
  );
  assert_eq!(
    entry.extensions.len(),
    2,
    "Both extension entries must be preserved"
  );
  assert_eq!(
    entry.extensions.get("auth.user"),
    Some(&"admin".to_string()),
    "auth.user must map to 'admin'"
  );
  assert_eq!(
    entry.extensions.get("audit.user"),
    Some(&"auditor".to_string()),
    "audit.user must map to 'auditor'"
  );
}

#[test]
fn test_build_log_entry_no_dot_key_preserved_as_is() {
  let ctx = RequestContext::new();
  ctx.insert("custom_field", "value");
  let entry = build_log_entry(
    &make_ok_result(),
    Instant::now(),
    ctx,
    vec!["custom_field".to_string()],
    "GET",
    "/",
  );
  assert_eq!(entry.extensions.len(), 1);
  assert_eq!(
    entry.extensions.get("custom_field"),
    Some(&"value".to_string())
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

#[tokio::test]
async fn test_access_log_layer_warns_when_channel_full() {
  use tower::ServiceExt;

  let (capture, _guard) = TracingCapture::new();

  let (tx, _rx) = std::sync::mpsc::sync_channel::<LogEntry>(1);
  let dummy_entry = LogEntry {
    entry: super::context::AccessLogEntry {
      time: time::OffsetDateTime::now_utc(),
      client_ip: String::new(),
      client_port: 0,
      server_ip: String::new(),
      server_port: 0,
      method: String::new(),
      target: String::new(),
      status: 0,
      duration_ms: 0,
      service: String::new(),
      err: None,
      extensions: std::collections::HashMap::new(),
    },
  };
  tx.try_send(dummy_entry).unwrap();

  let access_log_layer = AccessLogLayer::new(tx, vec![]);
  let mut service = tower::Layer::layer(
    &access_log_layer,
    crate::server::placeholder_service(),
  );
  let svc = service.ready().await.unwrap();
  let _ = tower::Service::call(svc, empty_request()).await;

  let output = capture.output();
  assert!(
    output.contains("channel full"),
    "tracing should capture 'channel full' warning from middleware, \
     got: {:?}",
    &output[..output.len().min(500)]
  );
}

#[tokio::test]
async fn test_access_log_layer_warns_when_channel_closed() {
  use tower::ServiceExt;

  let (capture, _guard) = TracingCapture::new();

  let (tx, rx) = std::sync::mpsc::sync_channel::<LogEntry>(1);
  drop(rx);

  let access_log_layer = AccessLogLayer::new(tx, vec![]);
  let mut service = tower::Layer::layer(
    &access_log_layer,
    crate::server::placeholder_service(),
  );
  let svc = service.ready().await.unwrap();
  let _ = tower::Service::call(svc, empty_request()).await;

  let output = capture.output();
  assert!(
    output.contains("channel closed"),
    "tracing should capture 'channel closed' warning from middleware, \
     got: {:?}",
    &output[..output.len().min(500)]
  );
}
