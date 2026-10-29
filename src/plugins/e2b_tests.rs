use tower::Service;

use super::e2b;
use crate::http_message::{BytesBufBodyWrapper, Request, RequestBody};

fn args(value: &str) -> crate::config::SerializedArgs {
  let _ = rustls::crypto::ring::default_provider().install_default();
  serde_yaml::from_str(value).unwrap()
}
fn request(id: Option<&str>) -> Request {
  let mut req = http::Request::builder()
    .method("CONNECT")
    .uri("127.0.0.1:8080")
    .body(RequestBody::new(BytesBufBodyWrapper::new(
      http_body_util::Empty::<bytes::Bytes>::new(),
    )))
    .unwrap();
  if let Some(id) = id {
    req.headers_mut().insert("x-sandbox-id", id.parse().unwrap());
  }
  req
}
#[test]
fn test_create_plugin_exposes_only_policy_layer() {
  let plugin = e2b::create_plugin(Some(&args(
    "policy_api_url: http://127.0.0.1:1/policy",
  )))
  .unwrap();
  assert_eq!(e2b::plugin_name(), "e2b");
  assert!(plugin.service_builder("upstream").is_none());
  assert!(plugin.layer_builder("unknown").is_none());
  assert!(plugin.layer_builder("sandbox_network_policy").is_some());
}
#[test]
fn test_create_plugin_rejects_invalid_configuration() {
  assert!(e2b::create_plugin(None).is_err());
  for config in [
    "policy_api_url: /relative",
    "policy_api_url: http://api/policy\npolicy_api_timeout: 0s",
    "policy_api_url: http://api/policy\nunknown: true",
  ] {
    assert!(e2b::create_plugin(Some(&args(config))).is_err());
  }
  let plugin = e2b::create_plugin(Some(&args(
    "policy_api_url: http://127.0.0.1:1/policy",
  )))
  .unwrap();
  let builder = plugin.layer_builder("sandbox_network_policy").unwrap();
  assert!(
    builder(args("default_policy: {}\npolicy_fallback_ttl: 0s"))
      .is_err()
  );
  assert!(
    builder(args("default_policy: {denyOut: [invalid]}")).is_err()
  );
}
#[tokio::test]
async fn test_layer_missing_empty_duplicate_identity_forbidden() {
  let plugin = e2b::create_plugin(Some(&args(
    "policy_api_url: http://127.0.0.1:1/policy",
  )))
  .unwrap();
  let layer = plugin.layer_builder("sandbox_network_policy").unwrap()(
    args("default_policy: {}"),
  )
  .unwrap();
  let mut service = layer.layer(crate::server::placeholder_service());
  for id in [None, Some("")] {
    assert_eq!(
      service.call(request(id)).await.unwrap().status(),
      http::StatusCode::FORBIDDEN
    );
  }
  let mut req = request(Some("one"));
  req.headers_mut().append("x-sandbox-id", "two".parse().unwrap());
  assert_eq!(
    service.call(req).await.unwrap().status(),
    http::StatusCode::FORBIDDEN
  );
}
#[tokio::test]
async fn test_layer_fetch_failure_uses_default_policy() {
  let plugin = e2b::create_plugin(Some(&args(
    "policy_api_url: http://127.0.0.1:1/policy",
  )))
  .unwrap();
  let layer = plugin.layer_builder("sandbox_network_policy").unwrap()(
    args("default_policy: {denyOut: [0.0.0.0/0]}"),
  )
  .unwrap();
  let mut service = layer.layer(crate::server::placeholder_service());
  assert_eq!(
    service.call(request(Some("sandbox"))).await.unwrap().status(),
    http::StatusCode::FORBIDDEN
  );
}
