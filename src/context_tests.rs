//! Public typed storage and immutable request metadata contracts.
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::context::fields::{auth, connection, upstream};
use crate::context::{RequestContext, build_request_context};

#[test]
fn test_set_get_preserves_native_values_and_shared_clones() {
  let context = RequestContext::new();
  context.set(auth::USER, Arc::from("admin"));
  context.set(upstream::FORWARD_STATUS, 200);
  context.set(upstream::FORWARD_TIME, Duration::from_micros(1500));
  context.set(connection::REUSED, false);
  let cloned = context.clone();
  assert_eq!(cloned.get(auth::USER).as_deref(), Some("admin"));
  assert_eq!(cloned.get(upstream::FORWARD_STATUS), Some(200));
  assert_eq!(
    cloned.get(upstream::FORWARD_TIME),
    Some(Duration::from_micros(1500))
  );
  assert_eq!(cloned.get(connection::REUSED), Some(false));
  cloned.set(auth::USER, Arc::from("new"));
  assert_eq!(context.get(auth::USER).as_deref(), Some("new"));
}

#[test]
fn test_snapshot_selects_fields_and_preserves_json_types() {
  let context = RequestContext::new();
  context.set(auth::USER, Arc::from("admin"));
  context.set(upstream::FORWARD_STATUS, 201);
  context.set(connection::REUSED, true);
  let values = context.snapshot(&[
    "upstream.forward_status".into(),
    "upstream.connection.reused".into(),
    "unknown".into(),
  ]);
  let json = serde_json::to_value(values).unwrap();
  assert_eq!(json["upstream.forward_status"], 201);
  assert_eq!(json["upstream.connection.reused"], true);
  assert!(json.get("basic_auth.user").is_none());
  assert!(json.get("unknown").is_none());
}

#[test]
fn test_build_request_context_preserves_typed_metadata() {
  let peer: SocketAddr = "192.168.1.100:54321".parse().unwrap();
  let local: SocketAddr = "[::1]:8080".parse().unwrap();
  let context = build_request_context(&peer, &local, "proxy");
  assert_eq!(context.client_addr(), Some(peer));
  assert_eq!(context.server_addr(), Some(local));
  assert_eq!(context.service_name(), Some("proxy"));
  assert_eq!(
    context.server_addr().map(|address| address.to_string()).as_deref(),
    Some("[::1]:8080")
  );
  let selected =
    context.snapshot(&["client.port".into(), "server.ip".into()]);
  assert_eq!(
    serde_json::to_value(selected).unwrap(),
    serde_json::json!({"client.port":54321, "server.ip":"::1"})
  );
}

#[test]
fn test_with_request_id_and_service_preserves_identity_and_shared_data()
{
  let mut headers = http::HeaderMap::new();
  headers.insert("x-request-id", "caller-id".parse().unwrap());
  let id =
    crate::request_id::RequestId::read_or_generate(&headers).unwrap();
  let context = build_request_context(
    &"127.0.0.1:1".parse().unwrap(),
    &"127.0.0.1:2".parse().unwrap(),
    "",
  )
  .with_request_id(id);
  context.set(auth::USER, Arc::from("alice"));
  let routed = context.with_service("routed");
  assert_eq!(routed.request_id().unwrap().to_string(), "caller-id");
  assert_eq!(routed.service_name(), Some("routed"));
  assert_eq!(routed.get(auth::USER).as_deref(), Some("alice"));
  assert_eq!(
    routed.snapshot(&["request.id".into()])["request.id"].to_string(),
    "caller-id"
  );
}

#[test]
fn test_new_and_default_have_no_fabricated_connection_fields() {
  for context in [RequestContext::new(), RequestContext::default()] {
    assert!(context.get(auth::USER).is_none());
    assert!(context.client_addr().is_none());
    assert!(context.server_addr().is_none());
    assert!(context.service_name().is_none());
    assert!(
      context
        .server_addr()
        .map(|address| address.to_string())
        .is_none()
    );
  }
}
