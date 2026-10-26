use super::response::forward_response;
use crate::context::build_request_context;
use crate::http_message::build_empty_response;

#[test]
fn test_forward_response_preserves_chain_and_consumes_hop_fields() {
  let mut original = build_empty_response(http::StatusCode::ACCEPTED);
  original
    .headers_mut()
    .append("proxy-status", "first".parse().unwrap());
  original
    .headers_mut()
    .append("proxy-status", "second".parse().unwrap());
  original.headers_mut().insert("connection", "x-hop".parse().unwrap());
  original.headers_mut().insert("x-hop", "private".parse().unwrap());
  original
    .headers_mut()
    .insert("proxy-authenticate", "Basic".parse().unwrap());
  let ctx = build_request_context(
    &"127.0.0.1:1234".parse().unwrap(),
    &"127.0.0.1:8080".parse().unwrap(),
    "proxy",
  );
  let (parts, body) = original.into_parts();
  let response = forward_response(parts, body, &ctx);
  assert_eq!(response.status(), http::StatusCode::ACCEPTED);
  assert_eq!(
    response.headers()["proxy-status"],
    "first, second, \"127.0.0.1:8080\"; received-status=202"
  );
  for name in ["connection", "x-hop", "proxy-authenticate"] {
    assert!(!response.headers().contains_key(name));
  }
}
