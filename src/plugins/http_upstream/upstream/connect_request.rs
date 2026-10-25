//! module: connect_request
//! responsibilities: encode a validated target as an upstream HTTP
//! CONNECT public operations: build_connect_request
//! data entities: none
//! tests: connect_request_tests.rs

use crate::http_message::{BytesBufBodyWrapper, RequestBody};
use crate::plugins::http_upstream::target_parser::ConnectTarget;

pub(crate) fn build_connect_request(
  target: &ConnectTarget,
  user: &Option<crate::config::UserCredential>,
) -> http::Request<RequestBody> {
  // ConnectTarget guarantees a validated ASCII authority and port.
  // With a fixed method and header name, builder failure is an internal
  // invariant violation. Intentionally panic to expose the programming
  // error instead of returning a recoverable upstream failure.
  let mut req = http::Request::builder()
    .method(http::Method::CONNECT)
    .uri(target.uri())
    .header(http::header::HOST, target.authority())
    .body(())
    .expect("validated CONNECT target must build an upstream request");
  super::proxy_auth::apply_proxy_auth(user, &mut req);
  let empty = http_body_util::Empty::new();
  let wrapped = BytesBufBodyWrapper::new(empty);
  let body = RequestBody::new(wrapped);
  let (parts, _) = req.into_parts();
  http::Request::from_parts(parts, body)
}
