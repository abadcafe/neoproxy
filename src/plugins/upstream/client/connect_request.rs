//! module: connect_request
//! responsibilities: construct transport-independent CONNECT headers
//! public operations: build_connect_request
//! data entities: none
//! tests: connect_request_tests.rs

use crate::plugins::upstream::target_parser::ConnectTarget;

pub(crate) fn build_connect_request(
  target: &ConnectTarget,
  user: &Option<crate::config::UserCredential>,
  received: &http::request::Parts,
) -> http::Request<()> {
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
  *req.headers_mut() = received.headers.clone();
  req.extensions_mut().extend(received.extensions.clone());
  drop(crate::hop_headers::strip_connection_headers(req.headers_mut()));
  // CONNECT has no HTTP content/framing; target validation owns Host.
  req.headers_mut().remove(http::header::CONTENT_LENGTH);
  req.headers_mut().remove(http::header::TRAILER);
  req.headers_mut().insert(
    http::header::HOST,
    target.authority().parse().expect("validated CONNECT authority"),
  );
  crate::via::append(req.headers_mut(), received.version);
  super::proxy_auth::apply_proxy_auth(user, &mut req);
  if let Some(ctx) =
    received.extensions.get::<crate::context::RequestContext>()
    && let Some(id) = ctx.request_id()
  {
    id.apply(req.headers_mut());
  }
  req
}
