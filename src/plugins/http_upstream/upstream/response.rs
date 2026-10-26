//! module: response
//! responsibility: normalize responses crossing an upstream proxy hop
//! public operations: forward_response
//! data entities: none
//! tests: response_tests.rs

use super::proxy_auth::consume_proxy_auth_headers;
use crate::context::{RequestContext, get_server_id};
use crate::http_message::{Response, ResponseBody};
use crate::proxy_status::{
  append_proxy_status, build_proxy_status_with_status,
  take_proxy_status,
};

pub(super) fn forward_response(
  mut parts: http::response::Parts,
  body: ResponseBody,
  ctx: &RequestContext,
) -> Response {
  crate::hop_headers::strip_connection_headers(&mut parts.headers);
  // Origin transport discovery belongs to the terminal direct client.
  parts.headers.remove("alt-svc");
  crate::via::append(&mut parts.headers, parts.version);
  consume_proxy_auth_headers(&mut parts.headers);
  let upstream = take_proxy_status(&mut parts.headers);
  let status = get_server_id(ctx)
    .map(|id| {
      append_proxy_status(
        upstream.as_ref(),
        &build_proxy_status_with_status(&id, parts.status.as_u16()),
      )
    })
    .or(upstream);
  if let Some(status) = status {
    parts.headers.insert("proxy-status", status);
  }
  parts.version = http::Version::HTTP_11;
  Response::from_parts(parts, body)
}
