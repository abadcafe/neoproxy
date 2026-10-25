//! module: forward
//! responsibilities: translate a forward request and streamed response
//! across an HTTP hop public operations: chain_forward_http
//! data entities: none
//! tests: forward_tests.rs
use std::time::Instant;

use hyper_util::client::legacy::Client;
use tracing::warn;

use super::proxy_auth::{apply_proxy_auth, consume_proxy_auth_headers};
use crate::context::{RequestContext, get_server_id};
use crate::http_message::{
  BytesBufBodyWrapper, RequestBody, Response, ResponseBody,
  build_error_response,
};
use crate::plugins::http_upstream::error::classify_http_client_error;
use crate::plugins::http_upstream::target_parser::ForwardTarget;
use crate::proxy_status::{
  append_proxy_status, build_proxy_status_with_status,
};

/// Forward an HTTP request over HTTP/1.1 or HTTPS/1.1 to the upstream
/// proxy. Uses hyper::Client which handles connection pooling
/// internally.
pub(super) async fn chain_forward_http<C>(
  client: Client<C, RequestBody>,
  user: Option<crate::config::UserCredential>,
  target: &ForwardTarget,
  mut req_headers: http::request::Parts,
  req_body: RequestBody,
  ctx: &RequestContext,
) -> Response
where
  C: hyper_util::client::legacy::connect::Connect
    + Clone
    + Send
    + Sync
    + Unpin
    + 'static,
{
  let headers = &mut req_headers.headers;
  crate::hop_headers::strip_connection_headers(headers);
  crate::hop_headers::join_cookie_headers(headers);
  let host_header = match target.host_header_value() {
    Ok(value) => value,
    Err(e) => {
      warn!("http_upstream: invalid forward target authority: {e}");
      return build_error_response(
        http::StatusCode::BAD_REQUEST,
        "Invalid target address",
      );
    }
  };
  headers.insert(http::header::HOST, host_header);

  req_headers.uri = target.absolute_uri().clone();
  req_headers.version = http::Version::HTTP_11;
  let mut fwd_req = http::Request::from_parts(req_headers, req_body);
  apply_proxy_auth(&user, &mut fwd_req);

  let forward_start = Instant::now();
  let upstream_resp = match client.request(fwd_req).await {
    Ok(resp) => resp,
    Err(e) => {
      warn!("http_upstream: forward request failed: {e}");
      return classify_http_client_error(e.into()).to_response(ctx);
    }
  };
  let forward_ms = forward_start.elapsed().as_millis() as u64;

  ctx.insert("upstream.forward_ms", forward_ms.to_string());
  ctx.insert(
    "upstream.forward_status",
    upstream_resp.status().as_str().to_string(),
  );

  let (resp_parts, resp_body) = upstream_resp.into_parts();
  let mut resp_headers = resp_parts.headers;
  crate::hop_headers::strip_connection_headers(&mut resp_headers);
  consume_proxy_auth_headers(&mut resp_headers);

  let upstream_ps = resp_headers
    .get(http::header::HeaderName::from_static("proxy-status"))
    .cloned();
  resp_headers
    .remove(http::header::HeaderName::from_static("proxy-status"));

  let mut resp = http::Response::builder().status(resp_parts.status);
  for (name, value) in resp_headers.iter() {
    resp = resp.header(name, value);
  }

  if let Some(ref id) = get_server_id(ctx) {
    let our_entry =
      build_proxy_status_with_status(id, resp_parts.status.as_u16());
    resp = resp.header(
      http::header::HeaderName::from_static("proxy-status"),
      append_proxy_status(upstream_ps.as_ref(), &our_entry),
    );
  } else if let Some(ps) = upstream_ps {
    resp = resp.header(
      http::header::HeaderName::from_static("proxy-status"),
      ps,
    );
  }

  let wrapped_body = BytesBufBodyWrapper::new(resp_body);
  let boxed_resp_body = ResponseBody::new(wrapped_body);

  match resp.body(boxed_resp_body) {
    Ok(r) => r,
    Err(e) => {
      warn!("http_upstream: failed to build response: {e}");
      build_error_response(
        http::StatusCode::BAD_GATEWAY,
        "Failed to build response",
      )
    }
  }
}
