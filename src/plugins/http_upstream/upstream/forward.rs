//! module: forward
//! responsibilities: translate a forward request and streamed response
//! across an HTTP hop public operations: ForwardClient, forward_request
//! data entities: none
//! tests: forward_tests.rs
use std::time::Instant;

use hyper_util::client::legacy::Client;
use tracing::warn;

use super::proxy_auth::apply_proxy_auth;
use super::response::forward_response;
use crate::context::RequestContext;
use crate::http_message::{
  BytesBufBodyWrapper, Request, RequestBody, Response, ResponseBody,
  build_error_response,
};
use crate::plugins::http_upstream::error::{
  UpstreamError, classify_http_client_error,
};
use crate::plugins::http_upstream::target_parser::ForwardTarget;

/// The forwarding policy consumes a transport without assuming its
/// pooling key. Direct clients pool by origin; proxy clients by proxy.
pub(super) trait ForwardClient {
  async fn send(
    &self,
    request: Request,
  ) -> Result<Response, UpstreamError>;
}

impl<C> ForwardClient for Client<C, RequestBody>
where
  C: hyper_util::client::legacy::connect::Connect
    + Clone
    + Send
    + Sync
    + Unpin
    + 'static,
{
  async fn send(
    &self,
    mut request: Request,
  ) -> Result<Response, UpstreamError> {
    *request.version_mut() = http::Version::HTTP_11;
    let response = self
      .request(request)
      .await
      .map_err(|error| classify_http_client_error(error.into()))?;
    let (parts, body) = response.into_parts();
    Ok(Response::from_parts(
      parts,
      ResponseBody::new(BytesBufBodyWrapper::new(body)),
    ))
  }
}

/// Normalize a forward exchange independently of transport pooling.
pub(super) async fn forward_request<C>(
  client: C,
  user: &Option<crate::config::UserCredential>,
  target: &ForwardTarget,
  mut req_headers: http::request::Parts,
  req_body: RequestBody,
  ctx: &RequestContext,
) -> Response
where
  C: ForwardClient,
{
  let headers = &mut req_headers.headers;
  crate::hop_headers::strip_connection_headers(headers);
  crate::via::append(headers, req_headers.version);
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
  let mut fwd_req = http::Request::from_parts(req_headers, req_body);
  apply_proxy_auth(user, &mut fwd_req);

  let forward_start = Instant::now();
  let upstream_resp = match client.send(fwd_req).await {
    Ok(resp) => resp,
    Err(e) => {
      warn!("http_upstream: forward request failed: {e}");
      return e.to_response(ctx);
    }
  };
  let forward_ms = forward_start.elapsed().as_millis() as u64;

  ctx.insert("upstream.forward_ms", forward_ms.to_string());
  ctx.insert(
    "upstream.forward_status",
    upstream_resp.status().as_str().to_string(),
  );

  let (parts, body) = upstream_resp.into_parts();
  forward_response(parts, body, ctx)
}
