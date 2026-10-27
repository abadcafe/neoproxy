//! module: forward
//! responsibilities: translate a forward request and streamed response
//! across an HTTP hop public operations: ForwardClient, forward_request
//! data entities: none
//! tests: forward_tests.rs
use std::future::Future;
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
    super::http1_framing::prepare_request(&mut request);
    let ctx = request.extensions().get::<RequestContext>().cloned();
    let captured =
      hyper_util::client::legacy::connect::capture_connection(
        &mut request,
      );
    let progress = request
      .extensions()
      .get::<super::retry_request::Progress>()
      .cloned();
    let pending = self.request(request);
    tokio::pin!(pending);
    let mut assigned: Option<
      super::observation::ConnectionObservation,
    > = None;
    let result = std::future::poll_fn(|cx| {
      let result = pending.as_mut().poll(cx);
      // Capture assignment in the same poll that selected the
      // connection, so setup metadata is available before response
      // headers.
      if let Some(connected) = captured.connection_metadata().as_ref() {
        if let Some(progress) = &progress {
          progress.mark();
        }
        let mut extras = http::Extensions::new();
        connected.get_extras(&mut extras);
        if let (Some(observation), Some(ctx)) = (
          extras.get::<super::observation::ConnectionObservation>(),
          ctx.as_ref(),
        ) && assigned
          .as_ref()
          .is_none_or(|previous| !previous.same_connection(observation))
        {
          observation.record(ctx);
          assigned = Some(observation.clone());
        }
      }
      result
    })
    .await;
    // A cancelled, unsent request may select another connection. A
    // setup failure on that replacement must retain its own evidence.
    if let (Err(error), Some(ctx)) = (&result, &ctx) {
      super::observation::ConnectionObservation::record_error(
        error, ctx,
      );
    }
    let response = result
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
) -> Result<Response, UpstreamError>
where
  C: ForwardClient,
{
  let headers = &mut req_headers.headers;
  let trailer_policy =
    crate::hop_headers::strip_connection_headers(headers);
  crate::via::append(headers, req_headers.version);
  crate::hop_headers::join_cookie_headers(headers);
  let host_header = match target.host_header_value() {
    Ok(value) => value,
    Err(e) => {
      warn!("http_upstream: invalid forward target authority: {e}");
      return Ok(build_error_response(
        http::StatusCode::BAD_REQUEST,
        "Invalid target address",
      ));
    }
  };
  headers.insert(http::header::HOST, host_header);
  if let Some(id) = ctx.request_id() {
    id.apply(headers);
  }

  req_headers.uri = target.absolute_uri().clone();
  let body = RequestBody::new(
    BytesBufBodyWrapper::with_trailer_policy(req_body, trailer_policy),
  );
  let mut fwd_req = http::Request::from_parts(req_headers, body);
  fwd_req.extensions_mut().insert(ctx.clone());
  apply_proxy_auth(user, &mut fwd_req);

  let forward_start = Instant::now();
  let upstream_resp = match client.send(fwd_req).await {
    Ok(resp) => resp,
    Err(e) => {
      return Err(e);
    }
  };
  ctx.set(
    crate::context::fields::upstream::FORWARD_TIME,
    forward_start.elapsed(),
  );
  ctx.set(
    crate::context::fields::upstream::FORWARD_STATUS,
    u64::from(upstream_resp.status().as_u16()),
  );

  let (parts, body) = upstream_resp.into_parts();
  Ok(forward_response(parts, body, ctx))
}
