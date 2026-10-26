//! module: listeners::http3::stream_handler
//! responsibility: adapt routed HTTP/3 exchanges to the service
//! contract
//! public operations: handle_h3_stream
//! data entities: none
//! tests: stream_handler_tests.rs

use std::net::SocketAddr;

use bytes::Bytes;
use h3::server;
use tower::ServiceExt;
use tracing::warn;

use super::recv_body::H3RecvBody;
use super::request_stream::CancellableStream;
use super::upgrade::H3UpgradeTrigger;
use crate::h3_response::ResponseWriter;
use crate::http_message::{
  BytesBufBodyWrapper, RequestBody, build_error_response,
};
use crate::listeners::header_validation::validate_and_route;

/// Handle a single HTTP/3 stream by delegating to the Service.
///
/// Flow:
/// 1. authority check (:authority MUST exist, if Host present must
///    equal :authority)
/// 2. Authentication check (fail -> send 407 directly)
/// 3. Route request to correct service based on :authority
/// 4. Create (trigger, on_upgrade) pair
/// 5. Build Request with on_upgrade in extensions
/// 6. Call service.call(request)
/// 7. Based on response status, trigger.send_success() or
///    trigger.send_error()
///
/// Returns unit `()` because all errors are handled internally via
/// logging and H3 error responses. This function never propagates
/// errors upward.
pub(super) async fn handle_h3_stream(
  req: http::Request<()>,
  stream: server::RequestStream<CancellableStream, Bytes>,
  server_router: crate::server::ServerRouter,
  client_addr: SocketAddr,
  local_addr: SocketAddr,
  client_cert_presented: bool,
) -> () {
  let method = req.method().clone();

  let routing_entry = match validate_and_route(&req, &server_router) {
    Ok(entry) => entry,
    Err(response) => {
      let mut stream = ResponseWriter::new(stream);
      if let Err(error) = stream.send(*response, &method).await {
        warn!("Failed to send routing error: {error}");
      }
      return;
    }
  };

  // QUIC/TLS already authenticated any presented client certificate
  // against this listener's combined CA roots. Only the requirement
  // for a non-anonymous connection depends on the routed server.
  // Do not revalidate certificates per stream or compare the proxy's
  // SNI with the request authority, which can name a tunnel target.
  if routing_entry.requires_client_cert() && !client_cert_presented {
    let resp = build_error_response(
      http::StatusCode::FORBIDDEN,
      "Forbidden: client certificate required",
    );
    let mut stream = ResponseWriter::new(stream);
    if let Err(e) = stream.send(resp, &method).await {
      warn!("Failed to send 403 response: {e}");
    }
    return;
  }

  let service = routing_entry.service.clone();

  // Phase 3: Build RequestContext with connection-level keys and insert
  // into request extensions. Auth and access logging are now handled
  // by the plugin layer in the service pipeline.
  let ctx = crate::context::build_request_context(
    &client_addr,
    &local_addr,
    &routing_entry.service_name,
  );

  // Phase 4: Create upgrade pair ONLY for CONNECT method
  let is_connect = method == http::Method::CONNECT;

  // Phase 5: Build Request with appropriate body and stream handling.
  // stream is consumed here — either by H3UpgradeTrigger::pair
  // (CONNECT) or by stream.split() (non-CONNECT). Both branches are
  // mutually exclusive.
  let (request_body, mut stream_holder, trigger_and_upgrade) =
    if is_connect {
      let (trigger, on_upgrade) = H3UpgradeTrigger::pair(stream);
      let body = RequestBody::new(BytesBufBodyWrapper::new(
        http_body_util::Empty::<Bytes>::new(),
      ));
      (body, None, Some((trigger, on_upgrade)))
    } else {
      // Non-CONNECT: split stream, use recv half for body, keep send
      // half for response
      let (send_stream, recv_stream) = stream.split();
      let body = RequestBody::new(BytesBufBodyWrapper::new(
        H3RecvBody::new(recv_stream),
      ));
      (body, Some(ResponseWriter::new(send_stream)), None)
    };

  let (parts, ()) = req.into_parts();
  let mut request = http::Request::from_parts(parts, request_body);
  crate::hop_headers::join_cookie_headers(request.headers_mut());

  // Insert RequestContext into request extensions
  request.extensions_mut().insert(ctx);

  let trigger = if let Some((trigger, on_upgrade)) = trigger_and_upgrade
  {
    request.extensions_mut().insert(on_upgrade);
    Some(trigger)
  } else {
    None
  };

  // Phase 6: Call Service
  let result = service.oneshot(request).await;

  // Phase 7: Handle Service response
  match result {
    Ok(resp) => {
      if is_connect {
        if let Some(trigger) = trigger
          && let Err(error) = trigger.respond(resp).await
        {
          warn!("H3 failed to send CONNECT response: {error}");
        }
      } else if let Some(ref mut stream) = stream_holder
        && let Err(e) = stream.send(resp, &method).await
      {
        warn!("H3 failed to send response: {e}");
      }
    }
    Err(e) => {
      warn!("H3 service error: {e}");
      if is_connect {
        if let Some(t) = trigger
          && let Err(e) = t
            .respond(build_error_response(
              http::StatusCode::BAD_GATEWAY,
              "Bad Gateway",
            ))
            .await
        {
          warn!("H3 failed to send error: {e}");
        }
      } else if let Some(ref mut stream) = stream_holder {
        let resp = build_error_response(
          http::StatusCode::BAD_GATEWAY,
          "Bad Gateway",
        );
        if let Err(e) = stream.send(resp, &method).await {
          warn!("H3 failed to send error response: {e}");
        }
      }
    }
  }
}
