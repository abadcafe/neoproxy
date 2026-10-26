//! module: listeners::http3::stream_handler
//! responsibility: adapt routed HTTP/3 exchanges to the service
//! contract
//! public operations: handle_h3_stream
//! data entities: none
//! tests: stream_handler_tests.rs

use std::net::SocketAddr;

use bytes::Bytes;
use h3::server;
use tracing::warn;

use super::recv_body::H3RecvBody;
use super::request_stream::CancellableStream;
use super::upgrade::H3UpgradeTrigger;
use crate::h3_response::ResponseWriter;
use crate::http_message::{
  BytesBufBodyWrapper, RequestBody, build_error_response,
};
use crate::listeners::http_service::HttpService;

/// Handle a single HTTP/3 stream by delegating to the Service.
///
/// Transport adaptation and stream ownership remain here; the shared
/// HTTP service owns validation, routing and connection policy.
pub(super) async fn handle_h3_stream(
  req: http::Request<()>,
  stream: server::RequestStream<CancellableStream, Bytes>,
  server_router: crate::server::ServerRouter,
  client_addr: SocketAddr,
  local_addr: SocketAddr,
  client_cert_presented: bool,
) -> () {
  let method = req.method().clone();

  let service = HttpService::new_tls(
    server_router,
    client_addr,
    local_addr,
    client_cert_presented,
  );

  // CONNECT transfers the whole stream after a successful response.
  let is_connect = method == http::Method::CONNECT;

  // Adapt the body while retaining ownership of the response transport.
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

  let trigger = if let Some((trigger, on_upgrade)) = trigger_and_upgrade
  {
    request.extensions_mut().insert(on_upgrade);
    Some(trigger)
  } else {
    None
  };

  let response = match service.dispatch(request).await {
    Ok(response) => response,
    Err(error) => {
      warn!("H3 service error: {error}");
      build_error_response(http::StatusCode::BAD_GATEWAY, "Bad Gateway")
    }
  };
  if let Some(trigger) = trigger {
    if let Err(error) = trigger.respond(response).await {
      warn!("H3 failed to send CONNECT response: {error}");
    }
  } else if let Some(ref mut stream) = stream_holder
    && let Err(error) = stream.send(response, &method).await
  {
    warn!("H3 failed to send response: {error}");
  }
}
