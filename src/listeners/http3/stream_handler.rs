use std::net::SocketAddr;

use bytes::Bytes;
use h3::server;
use http_body_util::BodyExt;
use tower::ServiceExt;
use tracing::warn;

use super::recv_body::H3RecvBody;
use super::request_stream::CancellableStream;
use crate::http_message::{
  BytesBufBodyWrapper, RequestBody, Response, build_error_response,
};
use crate::listeners::header_validation::validate_and_route;
use crate::stream::H3UpgradeTrigger;

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
        if resp.status() == http::StatusCode::OK {
          let resp_headers = resp.headers().clone();
          if let Some(t) = trigger
            && let Err(e) = t.send_success(Some(&resp_headers)).await
          {
            warn!("H3 failed to send success: {e}");
          }
        } else {
          let resp_headers = resp.headers().clone();
          let status = resp.status();
          let body_bytes =
            match http_body_util::BodyExt::collect(resp.into_body())
              .await
            {
              Ok(collected) => collected.to_bytes(),
              Err(e) => {
                warn!("H3 failed to collect response body: {e}");
                Bytes::new()
              }
            };
          if let Some(t) = trigger
            && let Err(e) = t
              .send_error_with_body(
                status,
                body_bytes,
                Some(&resp_headers),
              )
              .await
          {
            warn!("H3 failed to send error: {e}");
          }
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
          && let Err(e) =
            t.send_error(http::StatusCode::BAD_GATEWAY).await
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

/// Cancelling an exchange must reset its response stream. Dropping a
/// Quinn sender alone sends FIN, which can disguise a truncated body.
struct ResponseWriter<S: h3::quic::SendStream<Bytes>> {
  stream: server::RequestStream<S, Bytes>,
  finished: bool,
}

impl<S: h3::quic::SendStream<Bytes>> ResponseWriter<S> {
  fn new(stream: server::RequestStream<S, Bytes>) -> Self {
    Self { stream, finished: false }
  }

  async fn send(
    &mut self,
    response: Response,
    method: &http::Method,
  ) -> anyhow::Result<()> {
    let (mut parts, mut body) = response.into_parts();
    let body_allowed = method != http::Method::HEAD
      && !parts.status.is_informational()
      && !matches!(
        parts.status,
        http::StatusCode::NO_CONTENT
          | http::StatusCode::RESET_CONTENT
          | http::StatusCode::NOT_MODIFIED
      );
    if parts.status.is_informational()
      || parts.status == http::StatusCode::NO_CONTENT
    {
      parts.headers.remove(http::header::CONTENT_LENGTH);
    }
    // Preserve this proxy's locally generated 407 challenge.
    crate::hop_headers::strip_connection_headers(&mut parts.headers);
    self
      .stream
      .send_response(http::Response::from_parts(parts, ()))
      .await?;
    if !body_allowed {
      drop(body);
      self.stream.finish().await?;
      self.finished = true;
      return Ok(());
    }
    while let Some(frame) = body.frame().await {
      let frame = frame?;
      match frame.into_data() {
        Ok(data) => {
          if !data.is_empty() {
            self.stream.send_data(data).await?;
          }
        }
        Err(frame) => {
          if let Ok(mut trailers) = frame.into_trailers() {
            crate::hop_headers::strip_trailer_headers(&mut trailers);
            self.stream.send_trailers(trailers).await?;
            self.stream.finish().await?;
            self.finished = true;
            return Ok(());
          }
        }
      }
    }
    self.stream.finish().await?;
    self.finished = true;
    Ok(())
  }
}

impl<S: h3::quic::SendStream<Bytes>> Drop for ResponseWriter<S> {
  fn drop(&mut self) {
    if !self.finished {
      self.stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
    }
  }
}
