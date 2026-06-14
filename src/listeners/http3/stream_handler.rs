use std::net::SocketAddr;
use std::rc::Rc;

use bytes::Bytes;
use h3::server;
use http_body_util::BodyExt;
use tower::Service;
use tracing::warn;

use crate::http_utils::{
  BytesBufBodyWrapper, RequestBody, Response, build_error_response,
};
use crate::listeners::header_validation::authority_host_mismatch;
use crate::shutdown::ShutdownHandle;
use crate::stream::H3UpgradeTrigger;
use crate::tracker::StreamTracker;

use super::recv_body::H3RecvBody;

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
  stream: server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
  server_router: crate::server::ServerRouter,
  _shutdown_handle: ShutdownHandle,
  client_addr: SocketAddr,
  local_addr: SocketAddr,
  client_cert_presented: bool,
) -> () {
  let method = req.method().clone();

  // Phase 1a: Check :authority MUST exist
  let authority = match req.uri().authority() {
    Some(a) => a,
    None => {
      let resp = build_error_response(
        http::StatusCode::BAD_REQUEST,
        "Bad Request: :authority is required",
      );
      let mut stream = stream;
      if let Err(e) = send_h3_response(&mut stream, resp, true).await {
        warn!("Failed to send 400 response: {e}");
      }
      return;
    }
  };

  // Phase 1b: If Host header exists, it must equal :authority
  if let Some(host_val) = req.headers().get(http::header::HOST)
    && let Ok(host_str) = host_val.to_str()
    && authority_host_mismatch(authority.as_ref(), host_str)
  {
    let resp = build_error_response(
      http::StatusCode::BAD_REQUEST,
      "Bad Request: :authority and Host headers differ",
    );
    let mut stream = stream;
    if let Err(e) = send_h3_response(&mut stream, resp, true).await {
      warn!("Failed to send 400 response: {e}");
    }
    return;
  }

  // Phase 2: Route FIRST based on :authority
  let hostname = req.uri().authority().map(|a| a.host());
  let routing_entry = server_router.route(hostname);

  let routing_entry = match routing_entry {
    Some(entry) => entry,
    None => {
      let resp = build_error_response(
        http::StatusCode::NOT_FOUND,
        "Not Found: No matching server for this host",
      );
      let mut stream = stream;
      if let Err(e) = send_h3_response(&mut stream, resp, true).await {
        warn!("Failed to send 404 response: {e}");
      }
      return;
    }
  };

  // Phase 2b: Check client certificate requirement
  // If the server requires mTLS (has client_ca_certs) but the
  // client did not present a certificate, reject with 403.
  if routing_entry.requires_client_cert() && !client_cert_presented {
    let resp = build_error_response(
      http::StatusCode::FORBIDDEN,
      "Forbidden: client certificate required",
    );
    let mut stream = stream;
    if let Err(e) = send_h3_response(&mut stream, resp, true).await {
      warn!("Failed to send 403 response: {e}");
    }
    return;
  }

  let mut service = routing_entry.service.clone();

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
      (body, Some(send_stream), None)
    };

  let mut request = http::Request::builder()
    .method(req.method().clone())
    .uri(req.uri().clone())
    .version(req.version())
    .body(request_body)
    .expect("failed to build request");

  for (name, value) in req.headers() {
    request.headers_mut().insert(name.clone(), value.clone());
  }

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
  let result = service.call(request).await;

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
        && let Err(e) = send_h3_response(stream, resp, true).await
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
        if let Err(e) = send_h3_response(stream, resp, true).await {
          warn!("H3 failed to send error response: {e}");
        }
      }
    }
  }
}

/// Send an HTTP/3 response with optional stream finish
///
/// # Arguments
/// * `stream` - The HTTP/3 send stream (send half or full bidi stream)
/// * `resp` - The HTTP response to send
/// * `finish_stream` - If true, close the stream after sending
///   response. Should be false for CONNECT success response to allow
///   bidirectional data transfer.
pub(super) async fn send_h3_response<S>(
  stream: &mut server::RequestStream<S, Bytes>,
  resp: Response,
  finish_stream: bool,
) -> anyhow::Result<()>
where
  S: h3::quic::SendStream<Bytes>,
{
  let (parts, body) = resp.into_parts();
  let resp = http::Response::from_parts(parts, ());

  // Send response headers
  stream.send_response(resp).await?;

  // Send response body if any
  let body_bytes = body.collect().await?.to_bytes();
  if !body_bytes.is_empty() {
    stream.send_data(body_bytes).await?;
  }

  // Finish the stream only if requested
  // For CONNECT success, we don't finish to allow bidirectional
  // transfer
  if finish_stream {
    stream.finish().await?;
  }

  Ok(())
}

// ============================================================================
// HTTP/3 Connection Handler
// ============================================================================

/// Handle a single HTTP/3 connection
pub(super) async fn handle_h3_connection(
  conn: quinn::Connection,
  server_routing_table: Vec<crate::server::Server>,
  stream_tracker: Rc<StreamTracker>,
  shutdown_handle: ShutdownHandle,
  local_addr: SocketAddr,
) {
  let client_addr = conn.remote_address();

  // Check whether client presented a certificate during TLS handshake
  let client_cert_presented = conn.peer_identity().is_some();

  // Build ServerRouter once for the entire connection
  let server_router =
    crate::server::ServerRouter::build(server_routing_table);

  // Create H3 connection
  let mut h3_conn = match h3::server::builder()
    .build(h3_quinn::Connection::new(conn))
    .await
  {
    Ok(c) => c,
    Err(e) => {
      warn!("Failed to create H3 connection: {e}");
      return;
    }
  };

  // Accept and handle streams
  loop {
    let accept_result = tokio::select! {
      res = h3_conn.accept() => res,
      _ = shutdown_handle.notified() => {
        // Graceful shutdown
        break;
      }
    };

    match accept_result {
      Ok(Some(resolver)) => {
        let server_router = server_router.clone();
        let stream_shutdown = stream_tracker.shutdown_handle();
        stream_tracker.register(async move {
          match resolver.resolve_request().await {
            Ok((req, stream)) => {
              handle_h3_stream(
                req,
                stream,
                server_router,
                stream_shutdown,
                client_addr,
                local_addr,
                client_cert_presented,
              )
              .await;
            }
            Err(e) => {
              warn!("Failed to resolve request: {e}");
            }
          }
        });
      }
      Ok(None) => {
        // Connection closed
        break;
      }
      Err(e) => {
        if !e.is_h3_no_error() {
          warn!("connection from {client_addr} on {local_addr}: {e}");
        }
        break;
      }
    }
  }
}
