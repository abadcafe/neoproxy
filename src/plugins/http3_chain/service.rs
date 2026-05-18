use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::Result;
use bytes::{Buf, Bytes};
use h3::client as h3_cli;
use http_body_util::BodyExt as _;
use tracing::{info, warn};

use crate::context::RequestContext;
use crate::h3_stream::H3ClientBidiStream;
use crate::http_utils::{
  Request, Response, append_proxy_status, build_empty_response,
  build_error_response, build_proxy_status_error,
  build_proxy_status_with_status,
};
use crate::service::Service;
use crate::stream::Io;
use crate::tracker::StreamTracker;

use super::config::UserPasswordCredential;
use super::error::UpstreamHandleError;
use super::upstream::get_upstream_handle;
use crate::plugins::utils::{self as utils, ConnectTargetError, ForwardTargetError};

// ============================================================================
// Service
// ============================================================================

#[derive(Clone)]
pub(crate) struct Http3ChainService {
  upstream_name: String,
  stream_tracker: Rc<StreamTracker>,
}

impl Http3ChainService {
  #[allow(clippy::new_ret_no_self)]
  pub(crate) fn new(
    sargs: crate::config::SerializedArgs,
    stream_tracker: Rc<StreamTracker>,
  ) -> Result<Service> {
    let args: super::config::Http3ChainServiceArgs = serde_yaml::from_value(sargs)?;
    args.validate()?;

    Ok(Service::new(Self {
      upstream_name: args.upstream,
      stream_tracker,
    }))
  }

  fn is_shutting_down(&self) -> bool {
    self.stream_tracker.shutdown_handle().is_shutdown()
  }

  #[cfg(test)]
  pub(crate) fn new_for_test(upstream_name: &str) -> Self {
    Self {
      upstream_name: upstream_name.to_string(),
      stream_tracker: Rc::new(StreamTracker::new()),
    }
  }
}

impl tower::Service<Request> for Http3ChainService {
  type Error = anyhow::Error;
  type Future = Pin<Box<dyn std::future::Future<Output = Result<Response>>>>;
  type Response = Response;

  fn poll_ready(
    &mut self,
    _cx: &mut TaskContext<'_>,
  ) -> Poll<Result<(), Self::Error>> {
    Poll::Ready(Ok(()))
  }

  fn call(&mut self, mut req: Request) -> Self::Future {
    let upstream_name = self.upstream_name.clone();
    let st = self.stream_tracker.clone();
    let is_shutting_down = self.is_shutting_down();

    let ctx = req
      .extensions()
      .get::<RequestContext>()
      .cloned()
      .expect("RequestContext should be present");

    let upgrade = crate::stream::extract_upgrade(&mut req);
    let (req_headers, req_body) = req.into_parts();

    Box::pin(async move {
      if is_shutting_down {
        warn!("Http3ChainService: rejecting request during shutdown");
        let mut resp = build_empty_response(
          http::StatusCode::SERVICE_UNAVAILABLE,
        );
        if let Some(ref id) = ctx.get("listener.hostname") {
          resp.headers_mut().insert(
            http::header::HeaderName::from_static("proxy-status"),
            build_proxy_status_error(id, "proxy_internal_response"),
          );
        }
        return Ok(resp);
      }

      // Dispatch based on method
      if req_headers.method == http::Method::CONNECT {
        // CONNECT tunnel path
        let (host, port) = match utils::parse_connect_target(&req_headers) {
          Ok(result) => result,
          Err(ConnectTargetError::NotConnectMethod) => {
            return Ok(build_error_response(
              http::StatusCode::METHOD_NOT_ALLOWED,
              "Only CONNECT method is supported",
            ));
          }
          Err(
            ConnectTargetError::NoAuthority
            | ConnectTargetError::NoPort
            | ConnectTargetError::PortZero,
          ) => {
            return Ok(build_error_response(
              http::StatusCode::BAD_REQUEST,
              "Invalid target address",
            ));
          }
        };

        let handle = match get_upstream_handle(&upstream_name).await {
          Ok(h) => h,
          Err(e) => {
            warn!(
              "Http3ChainService: failed to get upstream handle: {e}"
            );
            let (status, error) = match &e {
              UpstreamHandleError::DnsError(_) => {
                (http::StatusCode::BAD_GATEWAY, "dns_error")
              }
              UpstreamHandleError::ConnectionRefused(_) => {
                (http::StatusCode::BAD_GATEWAY, "connection_refused")
              }
              UpstreamHandleError::ConnectionTimeout(_) => {
                (
                  http::StatusCode::GATEWAY_TIMEOUT,
                  "connection_timeout",
                )
              }
              UpstreamHandleError::DestinationUnavailable(_) => {
                (
                  http::StatusCode::BAD_GATEWAY,
                  "destination_unavailable",
                )
              }
              UpstreamHandleError::ProxyInternalResponse(_) => {
                (
                  http::StatusCode::SERVICE_UNAVAILABLE,
                  "proxy_internal_response",
                )
              }
            };
            let mut resp = build_empty_response(status);
            if let Some(ref id) = ctx.get("listener.hostname") {
              resp.headers_mut().insert(
                http::header::HeaderName::from_static("proxy-status"),
                build_proxy_status_error(id, error),
              );
            }
            return Ok(resp);
          }
        };

        send_connect_and_tunnel_with_credential(
          handle.requester,
          host,
          port,
          &handle.user_password_credential,
          &st,
          upgrade,
          &ctx,
          handle.max_idle_timeout,
        )
        .await
      } else {
        // Forward HTTP path
        forward_http_over_h3(req_headers, req_body, upstream_name, ctx).await
      }
    })
  }
}

/// Send CONNECT request with credentials and tunnel data
async fn send_connect_and_tunnel_with_credential(
  mut requester: h3_cli::SendRequest<h3_quinn::OpenStreams, Bytes>,
  host: String,
  port: u16,
  user_password_credential: &UserPasswordCredential,
  st: &Rc<StreamTracker>,
  upgrade: Option<Pin<Box<dyn std::future::Future<Output = Result<Box<dyn Io>>>>>>,
  ctx: &RequestContext,
  max_idle_timeout: Duration,
) -> Result<Response> {
  let mut proxy_req = http::Request::builder()
    .method(http::Method::CONNECT)
    .uri(format!("{host}:{port}"))
    .body(())?;

  user_password_credential.apply(&mut proxy_req);

  info!("Http3ChainService: sending CONNECT request");
  let proxy_start = std::time::Instant::now();
  let mut proxy_stream = requester.send_request(proxy_req).await?;
  let proxy_resp = proxy_stream.recv_response().await?;
  let proxy_ms = proxy_start.elapsed().as_millis() as u64;
  info!(
    "Http3ChainService: received CONNECT response: status={}",
    proxy_resp.status()
  );

  // Preserve upstream Proxy-Status for both error and success paths
  // per RFC 9209 Section 2 (append, not overwrite).
  let upstream_ps = proxy_resp.headers().get(
    http::header::HeaderName::from_static("proxy-status"),
  );

  if !proxy_resp.status().is_success() {
    let upstream_status = proxy_resp.status();
    let status = if upstream_status
      == http::StatusCode::PROXY_AUTHENTICATION_REQUIRED
    {
      http::StatusCode::BAD_GATEWAY
    } else {
      upstream_status
    };
    let mut resp = build_empty_response(status);
    if let Some(ref id) = ctx.get("listener.hostname") {
      let our_entry =
        build_proxy_status_with_status(id, upstream_status.as_u16());
      resp.headers_mut().insert(
        http::header::HeaderName::from_static("proxy-status"),
        append_proxy_status(upstream_ps, &our_entry),
      );
    }
    return Ok(resp);
  }

  info!("Http3ChainService: CONNECT succeeded, setting up tunnel");
  let (sending_stream, receiving_stream) = proxy_stream.split();
  complete_tunnel(
    sending_stream,
    receiving_stream,
    requester,
    st,
    upgrade,
    proxy_ms,
    ctx,
    max_idle_timeout,
    upstream_ps,
  )
  .await
}

/// Complete the tunnel by setting up bidirectional transfer
async fn complete_tunnel(
  sending_stream: h3_cli::RequestStream<
    h3_quinn::SendStream<Bytes>,
    Bytes,
  >,
  receiving_stream: h3_cli::RequestStream<h3_quinn::RecvStream, Bytes>,
  requester: h3_cli::SendRequest<h3_quinn::OpenStreams, Bytes>,
  st: &Rc<StreamTracker>,
  upgrade: Option<Pin<Box<dyn std::future::Future<Output = Result<Box<dyn Io>>>>>>,
  connect_ms: u64,
  ctx: &RequestContext,
  max_idle_timeout: Duration,
  upstream_ps: Option<&http::HeaderValue>,
) -> Result<Response> {
  ctx.insert(
    "http3_chain.connect_ms",
    connect_ms.to_string(),
  );

  let mut resp = build_tunnel_response();
  if let Some(ref id) = ctx.get("listener.hostname") {
    let our_entry =
      build_proxy_status_with_status(id, 200);
    resp.headers_mut().insert(
      http::header::HeaderName::from_static("proxy-status"),
      append_proxy_status(upstream_ps, &our_entry),
    );
  }
  let shutdown_handle = st.shutdown_handle();
  let addr = "http3_chain".to_string();

  st.register(async move {
    // Hold requester alive for the tunnel's lifetime
    let _requester = requester;

    let client = match upgrade {
      Some(u) => match u.await {
        Ok(c) => c,
        Err(e) => {
          warn!("tunnel to {addr} upgrade failed: {e}");
          return;
        }
      },
      None => {
        warn!("tunnel to {addr}: no upgrade available");
        return;
      }
    };

    let h3_stream =
      H3ClientBidiStream::new(sending_stream, receiving_stream);

    crate::stream::run_tunnel(
      client,
      h3_stream,
      shutdown_handle,
      max_idle_timeout,
      &addr,
    )
    .await;
  });

  Ok(resp)
}

/// Forward an HTTP request over H3 to the upstream proxy.
///
/// Handles GET/POST/PUT/DELETE and other non-CONNECT methods by forwarding
/// them to the upstream proxy via HTTP/3.
async fn forward_http_over_h3(
  req_headers: http::request::Parts,
  req_body: crate::http_utils::RequestBody,
  upstream_name: String,
  ctx: RequestContext,
) -> Result<Response> {
  // Validate forward target (absolute-form http:// URI required).
  // The full absolute URI is forwarded as-is to the upstream proxy.
  match utils::parse_forward_target(&req_headers) {
    Ok(_) => {}
    Err(ForwardTargetError::ConnectMethod) => {
      return Ok(build_error_response(
        http::StatusCode::METHOD_NOT_ALLOWED,
        "CONNECT method not allowed for forward proxy",
      ));
    }
    Err(ForwardTargetError::UnsupportedScheme) => {
      return Ok(build_error_response(
        http::StatusCode::BAD_REQUEST,
        "Only http:// scheme supported for forward proxy",
      ));
    }
    Err(
      ForwardTargetError::NotAbsoluteForm
      | ForwardTargetError::NoAuthority
      | ForwardTargetError::PortZero,
    ) => {
      return Ok(build_error_response(
        http::StatusCode::BAD_REQUEST,
        "Invalid target address",
      ));
    }
  };

  // Get upstream handle
  let handle = match get_upstream_handle(&upstream_name).await {
    Ok(h) => h,
    Err(e) => {
      warn!("Http3ChainService: failed to get upstream handle for forward: {e}");
      let (status, error) = match &e {
        UpstreamHandleError::DnsError(_) => {
          (http::StatusCode::BAD_GATEWAY, "dns_error")
        }
        UpstreamHandleError::ConnectionRefused(_) => {
          (http::StatusCode::BAD_GATEWAY, "connection_refused")
        }
        UpstreamHandleError::ConnectionTimeout(_) => {
          (http::StatusCode::GATEWAY_TIMEOUT, "connection_timeout")
        }
        UpstreamHandleError::DestinationUnavailable(_) => {
          (http::StatusCode::BAD_GATEWAY, "destination_unavailable")
        }
        UpstreamHandleError::ProxyInternalResponse(_) => {
          (http::StatusCode::SERVICE_UNAVAILABLE, "proxy_internal_response")
        }
      };
      let mut resp = build_empty_response(status);
      if let Some(ref id) = ctx.get("listener.hostname") {
        resp.headers_mut().insert(
          http::header::HeaderName::from_static("proxy-status"),
          build_proxy_status_error(id, error),
        );
      }
      return Ok(resp);
    }
  };

  // Collect request body
  let body_bytes = match req_body.collect().await {
    Ok(collected) => collected.to_bytes(),
    Err(e) => {
      warn!("Http3ChainService: failed to collect request body: {e}");
      return Ok(build_error_response(
        http::StatusCode::BAD_REQUEST,
        "Failed to read request body",
      ));
    }
  };

  // Build H3 request with absolute URI
  let mut fwd_req = http::Request::builder()
    .method(req_headers.method.clone())
    .uri(req_headers.uri.clone())
    .body(())?;

  // Copy headers and strip hop-by-hop
  let mut headers = req_headers.headers.clone();
  utils::strip_hop_by_hop_headers(&mut headers);

  // Apply proxy credentials
  handle.user_password_credential.apply(&mut fwd_req);

  for (name, value) in headers.iter() {
    fwd_req.headers_mut().insert(name.clone(), value.clone());
  }

  // Send request over H3
  let forward_start = std::time::Instant::now();
  let mut proxy_stream = match handle.requester.clone().send_request(fwd_req).await {
    Ok(stream) => stream,
    Err(e) => {
      warn!("Http3ChainService: failed to send forward request: {e}");
      let mut resp = build_empty_response(http::StatusCode::BAD_GATEWAY);
      if let Some(ref id) = ctx.get("listener.hostname") {
        resp.headers_mut().insert(
          http::header::HeaderName::from_static("proxy-status"),
          build_proxy_status_error(id, "proxy_internal_response"),
        );
      }
      return Ok(resp);
    }
  };

  // Send body
  if !body_bytes.is_empty() {
    if let Err(e) = proxy_stream.send_data(body_bytes).await {
      warn!("Http3ChainService: failed to send request body: {e}");
      return Ok(build_error_response(
        http::StatusCode::BAD_GATEWAY,
        "Failed to send request body",
      ));
    }
  }

  if let Err(e) = proxy_stream.finish().await {
    warn!("Http3ChainService: failed to finish request: {e}");
    return Ok(build_error_response(
      http::StatusCode::BAD_GATEWAY,
      "Failed to finish request",
    ));
  }

  // Receive response
  let proxy_resp = match proxy_stream.recv_response().await {
    Ok(resp) => resp,
    Err(e) => {
      warn!("Http3ChainService: failed to receive response: {e}");
      return Ok(build_error_response(
        http::StatusCode::BAD_GATEWAY,
        "Failed to receive response",
      ));
    }
  };

  let forward_ms = forward_start.elapsed().as_millis() as u64;

  // Record metrics
  ctx.insert("http3_chain.forward_ms", forward_ms.to_string());
  ctx.insert(
    "http3_chain.forward_status",
    proxy_resp.status().as_str().to_string(),
  );

  // Build response
  let (resp_parts, _resp_body) = proxy_resp.into_parts();
  let mut resp_headers = resp_parts.headers.clone();
  utils::strip_hop_by_hop_headers(&mut resp_headers);

  // Append our Proxy-Status entry to whatever the upstream sent
  // (RFC 9209 Section 2).
  let upstream_ps = resp_headers
    .get(http::header::HeaderName::from_static("proxy-status"))
    .cloned();
  resp_headers.remove(http::header::HeaderName::from_static("proxy-status"));

  // Collect response body from the H3 stream via recv_data()
  let mut body_buf = bytes::BytesMut::new();
  loop {
    match proxy_stream.recv_data().await {
      Ok(Some(mut chunk)) => {
        let b = chunk.copy_to_bytes(chunk.remaining());
        body_buf.extend_from_slice(&b);
      }
      Ok(None) => break,
      Err(e) => {
        warn!("Http3ChainService: failed to receive response body: {e}");
        break;
      }
    }
  }
  let body_bytes = body_buf.freeze();

  let mut resp = http::Response::builder()
    .status(resp_parts.status)
    .version(resp_parts.version);

  for (name, value) in resp_headers.iter() {
    resp = resp.header(name, value);
  }

  if let Some(ref id) = ctx.get("listener.hostname") {
    let our_entry =
      build_proxy_status_with_status(id, resp_parts.status.as_u16());
    resp = resp.header(
      http::header::HeaderName::from_static("proxy-status"),
      append_proxy_status(upstream_ps.as_ref(), &our_entry),
    );
  } else if let Some(ps) = upstream_ps {
    // No listener identifier to add our own entry, but still
    // preserve upstream's Proxy-Status so it isn't dropped.
    resp = resp.header(
      http::header::HeaderName::from_static("proxy-status"),
      ps,
    );
  }

  let resp_body_wrapped = crate::http_utils::BytesBufBodyWrapper::new(
    http_body_util::Full::new(body_bytes),
  );
  let resp_body_response =
    crate::http_utils::ResponseBody::new(resp_body_wrapped);

  match resp.body(resp_body_response) {
    Ok(r) => Ok(r),
    Err(e) => {
      warn!("Http3ChainService: failed to build response: {e}");
      Ok(build_error_response(
        http::StatusCode::BAD_GATEWAY,
        "Failed to build response",
      ))
    }
  }
}

/// Build a 200 OK tunnel response.
pub(crate) fn build_tunnel_response() -> Response {
  build_empty_response(http::StatusCode::OK)
}