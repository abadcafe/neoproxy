use std::cell::RefCell;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::Result;
use bytes::{Buf, Bytes};
use http_body_util::BodyExt;
use hyper_util::client::legacy::Client;
use tracing::warn;

use crate::context::RequestContext;
use crate::http_utils::{
  Request, RequestBody, Response, ResponseBody, append_proxy_status,
  build_empty_response, build_error_response,
  build_proxy_status_with_status,
};
use crate::listeners::utils::get_server_id;
use crate::service::Service;
use crate::stream::{self, Io};
use crate::tracker::StreamTracker;

use super::config::UserPasswordCredential;
use super::error::UpstreamError;
use super::upstream::{
  ConnectResult, Transport, TunnelTransport, UpstreamRegistry,
};
use crate::plugins::utils::{self, ConnectTargetError, ForwardTargetError};

// ============================================================================
// Upstream Service (unified: chain mode when upstream is Some, direct when None)
// ============================================================================

#[derive(Clone)]
pub(crate) struct UpstreamService {
  upstream_name: String,
  stream_tracker: Rc<StreamTracker>,
  registry: Rc<RefCell<UpstreamRegistry>>,
}

impl UpstreamService {
  #[allow(clippy::new_ret_no_self)]
  pub(crate) fn new(
    sargs: crate::config::SerializedArgs,
    stream_tracker: Rc<StreamTracker>,
    registry: Rc<RefCell<UpstreamRegistry>>,
  ) -> Result<Service> {
    let args: super::config::UpstreamServiceArgs =
      serde_yaml::from_value(sargs)?;

    // Validate upstream exists in registry
    if !registry.borrow().resolved.contains_key(&args.upstream) {
      anyhow::bail!("upstream '{}' not found in registry", args.upstream);
    }

    Ok(Service::new(Self {
      upstream_name: args.upstream,
      stream_tracker,
      registry,
    }))
  }

  fn is_shutting_down(&self) -> bool {
    self.stream_tracker.shutdown_handle().is_shutdown()
  }
}

impl tower::Service<Request> for UpstreamService {
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
    let registry = self.registry.clone();
    let is_shutting_down = self.is_shutting_down();

    let ctx = req
      .extensions()
      .get::<RequestContext>()
      .cloned()
      .expect("RequestContext should be present");

    let upgrade = stream::extract_upgrade(&mut req);
    let (req_headers, req_body) = req.into_parts();

    Box::pin(async move {
      if is_shutting_down {
        warn!("UpstreamService: rejecting request during shutdown");
        return Ok(UpstreamError::ProxyInternalError("shutting down".into())
          .to_response(&ctx));
      }

      if req_headers.method == http::Method::CONNECT {
        chain_connect(&upstream_name, &registry, &st, req_headers, upgrade, &ctx).await
      } else {
        chain_forward(&upstream_name, &registry, req_headers, req_body, &ctx).await
      }
    })
  }
}

// ============================================================================
// Chain Mode: CONNECT
// ============================================================================

async fn chain_connect(
  upstream_name: &str,
  registry: &Rc<RefCell<UpstreamRegistry>>,
  st: &Rc<StreamTracker>,
  req_headers: http::request::Parts,
  upgrade: Option<Pin<Box<dyn std::future::Future<Output = Result<Box<dyn Io>>>>>>,
  ctx: &RequestContext,
) -> Result<Response> {
  let (host, port) = match utils::parse_connect_target(&req_headers) {
    Ok(result) => result,
    Err(ConnectTargetError::NotConnectMethod) => {
      return Ok(build_error_response(
        http::StatusCode::METHOD_NOT_ALLOWED,
        "Only CONNECT method is supported",
      ));
    }
    Err(_) => {
      return Ok(build_error_response(
        http::StatusCode::BAD_REQUEST,
        "Invalid target address",
      ));
    }
  };
  let target = format!("{host}:{port}");

  let connect_start = std::time::Instant::now();
  let result = match registry
    .borrow()
    .connect_for_tunnel(upstream_name, &target)
    .await
  {
    Ok(r) => r,
    Err(e) => {
      warn!("UpstreamService: CONNECT to upstream failed: {e}");
      return Ok(e.to_response(ctx));
    }
  };
  let connect_ms = connect_start.elapsed().as_millis() as u64;
  ctx.insert("upstream.connect_ms", connect_ms.to_string());

  let ConnectResult {
    transport,
    upstream_proxy_status,
    tunnel_idle_timeout,
  } = result;

  let target: Box<dyn Io> = match transport {
    TunnelTransport::Tcp(stream) => stream,
    TunnelTransport::Http3(h3_stream) => Box::new(h3_stream),
  };

  complete_tunnel(target, st, upgrade, ctx, upstream_proxy_status, tunnel_idle_timeout).await
}

/// Complete a CONNECT tunnel by building the 200 response and registering
/// bidirectional transfer.
async fn complete_tunnel(
  target: Box<dyn Io>,
  st: &Rc<StreamTracker>,
  upgrade: Option<Pin<Box<dyn std::future::Future<Output = Result<Box<dyn Io>>>>>>,
  ctx: &RequestContext,
  upstream_proxy_status: Option<http::HeaderValue>,
  tunnel_idle_timeout: Duration,
) -> Result<Response> {
  let mut resp = build_tunnel_response();
  if let Some(ref id) = get_server_id(ctx) {
    let our_entry = build_proxy_status_with_status(id, 200);
    resp.headers_mut().insert(
      http::header::HeaderName::from_static("proxy-status"),
      append_proxy_status(upstream_proxy_status.as_ref(), &our_entry),
    );
  }

  let shutdown_handle = st.shutdown_handle();
  let addr = "upstream".to_string();

  st.register(async move {
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

    stream::run_tunnel(client, target, shutdown_handle, tunnel_idle_timeout, &addr).await;
  });

  Ok(resp)
}

fn build_tunnel_response() -> Response {
  build_empty_response(http::StatusCode::OK)
}

// ============================================================================
// Chain Mode: Forward
// ============================================================================

async fn chain_forward(
  upstream_name: &str,
  registry: &Rc<RefCell<UpstreamRegistry>>,
  req_headers: http::request::Parts,
  req_body: RequestBody,
  ctx: &RequestContext,
) -> Result<Response> {
  // Validate forward target
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
    Err(_) => {
      return Ok(build_error_response(
        http::StatusCode::BAD_REQUEST,
        "Invalid target address",
      ));
    }
  };

  let transport = match registry.borrow().get_transport(upstream_name).await {
    Ok(t) => t,
    Err(e) => {
      warn!("UpstreamService: failed to get transport for forward: {e}");
      return Ok(e.to_response(ctx));
    }
  };

  match transport {
    Transport::Direct {
      client,
    } => {
      chain_forward_http(
        client,
        UserPasswordCredential::none(),
        req_headers,
        req_body,
        ctx,
      )
      .await
    }
    Transport::Http {
      client,
      user,
    } => {
      chain_forward_http(
        client,
        user,
        req_headers,
        req_body,
        ctx,
      )
      .await
    }
    Transport::Https {
      client,
      user,
    } => {
      chain_forward_http(
        client,
        user,
        req_headers,
        req_body,
        ctx,
      )
      .await
    }
    Transport::Http3 {
      send_request,
      user,
    } => {
      chain_forward_h3(send_request, user, req_headers, req_body, ctx).await
    }
  }
}

/// Forward an HTTP request over HTTP/1.1 or HTTPS/1.1 to the upstream proxy.
/// Uses hyper::Client which handles connection pooling internally.
async fn chain_forward_http<C>(
  client: Client<C, RequestBody>,
  user: UserPasswordCredential,
  req_headers: http::request::Parts,
  req_body: RequestBody,
  ctx: &RequestContext,
) -> Result<Response>
where
  C: hyper_util::client::legacy::connect::Connect + Clone + Send + Sync + Unpin + 'static,
{
  // Collect request body
  let body_bytes = match req_body.collect().await {
    Ok(collected) => collected.to_bytes(),
    Err(e) => {
      warn!("UpstreamService: failed to collect request body: {e}");
      return Ok(build_error_response(
        http::StatusCode::BAD_REQUEST,
        "Failed to read request body",
      ));
    }
  };

  // Build forwarded request with absolute-form URI
  let mut headers = req_headers.headers.clone();
  utils::strip_hop_by_hop_headers(&mut headers);

  // Apply proxy credentials to a temp request, then merge into headers
  let mut temp_req = http::Request::builder()
    .method(req_headers.method.clone())
    .uri(req_headers.uri.clone())
    .body(())
    .unwrap();
  user.apply(&mut temp_req);
  for (name, value) in temp_req.headers().iter() {
    headers.insert(name.clone(), value.clone());
  }

  // Build final request
  let mut fwd_req_builder = http::Request::builder()
    .method(req_headers.method)
    .uri(req_headers.uri);
  for (name, value) in headers.iter() {
    fwd_req_builder = fwd_req_builder.header(name, value);
  }

  let body = http_body_util::Full::new(body_bytes);
  let boxed_body = crate::http_utils::RequestBody::new(
    crate::http_utils::BytesBufBodyWrapper::new(body),
  );
  let fwd_req = fwd_req_builder.body(boxed_body).unwrap();

  let forward_start = std::time::Instant::now();
  let upstream_resp = match client.request(fwd_req).await {
    Ok(resp) => resp,
    Err(e) => {
      warn!("UpstreamService: forward request failed: {e}");
      return Ok(UpstreamError::ConnectionTerminated(e.to_string())
        .to_response(ctx));
    }
  };
  let forward_ms = forward_start.elapsed().as_millis() as u64;

  // Record metrics
  ctx.insert("upstream.forward_ms", forward_ms.to_string());
  ctx.insert(
    "upstream.forward_status",
    upstream_resp.status().as_str().to_string(),
  );

  // Build streaming response
  let (resp_parts, resp_body) = upstream_resp.into_parts();
  let mut resp_headers = resp_parts.headers;
  utils::strip_hop_by_hop_headers(&mut resp_headers);

  // Append Proxy-Status
  let upstream_ps = resp_headers
    .get(http::header::HeaderName::from_static("proxy-status"))
    .cloned();
  resp_headers.remove(http::header::HeaderName::from_static("proxy-status"));

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
    resp = resp.header(http::header::HeaderName::from_static("proxy-status"), ps);
  }

  // Stream response body (no buffering)
  let wrapped_body = crate::http_utils::BytesBufBodyWrapper::new(resp_body);
  let boxed_resp_body = ResponseBody::new(wrapped_body);

  match resp.body(boxed_resp_body) {
    Ok(r) => Ok(r),
    Err(e) => {
      warn!("UpstreamService: failed to build response: {e}");
      Ok(build_error_response(
        http::StatusCode::BAD_GATEWAY,
        "Failed to build response",
      ))
    }
  }
}

/// Forward an HTTP request over H3 to the upstream proxy.
async fn chain_forward_h3(
  mut send_request: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
  user: UserPasswordCredential,
  req_headers: http::request::Parts,
  req_body: RequestBody,
  ctx: &RequestContext,
) -> Result<Response> {
  // Collect request body
  let body_bytes = match req_body.collect().await {
    Ok(collected) => collected.to_bytes(),
    Err(e) => {
      warn!("UpstreamService: failed to collect request body: {e}");
      return Ok(build_error_response(
        http::StatusCode::BAD_REQUEST,
        "Failed to read request body",
      ));
    }
  };

  // Build H3 request with absolute-form URI
  let mut fwd_req = http::Request::builder()
    .method(req_headers.method.clone())
    .uri(req_headers.uri.clone())
    .body(())?;

  let mut headers = req_headers.headers.clone();
  utils::strip_hop_by_hop_headers(&mut headers);
  user.apply(&mut fwd_req);

  for (name, value) in headers.iter() {
    fwd_req.headers_mut().insert(name.clone(), value.clone());
  }

  let forward_start = std::time::Instant::now();
  let mut stream = match send_request.send_request(fwd_req).await {
    Ok(s) => s,
    Err(e) => {
      warn!("UpstreamService: H3 forward request failed: {e}");
      return Ok(UpstreamError::ConnectionTerminated(e.to_string())
        .to_response(ctx));
    }
  };

  // Send body
  if !body_bytes.is_empty() {
    if let Err(e) = stream.send_data(body_bytes).await {
      warn!("UpstreamService: H3 failed to send body: {e}");
      return Ok(UpstreamError::ProxyInternalError(
        format!("Failed to send request body: {e}"),
      ).to_response(ctx));
    }
  }

  if let Err(e) = stream.finish().await {
    warn!("UpstreamService: H3 failed to finish request: {e}");
    return Ok(UpstreamError::ProxyInternalError(
      format!("Failed to finish request: {e}"),
    ).to_response(ctx));
  }

  // Receive response
  let proxy_resp = match stream.recv_response().await {
    Ok(resp) => resp,
    Err(e) => {
      warn!("UpstreamService: H3 failed to receive response: {e}");
      return Ok(UpstreamError::ConnectionTerminated(e.to_string())
        .to_response(ctx));
    }
  };
  let forward_ms = forward_start.elapsed().as_millis() as u64;

  ctx.insert("upstream.forward_ms", forward_ms.to_string());
  ctx.insert(
    "upstream.forward_status",
    proxy_resp.status().as_str().to_string(),
  );

  // Build response - collect body from H3 stream
  let (resp_parts, _) = proxy_resp.into_parts();
  let mut resp_headers = resp_parts.headers;
  utils::strip_hop_by_hop_headers(&mut resp_headers);

  let upstream_ps = resp_headers
    .get(http::header::HeaderName::from_static("proxy-status"))
    .cloned();
  resp_headers.remove(http::header::HeaderName::from_static("proxy-status"));

  // Collect response body
  let mut body_buf = bytes::BytesMut::new();
  loop {
    match stream.recv_data().await {
      Ok(Some(mut chunk)) => {
        let b = chunk.copy_to_bytes(chunk.remaining());
        body_buf.extend_from_slice(&b);
      }
      Ok(None) => break,
      Err(e) => {
        warn!("UpstreamService: H3 failed to receive response body: {e}");
        break;
      }
    }
  }
  let body_bytes = body_buf.freeze();

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
    resp = resp.header(http::header::HeaderName::from_static("proxy-status"), ps);
  }

  let resp_body_wrapped = crate::http_utils::BytesBufBodyWrapper::new(
    http_body_util::Full::new(body_bytes),
  );
  let resp_body = ResponseBody::new(resp_body_wrapped);

  match resp.body(resp_body) {
    Ok(r) => Ok(r),
    Err(e) => {
      warn!("UpstreamService: failed to build H3 response: {e}");
      Ok(build_error_response(
        http::StatusCode::BAD_GATEWAY,
        "Failed to build response",
      ))
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::context::RequestContext;
  use crate::service::Service as RuntimeService;
  use futures::task::noop_waker;
  use tower::Service;

  fn make_request(method: http::Method, uri: &str) -> Request {
    let mut req = http::Request::builder()
      .method(method)
      .uri(uri)
      .body(RequestBody::new(
        crate::http_utils::BytesBufBodyWrapper::new(http_body_util::Empty::new()),
      ))
      .unwrap();
    req.extensions_mut().insert(RequestContext::new());
    req
  }

  fn make_direct_service() -> RuntimeService {
    let plugin_config: super::super::config::HttpUpstreamPluginConfig =
      serde_yaml::from_str("upstreams:\n  - name: direct\n").unwrap();
    let sargs = serde_yaml::to_value(serde_yaml::Mapping::from_iter([
      (serde_yaml::Value::String("upstream".into()), serde_yaml::Value::String("direct".into())),
    ])).unwrap();
    let st = Rc::new(StreamTracker::new());
    let registry = Rc::new(RefCell::new(
      UpstreamRegistry::new(&plugin_config, st.clone()).unwrap(),
    ));
    UpstreamService::new(sargs, st, registry).unwrap()
  }

  #[test]
  fn test_build_tunnel_response_is_200() {
    let resp = build_tunnel_response();
    assert_eq!(resp.status(), http::StatusCode::OK);
  }

  #[test]
  fn test_plugin_name() {
    assert_eq!(super::super::plugin_name(), "http_upstream");
  }

  #[tokio::test]
  async fn test_direct_service_new_with_direct_upstream() {
    let plugin_config: super::super::config::HttpUpstreamPluginConfig =
      serde_yaml::from_str("upstreams:\n  - name: direct\n").unwrap();
    let sargs = serde_yaml::to_value(serde_yaml::Mapping::from_iter([
      (serde_yaml::Value::String("upstream".into()), serde_yaml::Value::String("direct".into())),
    ])).unwrap();
    let st = Rc::new(StreamTracker::new());
    let registry = Rc::new(RefCell::new(
      UpstreamRegistry::new(&plugin_config, st.clone()).unwrap(),
    ));
    let result = UpstreamService::new(sargs, st, registry);
    assert!(result.is_ok());
  }

  #[tokio::test]
  async fn test_direct_service_poll_ready() {
    let mut svc = make_direct_service();
    let waker = noop_waker();
    let mut cx = std::task::Context::from_waker(&waker);
    let result = svc.poll_ready(&mut cx);
    assert!(matches!(result, std::task::Poll::Ready(Ok(()))));
  }

  #[tokio::test]
  async fn test_direct_connect_no_authority_returns_400() {
    let mut svc = make_direct_service();
    let req = make_request(http::Method::CONNECT, "/");
    let resp = svc.call(req).await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
  }

  #[tokio::test]
  async fn test_direct_connect_no_port_returns_400() {
    let mut svc = make_direct_service();
    let req = make_request(http::Method::CONNECT, "example.com");
    let resp = svc.call(req).await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
  }

  #[tokio::test]
  async fn test_direct_forward_origin_form_returns_400() {
    let mut svc = make_direct_service();
    let req = make_request(http::Method::GET, "/");
    let resp = svc.call(req).await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
  }

  #[tokio::test]
  async fn test_direct_forward_https_scheme_returns_400() {
    let mut svc = make_direct_service();
    let req = make_request(http::Method::GET, "https://example.com/");
    let resp = svc.call(req).await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
  }

  #[tokio::test]
  async fn test_direct_connect_port_zero_returns_400() {
    let mut svc = make_direct_service();
    let req = make_request(http::Method::CONNECT, "example.com:0");
    let resp = svc.call(req).await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
  }

  #[tokio::test]
  async fn test_direct_connect_refused_returns_502() {
    let mut svc = make_direct_service();
    // Connect to a port that is very unlikely to be listening
    let req = make_request(http::Method::CONNECT, "127.0.0.1:1");
    let resp = svc.call(req).await.unwrap();
    // Should be 502 (BAD_GATEWAY) or 504 (GATEWAY_TIMEOUT)
    assert!(
      resp.status() == http::StatusCode::BAD_GATEWAY
        || resp.status() == http::StatusCode::GATEWAY_TIMEOUT
    );
  }

  #[tokio::test]
  async fn test_direct_connect_full_flow() {
    let local = tokio::task::LocalSet::new();

    local.run_until(async {
      // Start a local TCP echo server
      let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
      let port = listener.local_addr().unwrap().port();

      let echo_server = tokio::task::spawn_local(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
          let mut buf = [0u8; 64];
          let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;
          let _ = tokio::io::AsyncWriteExt::write(&mut stream, b"hello").await;
        }
      });

      let mut svc = make_direct_service();
      let req = make_request(http::Method::CONNECT, &format!("127.0.0.1:{port}"));
      let resp = svc.call(req).await.unwrap();
      assert_eq!(resp.status(), http::StatusCode::OK);

      echo_server.abort();
      let _ = echo_server.await;
    }).await;
  }

  #[tokio::test]
  async fn test_upstream_service_new_missing_upstream_fails() {
    let plugin_config: super::super::config::HttpUpstreamPluginConfig =
      serde_yaml::from_str("upstreams:\n  - name: direct\n").unwrap();
    let sargs = serde_yaml::to_value(serde_yaml::Mapping::from_iter([
      (serde_yaml::Value::String("upstream".into()), serde_yaml::Value::String("nonexistent".into())),
    ])).unwrap();
    let st = Rc::new(StreamTracker::new());
    let registry = Rc::new(RefCell::new(
      UpstreamRegistry::new(&plugin_config, st.clone()).unwrap(),
    ));
    let result = UpstreamService::new(sargs, st, registry);
    assert!(result.is_err());
  }

  #[tokio::test]
  async fn test_upstream_service_new_with_chain_upstream() {
    let st = Rc::new(StreamTracker::new());

    let plugin_config: super::super::config::HttpUpstreamPluginConfig =
      serde_yaml::from_str(r#"
upstreams:
  - name: test
    addresses:
      - address: "127.0.0.1:8080"
        http: {}
"#).unwrap();
    let registry = UpstreamRegistry::new(&plugin_config, st.clone()).unwrap();
    let registry = Rc::new(RefCell::new(registry));

    let sargs = serde_yaml::to_value(serde_yaml::Mapping::from_iter([
      (serde_yaml::Value::String("upstream".into()), serde_yaml::Value::String("test".into())),
    ])).unwrap();
    let result = UpstreamService::new(sargs, st, registry);
    assert!(result.is_ok());
  }

  #[tokio::test]
  async fn test_direct_forward_success() {
    let local = tokio::task::LocalSet::new();

    local.run_until(async {
      // Start a local HTTP server
      let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
      let port = listener.local_addr().unwrap().port();

      let server = tokio::task::spawn_local(async move {
        if let Ok((stream, _)) = listener.accept().await {
          let io = hyper_util::rt::TokioIo::new(stream);
          let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(io, hyper::service::service_fn(|_req| async move {
              Ok::<_, std::convert::Infallible>(http::Response::builder()
                .status(200)
                .body(http_body_util::Full::new(bytes::Bytes::from("hello")))
                .unwrap())
            }))
            .await;
        }
      });

      let mut svc = make_direct_service();
      let req = make_request(http::Method::GET, &format!("http://127.0.0.1:{port}/"));
      let resp = svc.call(req).await.unwrap();
      assert_eq!(resp.status(), http::StatusCode::OK);

      server.abort();
      let _ = server.await;
    }).await;
  }
}
