use std::cell::RefCell;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::Result;
use tracing::warn;

use super::error::UpstreamError;
use super::upstream::{ConnectResult, UpstreamRegistry};
use crate::context::RequestContext;
use crate::http_utils::{
  Request, RequestBody, Response, append_proxy_status,
  build_empty_response, build_error_response,
  build_proxy_status_with_status,
};
use crate::listeners::utils::get_server_id;
use crate::plugins::utils::{
  self, ConnectTargetError, ForwardTargetError,
};
use crate::service::Service;
use crate::stream::{self, Io};
use crate::tracker::StreamTracker;

// ============================================================================
// Upstream Service (unified: chain mode when upstream is Some, direct
// when None)
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
    if !registry.borrow().entries.contains_key(&args.upstream) {
      anyhow::bail!(
        "upstream '{}' not found in registry",
        args.upstream
      );
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
  type Future =
    Pin<Box<dyn std::future::Future<Output = Result<Response>>>>;
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
        return Ok(
          UpstreamError::ProxyInternalError("shutting down".into())
            .to_response(&ctx),
        );
      }

      if req_headers.method == http::Method::CONNECT {
        chain_connect(
          &upstream_name,
          &registry,
          &st,
          req_headers,
          upgrade,
          &ctx,
        )
        .await
      } else {
        chain_forward(
          &upstream_name,
          &registry,
          req_headers,
          req_body,
          &ctx,
        )
        .await
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
  upgrade: Option<
    Pin<Box<dyn std::future::Future<Output = Result<Box<dyn Io>>>>>,
  >,
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

  let (tls_config, tracker) = {
    let reg = registry.borrow();
    (reg.tls_config(), reg.tracker())
  };

  let connect_start = std::time::Instant::now();
  let result = match registry.borrow().get_upstream(upstream_name) {
    Ok(upstream) => {
      upstream.connect_for_tunnel(&target, &tls_config, &tracker).await
    }
    Err(e) => return Ok(e.to_response(ctx)),
  };
  let result = match result {
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
    upstream_addr,
    upstream_proxy_status,
    tunnel_idle_timeout,
  } = result;

  let target_io: Box<dyn Io> = transport;

  let client_addr = format!(
    "{}:{}",
    ctx.get("client.ip").unwrap_or_default(),
    ctx.get("client.port").unwrap_or_default(),
  );
  let upstream_ip =
    upstream_addr.map(|a| format!(" ({a})")).unwrap_or_default();
  let tunnel_desc = format!("{client_addr} -> {target}{upstream_ip}");

  complete_tunnel(
    target_io,
    st,
    upgrade,
    ctx,
    upstream_proxy_status,
    tunnel_idle_timeout,
    &tunnel_desc,
  )
  .await
}

/// Complete a CONNECT tunnel by building the 200 response and
/// registering bidirectional transfer.
async fn complete_tunnel(
  target: Box<dyn Io>,
  st: &Rc<StreamTracker>,
  upgrade: Option<
    Pin<Box<dyn std::future::Future<Output = Result<Box<dyn Io>>>>>,
  >,
  ctx: &RequestContext,
  upstream_proxy_status: Option<http::HeaderValue>,
  tunnel_idle_timeout: Duration,
  tunnel_desc: &str,
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
  let tunnel_desc = tunnel_desc.to_string();

  st.register(async move {
    let client = match upgrade {
      Some(u) => match u.await {
        Ok(c) => c,
        Err(e) => {
          warn!("tunnel {tunnel_desc} upgrade failed: {e}");
          return;
        }
      },
      None => {
        warn!("tunnel {tunnel_desc}: no upgrade available");
        return;
      }
    };

    stream::run_tunnel(
      client,
      target,
      shutdown_handle,
      tunnel_idle_timeout,
      &tunnel_desc,
    )
    .await;
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

  let (tls_config, tracker) = {
    let reg = registry.borrow();
    (reg.tls_config(), reg.tracker())
  };

  match registry.borrow().get_upstream(upstream_name) {
    Ok(upstream) => {
      match upstream
        .forward(&tls_config, &tracker, req_headers, req_body, ctx)
        .await
      {
        Ok(resp) => Ok(resp),
        Err(e) => {
          warn!("UpstreamService: forward failed: {e}");
          Ok(e.to_response(ctx))
        }
      }
    }
    Err(e) => {
      warn!("UpstreamService: failed to get upstream for forward: {e}");
      Ok(e.to_response(ctx))
    }
  }
}

#[cfg(test)]
mod tests {
  use futures::task::noop_waker;
  use tower::Service;

  use super::*;
  use crate::context::RequestContext;
  use crate::service::Service as RuntimeService;

  fn make_request(method: http::Method, uri: &str) -> Request {
    let mut req = http::Request::builder()
      .method(method)
      .uri(uri)
      .body(RequestBody::new(
        crate::http_utils::BytesBufBodyWrapper::new(
          http_body_util::Empty::new(),
        ),
      ))
      .unwrap();
    req.extensions_mut().insert(RequestContext::new());
    req
  }

  fn build_registry(
    plugin_config: super::super::config::HttpUpstreamPluginConfig,
  ) -> UpstreamRegistry {
    let merged =
      super::super::config::merge_chain_config(&plugin_config).unwrap();
    let st = Rc::new(StreamTracker::new());
    UpstreamRegistry::new(merged, None, st.clone()).unwrap()
  }

  fn make_direct_service() -> RuntimeService {
    let plugin_config: super::super::config::HttpUpstreamPluginConfig =
      serde_yaml::from_str("upstreams:\n  - name: direct\n").unwrap();
    let sargs =
      serde_yaml::to_value(serde_yaml::Mapping::from_iter([(
        serde_yaml::Value::String("upstream".into()),
        serde_yaml::Value::String("direct".into()),
      )]))
      .unwrap();
    let st = Rc::new(StreamTracker::new());
    let registry = Rc::new(RefCell::new(build_registry(plugin_config)));
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
    let sargs =
      serde_yaml::to_value(serde_yaml::Mapping::from_iter([(
        serde_yaml::Value::String("upstream".into()),
        serde_yaml::Value::String("direct".into()),
      )]))
      .unwrap();
    let st = Rc::new(StreamTracker::new());
    let registry = Rc::new(RefCell::new(build_registry(plugin_config)));
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

    local
      .run_until(async {
        // Start a local TCP echo server
        let listener =
          tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let echo_server = tokio::task::spawn_local(async move {
          if let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = [0u8; 64];
            let _ =
              tokio::io::AsyncReadExt::read(&mut stream, &mut buf)
                .await;
            let _ =
              tokio::io::AsyncWriteExt::write(&mut stream, b"hello")
                .await;
          }
        });

        let mut svc = make_direct_service();
        let req = make_request(
          http::Method::CONNECT,
          &format!("127.0.0.1:{port}"),
        );
        let resp = svc.call(req).await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::OK);

        echo_server.abort();
        let _ = echo_server.await;
      })
      .await;
  }

  #[tokio::test]
  async fn test_upstream_service_new_missing_upstream_fails() {
    let plugin_config: super::super::config::HttpUpstreamPluginConfig =
      serde_yaml::from_str("upstreams:\n  - name: direct\n").unwrap();
    let sargs =
      serde_yaml::to_value(serde_yaml::Mapping::from_iter([(
        serde_yaml::Value::String("upstream".into()),
        serde_yaml::Value::String("nonexistent".into()),
      )]))
      .unwrap();
    let st = Rc::new(StreamTracker::new());
    let registry = Rc::new(RefCell::new(build_registry(plugin_config)));
    let result = UpstreamService::new(sargs, st, registry);
    assert!(result.is_err());
  }

  #[tokio::test]
  async fn test_upstream_service_new_with_chain_upstream() {
    let st = Rc::new(StreamTracker::new());

    let plugin_config: super::super::config::HttpUpstreamPluginConfig =
      serde_yaml::from_str(
        r#"
upstreams:
  - name: test
    addresses:
      - address: "127.0.0.1:8080"
        http: {}
"#,
      )
      .unwrap();
    let registry = build_registry(plugin_config);
    let registry = Rc::new(RefCell::new(registry));

    let sargs =
      serde_yaml::to_value(serde_yaml::Mapping::from_iter([(
        serde_yaml::Value::String("upstream".into()),
        serde_yaml::Value::String("test".into()),
      )]))
      .unwrap();
    let result = UpstreamService::new(sargs, st, registry);
    assert!(result.is_ok());
  }

  #[tokio::test]
  async fn test_direct_forward_success() {
    let local = tokio::task::LocalSet::new();

    local
      .run_until(async {
        // Start a local HTTP server
        let listener =
          tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::task::spawn_local(async move {
          if let Ok((stream, _)) = listener.accept().await {
            let io = hyper_util::rt::TokioIo::new(stream);
            let _ = hyper::server::conn::http1::Builder::new()
              .serve_connection(
                io,
                hyper::service::service_fn(|_req| async move {
                  Ok::<_, std::convert::Infallible>(
                    http::Response::builder()
                      .status(200)
                      .body(http_body_util::Full::new(
                        bytes::Bytes::from("hello"),
                      ))
                      .unwrap(),
                  )
                }),
              )
              .await;
          }
        });

        let mut svc = make_direct_service();
        let req = make_request(
          http::Method::GET,
          &format!("http://127.0.0.1:{port}/"),
        );
        let resp = svc.call(req).await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::OK);

        server.abort();
        let _ = server.await;
      })
      .await;
  }
}
