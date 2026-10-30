use std::rc::Rc;

use futures::task::noop_waker;
use tower::Service;

use super::client::UpstreamRegistry;
use super::service::*;
use crate::context::RequestContext;
use crate::http_message::{Request, RequestBody};
use crate::service::Service as RuntimeService;
use crate::task_tracker::TaskTracker;

/// Ensure the rustls crypto provider is installed for tests.
fn ensure_crypto_provider() {
  static CRYPTO_PROVIDER_INSTALLED: std::sync::OnceLock<bool> =
    std::sync::OnceLock::new();
  CRYPTO_PROVIDER_INSTALLED.get_or_init(|| {
    let _ = rustls::crypto::ring::default_provider().install_default();
    true
  });
}

fn make_request(method: http::Method, uri: &str) -> Request {
  let mut req = http::Request::builder()
    .method(method)
    .uri(uri)
    .body(RequestBody::new(
      crate::http_message::BytesBufBodyWrapper::new(
        http_body_util::Empty::new(),
      ),
    ))
    .unwrap();
  let id =
    crate::request_id::RequestId::read_or_generate(req.headers())
      .unwrap();
  req
    .extensions_mut()
    .insert(RequestContext::new().with_request_id(id));
  req
}

fn build_registry(
  plugin_config: super::config::UpstreamPluginConfig,
) -> UpstreamRegistry {
  ensure_crypto_provider();
  let merged =
    super::config::merge_chain_config(&plugin_config).unwrap();
  let st = std::sync::Arc::new(TaskTracker::new());
  UpstreamRegistry::new(merged, None, st.clone()).unwrap()
}

fn make_direct_service() -> RuntimeService {
  let plugin_config: super::config::UpstreamPluginConfig =
    serde_yaml::from_str("upstreams:\n  - name: direct\n").unwrap();
  let sargs = serde_yaml::to_value(serde_yaml::Mapping::from_iter([(
    serde_yaml::Value::String("upstream".into()),
    serde_yaml::Value::String("direct".into()),
  )]))
  .unwrap();
  let st = std::sync::Arc::new(TaskTracker::new());
  let registry = Rc::new(build_registry(plugin_config));
  UpstreamService::build(sargs, st, registry).unwrap()
}

#[test]
fn test_plugin_name() {
  assert_eq!(super::plugin_name(), "upstream");
}

#[tokio::test]
async fn test_direct_service_new_with_direct_upstream() {
  let plugin_config: super::config::UpstreamPluginConfig =
    serde_yaml::from_str("upstreams:\n  - name: direct\n").unwrap();
  let sargs = serde_yaml::to_value(serde_yaml::Mapping::from_iter([(
    serde_yaml::Value::String("upstream".into()),
    serde_yaml::Value::String("direct".into()),
  )]))
  .unwrap();
  let st = std::sync::Arc::new(TaskTracker::new());
  let registry = Rc::new(build_registry(plugin_config));
  let result = UpstreamService::build(sargs, st, registry);
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
async fn test_call_rejects_unsupported_extended_connect_before_dialing()
{
  let mut service = make_direct_service();
  let mut request =
    make_request(http::Method::CONNECT, "https://127.0.0.1:1/tunnel");
  *request.version_mut() = http::Version::HTTP_3;
  request.extensions_mut().insert(h3::ext::Protocol::WEB_TRANSPORT);
  let response = service.call(request).await.unwrap();
  assert_eq!(response.status(), http::StatusCode::NOT_IMPLEMENTED);
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
async fn test_direct_forward_unsupported_scheme_returns_400() {
  let mut svc = make_direct_service();
  let req = make_request(http::Method::GET, "ftp://example.com/");
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
            tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;
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
  let plugin_config: super::config::UpstreamPluginConfig =
    serde_yaml::from_str("upstreams:\n  - name: direct\n").unwrap();
  let sargs = serde_yaml::to_value(serde_yaml::Mapping::from_iter([(
    serde_yaml::Value::String("upstream".into()),
    serde_yaml::Value::String("nonexistent".into()),
  )]))
  .unwrap();
  let st = std::sync::Arc::new(TaskTracker::new());
  let registry = Rc::new(build_registry(plugin_config));
  let result = UpstreamService::build(sargs, st, registry);
  assert!(result.is_err());
}

#[tokio::test]
async fn test_upstream_service_new_with_chain_upstream() {
  let st = std::sync::Arc::new(TaskTracker::new());

  let plugin_config: super::config::UpstreamPluginConfig =
    serde_yaml::from_str(
      r#"
upstreams:
- name: test
  addresses:
    - address: "127.0.0.1:8080"
      address_protocol: http
"#,
    )
    .unwrap();
  let registry = build_registry(plugin_config);
  let registry = Rc::new(registry);

  let sargs = serde_yaml::to_value(serde_yaml::Mapping::from_iter([(
    serde_yaml::Value::String("upstream".into()),
    serde_yaml::Value::String("test".into()),
  )]))
  .unwrap();
  let result = UpstreamService::build(sargs, st, registry);
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
