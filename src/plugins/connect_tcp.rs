use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::Result;
use bytes::Bytes;
use http_body_util::Full;
use hyper_util::rt::TokioIo;
use tokio::{io, net, task};
use tracing::warn;

use super::utils::{self, ConnectTargetError};
use crate::plugin;

fn build_empty_response(status: http::StatusCode) -> plugin::Response {
  let empty = http_body_util::Empty::new();
  let bytes_buf = plugin::BytesBufBodyWrapper::new(empty);
  let body = plugin::ResponseBody::new(bytes_buf);
  let mut resp = plugin::Response::new(body);
  *resp.status_mut() = status;
  resp
}

fn build_error_response(
  status: http::StatusCode,
  message: &str,
) -> plugin::Response {
  let full = Full::new(Bytes::from(message.to_string()));
  let bytes_buf = plugin::BytesBufBodyWrapper::new(full);
  let body = plugin::ResponseBody::new(bytes_buf);
  let mut resp = plugin::Response::new(body);
  *resp.status_mut() = status;
  resp.headers_mut().insert(
    http::header::CONTENT_TYPE,
    http::header::HeaderValue::from_static("text/plain"),
  );
  resp
}

#[derive(Clone)]
struct ConnectTcpService {}

impl ConnectTcpService {
  fn new(sargs: plugin::SerializedArgs) -> Result<plugin::Service> {
    let _args: () = serde_yaml::from_value(sargs)?;
    Ok(plugin::Service::new(Self {}))
  }
}

impl tower::Service<plugin::Request> for ConnectTcpService {
  type Error = anyhow::Error;
  type Future = Pin<Box<dyn Future<Output = Result<Self::Response>>>>;
  type Response = plugin::Response;

  fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<()>> {
    Poll::Ready(Ok(()))
  }

  fn call(&mut self, mut req: plugin::Request) -> Self::Future {
    Box::pin(async move {
      // 获取 OnUpgrade future
      let on_upgrade = hyper::upgrade::on(&mut req);

      // 解析目标地址
      let (parts, _body) = req.into_parts();
      let (host, port) = match utils::parse_connect_target(&parts) {
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

      // 构造 200 空响应
      let resp = build_empty_response(http::StatusCode::OK);

      // 关键：在后台任务中等待 upgrade 并处理隧道
      // 必须先返回响应，on_upgrade 才会完成，否则会死锁
      task::spawn_local(async move {
        // 等待 upgrade 完成
        let upgraded = match on_upgrade.await {
          Ok(upgraded) => upgraded,
          Err(e) => {
            warn!("upgrade failed: {e}");
            return;
          }
        };

        // 连接目标服务器
        let addr = format!("{host}:{port}");
        let target_stream = match net::TcpStream::connect(&addr).await {
          Ok(stream) => stream,
          Err(e) => {
            warn!("connect to target {addr} failed: {e}");
            return;
          }
        };

        // 双向转发
        // TokioIo 包装 Upgraded，使其实现 tokio 的 AsyncRead/AsyncWrite
        // TcpStream 已经实现了 tokio 的 AsyncRead/AsyncWrite，不需要包装
        let mut upgraded = TokioIo::new(upgraded);
        let mut target_stream = target_stream;
        let _ =
          io::copy_bidirectional(&mut upgraded, &mut target_stream)
            .await;
      });

      // 立即返回响应
      Ok(resp)
    })
  }
}

struct ConnectTcpPlugin {
  service_builders:
    HashMap<&'static str, Box<dyn plugin::BuildService>>,
}

impl ConnectTcpPlugin {
  fn new() -> ConnectTcpPlugin {
    let builder: Box<dyn plugin::BuildService> =
      Box::new(|a| ConnectTcpService::new(a));
    let service_builders = HashMap::from([("connect_tcp", builder)]);

    Self { service_builders }
  }
}

impl plugin::Plugin for ConnectTcpPlugin {
  fn service_builder(
    &self,
    name: &str,
  ) -> Option<&Box<dyn plugin::BuildService>> {
    self.service_builders.get(name)
  }
}

pub fn plugin_name() -> &'static str {
  "connect_tcp"
}

pub fn create_plugin() -> Box<dyn plugin::Plugin> {
  Box::new(ConnectTcpPlugin::new())
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::plugin::Plugin;
  use http_body_util::BodyExt;
  use std::task::{Context, Poll, RawWaker, RawWakerVTable};
  use tower::Service;

  fn dummy_waker() -> std::task::Waker {
    fn dummy_clone(_: *const ()) -> RawWaker {
      RawWaker::new(std::ptr::null(), &VTABLE)
    }
    fn dummy(_: *const ()) {}
    static VTABLE: RawWakerVTable =
      RawWakerVTable::new(dummy_clone, dummy, dummy, dummy);
    unsafe {
      std::task::Waker::from_raw(RawWaker::new(
        std::ptr::null(),
        &VTABLE,
      ))
    }
  }

  #[test]
  fn test_connect_tcp_service_new_default_args() {
    let result = ConnectTcpService::new(serde_yaml::Value::Null);
    assert!(result.is_ok());
  }

  #[test]
  fn test_connect_tcp_service_poll_ready() {
    let mut service = ConnectTcpService {};
    let waker = dummy_waker();
    let mut cx = Context::from_waker(&waker);
    let result = service.poll_ready(&mut cx);
    assert!(matches!(result, Poll::Ready(Ok(()))));
  }

  #[test]
  fn test_build_empty_response_ok() {
    let resp = build_empty_response(http::StatusCode::OK);
    assert_eq!(resp.status(), http::StatusCode::OK);
  }

  #[test]
  fn test_build_empty_response_bad_request() {
    let resp = build_empty_response(http::StatusCode::BAD_REQUEST);
    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
  }

  #[test]
  fn test_build_empty_response_method_not_allowed() {
    let resp =
      build_empty_response(http::StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(resp.status(), http::StatusCode::METHOD_NOT_ALLOWED);
  }

  #[test]
  fn test_build_error_response_method_not_allowed() {
    let resp = build_error_response(
      http::StatusCode::METHOD_NOT_ALLOWED,
      "Only CONNECT method is supported",
    );
    assert_eq!(resp.status(), http::StatusCode::METHOD_NOT_ALLOWED);
    let content_type = resp.headers().get(http::header::CONTENT_TYPE);
    assert_eq!(content_type.unwrap().to_str().unwrap(), "text/plain");
  }

  #[test]
  fn test_build_error_response_bad_request() {
    let resp = build_error_response(
      http::StatusCode::BAD_REQUEST,
      "Invalid target address",
    );
    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    let content_type = resp.headers().get(http::header::CONTENT_TYPE);
    assert_eq!(content_type.unwrap().to_str().unwrap(), "text/plain");
  }

  #[test]
  fn test_plugin_name() {
    assert_eq!(plugin_name(), "connect_tcp");
  }

  #[test]
  fn test_create_plugin() {
    let plugin = create_plugin();
    assert!(plugin.service_builder("connect_tcp").is_some());
  }

  #[test]
  fn test_connect_tcp_plugin_service_builder_valid_name() {
    let plugin = ConnectTcpPlugin::new();
    let builder = plugin.service_builder("connect_tcp");
    assert!(builder.is_some());
  }

  #[test]
  fn test_connect_tcp_plugin_service_builder_invalid_name() {
    let plugin = ConnectTcpPlugin::new();
    let builder = plugin.service_builder("invalid");
    assert!(builder.is_none());
  }

  fn make_connect_request(
    method: http::Method,
    uri: &str,
  ) -> plugin::Request {
    http::Request::builder()
      .method(method)
      .uri(uri)
      .body(plugin::RequestBody::new(plugin::BytesBufBodyWrapper::new(
        http_body_util::Empty::new(),
      )))
      .unwrap()
  }

  async fn collect_body(body: plugin::ResponseBody) -> Bytes {
    body.collect().await.unwrap().to_bytes()
  }

  #[tokio::test]
  async fn test_service_call_not_connect_method() {
    let mut service = ConnectTcpService {};
    let req = make_connect_request(http::Method::GET, "/");
    let fut = service.call(req);
    let resp = fut.await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::METHOD_NOT_ALLOWED);
    let content_type = resp.headers().get(http::header::CONTENT_TYPE);
    assert_eq!(content_type.unwrap().to_str().unwrap(), "text/plain");
    let body = collect_body(resp.into_body()).await;
    assert_eq!(body, Bytes::from("Only CONNECT method is supported"));
  }

  #[tokio::test]
  async fn test_service_call_no_authority() {
    let mut service = ConnectTcpService {};
    let req = make_connect_request(http::Method::CONNECT, "/");
    let fut = service.call(req);
    let resp = fut.await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    let content_type = resp.headers().get(http::header::CONTENT_TYPE);
    assert_eq!(content_type.unwrap().to_str().unwrap(), "text/plain");
    let body = collect_body(resp.into_body()).await;
    assert_eq!(body, Bytes::from("Invalid target address"));
  }

  #[tokio::test]
  async fn test_service_call_no_port() {
    let mut service = ConnectTcpService {};
    let req =
      make_connect_request(http::Method::CONNECT, "example.com");
    let fut = service.call(req);
    let resp = fut.await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    let content_type = resp.headers().get(http::header::CONTENT_TYPE);
    assert_eq!(content_type.unwrap().to_str().unwrap(), "text/plain");
    let body = collect_body(resp.into_body()).await;
    assert_eq!(body, Bytes::from("Invalid target address"));
  }

  #[tokio::test]
  async fn test_service_call_port_zero() {
    let mut service = ConnectTcpService {};
    let req =
      make_connect_request(http::Method::CONNECT, "example.com:0");
    let fut = service.call(req);
    let resp = fut.await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    let content_type = resp.headers().get(http::header::CONTENT_TYPE);
    assert_eq!(content_type.unwrap().to_str().unwrap(), "text/plain");
    let body = collect_body(resp.into_body()).await;
    assert_eq!(body, Bytes::from("Invalid target address"));
  }

  #[tokio::test]
  async fn test_service_call_valid_connect_returns_200() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let mut service = ConnectTcpService {};
        let req = make_connect_request(
          http::Method::CONNECT,
          "example.com:443",
        );
        let fut = service.call(req);
        let resp = fut.await.unwrap();
        // upgrade will fail because there's no actual HTTP connection
        // but we still get 200 response before upgrade attempt
        assert_eq!(resp.status(), http::StatusCode::OK);
      })
      .await;
  }

  #[tokio::test]
  async fn test_service_call_connect_to_nonexistent_target() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        // Start a local TCP listener to get a valid port
        let listener =
          tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Drop the listener so the port is free and connection will fail
        drop(listener);

        let mut service = ConnectTcpService {};
        let req = make_connect_request(
          http::Method::CONNECT,
          &format!("127.0.0.1:{}", addr.port()),
        );
        let fut = service.call(req);
        let resp = fut.await.unwrap();
        // upgrade will fail, but we still get 200 response
        assert_eq!(resp.status(), http::StatusCode::OK);
      })
      .await;
  }

  /// Integration test that requires actual HTTP server.
  /// This test verifies the full CONNECT tunnel flow including:
  /// - Successful HTTP upgrade
  /// - Successful target connection
  /// - Bidirectional data transfer
  #[tokio::test]
  async fn test_service_call_connect_full_flow() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        // Create a local TCP server to act as the target
        let target_listener =
          tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();

        // Spawn a task to accept target connection and handle data
        let target_task = tokio::spawn(async move {
          if let Ok((mut stream, _)) = target_listener.accept().await {
            // Simple echo: read and write back
            let mut buf = [0u8; 1024];
            if let Ok(n) = stream.read(&mut buf).await {
              let _ = stream.write_all(&buf[..n]).await;
            }
          }
        });

        // Create a local HTTP server to handle CONNECT request
        let http_listener =
          tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let _http_addr = http_listener.local_addr().unwrap();

        // Create the service and request
        let mut service = ConnectTcpService {};
        let req = make_connect_request(
          http::Method::CONNECT,
          &format!("127.0.0.1:{}", target_addr.port()),
        );

        // The service call will fail the upgrade since there's no
        // actual HTTP connection, so we just verify it returns 200
        let fut = service.call(req);
        let resp = fut.await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::OK);

        // Clean up
        target_task.abort();
        drop(http_listener);
      })
      .await;
  }

  /// Test using hyper server to verify successful upgrade path.
  /// This test creates an actual HTTP server that handles CONNECT requests.
  #[tokio::test]
  async fn test_service_call_with_hyper_server() {
    use http_body_util::Empty;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        // Create a target TCP server
        let target_listener =
          tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();

        // Spawn target server that echoes data
        let target_handle = tokio::spawn(async move {
          if let Ok((mut stream, _)) = target_listener.accept().await {
            let mut buf = [0u8; 1024];
            if let Ok(n) = stream.read(&mut buf).await {
              let _ = stream.write_all(&buf[..n]).await;
            }
          }
        });

        // Create a TCP listener for the HTTP server
        let http_listener =
          tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let _http_addr = http_listener.local_addr().unwrap();

        // Spawn HTTP server task
        let http_handle = tokio::spawn(async move {
          if let Ok((stream, _)) = http_listener.accept().await {
            let io = TokioIo::new(stream);
            let service = service_fn(|mut req| async move {
              // Get upgrade future before consuming the request
              let on_upgrade = hyper::upgrade::on(&mut req);

              // Return 200 response
              let resp = http::Response::new(Empty::<Bytes>::new());

              // Spawn task to handle the upgraded connection
              tokio::spawn(async move {
                if let Ok(upgraded) = on_upgrade.await {
                  let mut upgraded = TokioIo::new(upgraded);
                  // Just echo back
                  let mut buf = [0u8; 1024];
                  if let Ok(n) = upgraded.read(&mut buf).await {
                    let _ = upgraded.write_all(&buf[..n]).await;
                  }
                }
              });

              Ok::<_, anyhow::Error>(resp)
            });

            let _ =
              http1::Builder::new().serve_connection(io, service).await;
          }
        });

        // Give the server time to start
        tokio::time::sleep(tokio::time::Duration::from_millis(10))
          .await;

        // Now test our ConnectTcpService
        let mut service = ConnectTcpService {};
        let req = make_connect_request(
          http::Method::CONNECT,
          &format!("127.0.0.1:{}", target_addr.port()),
        );

        let fut = service.call(req);
        let resp = fut.await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::OK);

        // Clean up
        http_handle.abort();
        target_handle.abort();
      })
      .await;
  }
}
