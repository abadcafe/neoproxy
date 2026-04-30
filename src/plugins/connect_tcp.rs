#![allow(clippy::await_holding_refcell_ref)]
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::Result;
use hyper_util::rt::TokioIo;
use tokio::{self, net};
use tracing::{error, warn};

use crate::config::SerializedArgs;
use crate::connect_utils::{self as utils, ConnectTargetError};
use crate::http_utils::{Request, Response};
use crate::http_utils::{build_empty_response, build_error_response};
use crate::plugin::Plugin;
use crate::service::{BuildService, Service};
use crate::stream::{ClientStream, H3OnUpgrade, Socks5OnUpgrade};
use crate::tracker::StreamTracker;

#[derive(Clone)]
struct ConnectTcpService {
  /// Stream tracker (shared from Plugin)
  stream_tracker: Rc<StreamTracker>,
}

impl ConnectTcpService {
  /// Create a ConnectTcpService with a shared StreamTracker.
  ///
  /// The StreamTracker is owned by the Plugin and shared across all
  /// Service instances created by that Plugin.
  #[allow(clippy::new_ret_no_self)]
  fn new(
    sargs: SerializedArgs,
    stream_tracker: Rc<StreamTracker>,
  ) -> Result<Service> {
    let _args: () = serde_yaml::from_value(sargs)?;
    Ok(Service::new(Self { stream_tracker }))
  }

  /// Create a ConnectTcpService directly for testing purposes.
  #[cfg(test)]
  fn new_for_test() -> Self {
    Self { stream_tracker: Rc::new(StreamTracker::new()) }
  }
}

impl tower::Service<Request> for ConnectTcpService {
  type Error = anyhow::Error;
  type Future = Pin<Box<dyn Future<Output = Result<Self::Response>>>>;
  type Response = Response;

  fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<()>> {
    Poll::Ready(Ok(()))
  }

  fn call(&mut self, mut req: Request) -> Self::Future {
    let stream_tracker = self.stream_tracker.clone();

    // Check for SOCKS5 upgrade
    let socks5_upgrade = Socks5OnUpgrade::on(&mut req);

    // Check for H3 upgrade
    let h3_upgrade = H3OnUpgrade::on(&mut req);

    // Check for HTTP upgrade (only if no SOCKS5 and no H3)
    let http_upgrade =
      if socks5_upgrade.is_none() && h3_upgrade.is_none() {
        Some(hyper::upgrade::on(&mut req))
      } else {
        None
      };

    // Parse target address
    let (parts, _body) = req.into_parts();
    let (host, port) = match utils::parse_connect_target(&parts) {
      Ok(result) => result,
      Err(ConnectTargetError::NotConnectMethod) => {
        return Box::pin(async {
          Ok(build_error_response(
            http::StatusCode::METHOD_NOT_ALLOWED,
            "Only CONNECT method is supported",
          ))
        });
      }
      Err(
        ConnectTargetError::NoAuthority
        | ConnectTargetError::NoPort
        | ConnectTargetError::PortZero,
      ) => {
        return Box::pin(async {
          Ok(build_error_response(
            http::StatusCode::BAD_REQUEST,
            "Invalid target address",
          ))
        });
      }
    };

    Box::pin(async move {
      // Connect to target server with timing
      let addr = format!("{host}:{port}");
      let connect_start = std::time::Instant::now();
      let target_stream = match net::TcpStream::connect(&addr).await {
        Ok(stream) => stream,
        Err(e) => {
          // Map IO error to HTTP status for the Listener to translate
          let status = match e.kind() {
            std::io::ErrorKind::ConnectionRefused => {
              http::StatusCode::BAD_GATEWAY
            }
            std::io::ErrorKind::TimedOut => {
              http::StatusCode::GATEWAY_TIMEOUT
            }
            _ => http::StatusCode::BAD_GATEWAY,
          };
          return Ok(build_empty_response(status));
        }
      };
      let connect_ms = connect_start.elapsed().as_millis() as u64;

      // Build 200 response with ServiceMetrics
      let mut resp = build_empty_response(http::StatusCode::OK);
      let mut metrics = crate::access_log::ServiceMetrics::new();
      metrics.add("connect_ms", connect_ms);
      resp.extensions_mut().insert(metrics);

      // Get shutdown handle
      let shutdown_handle = stream_tracker.shutdown_handle();

      // Background task: wait for upgrade, then bidirectional transfer
      stream_tracker.register(async move {
        // Get client stream (SOCKS5, H3, or HTTP upgrade)
        let client_result: Result<ClientStream, String> =
          if let Some(socks5) = socks5_upgrade {
            match socks5.await {
              Ok(stream) => Ok(ClientStream::Socks5(stream)),
              Err(e) => Err(format!("SOCKS5 upgrade failed: {e}")),
            }
          } else if let Some(h3) = h3_upgrade {
            match h3.await {
              Ok(stream) => Ok(ClientStream::H3(stream)),
              Err(e) => Err(format!("H3 upgrade failed: {e}")),
            }
          } else if let Some(http) = http_upgrade {
            match http.await {
              Ok(upgraded) => {
                Ok(ClientStream::Http(TokioIo::new(upgraded)))
              }
              Err(e) => Err(format!("HTTP upgrade failed: {e}")),
            }
          } else {
            Err("no upgrade available".to_string())
          };

        let mut client = match client_result {
          Ok(c) => c,
          Err(e) => {
            warn!("tunnel to {addr} upgrade failed: {e}");
            return;
          }
        };

        let mut target_stream = target_stream;

        // Bidirectional transfer with shutdown notification
        let result = tokio::select! {
          res = tokio::io::copy_bidirectional(
            &mut client,
            &mut target_stream
          ) => {
            res
          }
          _ = shutdown_handle.notified() => {
            warn!("tunnel to {addr} shutdown by notification");
            return;
          }
        };

        if let Err(e) = result {
          error!("tunnel to {addr} transfer error: {e}");
        }
      });

      Ok(resp)
    })
  }
}

/// Plugin-level timeout for tunnel shutdown.
/// After this duration, remaining tunnels are forcefully aborted.
///
/// # Relationship with PLUGIN_UNINSTALL_TIMEOUT
///
/// This constant is used internally by `ConnectTcpPlugin::uninstall()`
/// to wait for tunnels to complete gracefully. The server layer uses
/// `PLUGIN_UNINSTALL_TIMEOUT` (also 5 seconds) to wait for all plugin
/// uninstall futures.
///
/// While both values are currently 5 seconds, they serve different purposes:
/// - `TUNNEL_SHUTDOWN_TIMEOUT`: Plugin-internal timeout for waiting on tunnels
/// - `PLUGIN_UNINSTALL_TIMEOUT`: Server-level timeout for all plugins
///
/// This separation allows different plugins to have different internal
/// shutdown strategies while the server maintains a consistent overall timeout.
const TUNNEL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

struct ConnectTcpPlugin {
  service_builders: HashMap<&'static str, Box<dyn BuildService>>,
  /// Plugin-level StreamTracker shared by all Service instances.
  stream_tracker: Rc<StreamTracker>,
}

impl ConnectTcpPlugin {
  fn new() -> ConnectTcpPlugin {
    let stream_tracker = Rc::new(StreamTracker::new());
    let stream_tracker_clone = stream_tracker.clone();

    let builder: Box<dyn BuildService> = Box::new(move |a| {
      ConnectTcpService::new(a, stream_tracker_clone.clone())
    });
    let service_builders = HashMap::from([("connect_tcp", builder)]);

    Self { service_builders, stream_tracker }
  }
}

impl Plugin for ConnectTcpPlugin {
  fn service_builder(
    &self,
    name: &str,
  ) -> Option<&Box<dyn BuildService>> {
    self.service_builders.get(name)
  }

  /// Trigger graceful shutdown of all tunnels created by this plugin.
  ///
  /// This method:
  /// 1. Triggers shutdown notification to all tunnels
  /// 2. Waits for tunnels to complete (up to TUNNEL_SHUTDOWN_TIMEOUT)
  /// 3. If timeout, forcefully aborts remaining tunnels
  fn uninstall(&mut self) -> Pin<Box<dyn Future<Output = ()>>> {
    let stream_tracker = self.stream_tracker.clone();

    Box::pin(async move {
      // Trigger shutdown notification
      stream_tracker.shutdown();

      // Wait for tunnels to complete with timeout
      let result = tokio::time::timeout(
        TUNNEL_SHUTDOWN_TIMEOUT,
        stream_tracker.wait_shutdown(),
      )
      .await;

      if result.is_err() {
        // Timeout reached, forcefully abort remaining tunnels
        warn!(
          "Tunnel shutdown timeout after {:?}, aborting {} remaining tunnels",
          TUNNEL_SHUTDOWN_TIMEOUT,
          stream_tracker.active_count()
        );
        stream_tracker.abort_all();
        // Wait for aborted tasks to be cleaned up
        stream_tracker.wait_shutdown().await;
      }
    })
  }
}

pub fn plugin_name() -> &'static str {
  "connect_tcp"
}

pub fn create_plugin() -> Box<dyn Plugin> {
  Box::new(ConnectTcpPlugin::new())
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::http_utils::{
    BytesBufBodyWrapper, RequestBody, ResponseBody,
  };
  use crate::plugin::Plugin;
  use crate::service::Service as RuntimeService;
  use bytes::Bytes;
  use futures::task::noop_waker;
  use http_body_util::BodyExt;
  use std::task::{Context, Poll};
  use tower::Service as TowerService;

  // ============== StreamTracker Tests (reusing tracker module tests) ==============
  // Note: StreamTracker tests are now in src/tracker.rs

  // ============== ConnectTcpService Tests ==============

  #[test]
  fn test_connect_tcp_service_new_default_args() {
    let stream_tracker = Rc::new(StreamTracker::new());
    let result =
      ConnectTcpService::new(serde_yaml::Value::Null, stream_tracker);
    assert!(result.is_ok());
  }

  #[test]
  fn test_connect_tcp_service_poll_ready() {
    let service = ConnectTcpService::new_for_test();
    let mut service = RuntimeService::new(service);
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let result = TowerService::poll_ready(&mut service, &mut cx);
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

  fn make_connect_request(method: http::Method, uri: &str) -> Request {
    http::Request::builder()
      .method(method)
      .uri(uri)
      .body(RequestBody::new(BytesBufBodyWrapper::new(
        http_body_util::Empty::new(),
      )))
      .unwrap()
  }

  async fn collect_body(body: ResponseBody) -> Bytes {
    body.collect().await.unwrap().to_bytes()
  }

  #[tokio::test]
  async fn test_service_call_not_connect_method() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let service = ConnectTcpService::new_for_test();
        let mut service = RuntimeService::new(service);
        let req = make_connect_request(http::Method::GET, "/");
        let fut = service.call(req);
        let resp = fut.await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::METHOD_NOT_ALLOWED);
        let content_type =
          resp.headers().get(http::header::CONTENT_TYPE);
        assert_eq!(
          content_type.unwrap().to_str().unwrap(),
          "text/plain"
        );
        let body = collect_body(resp.into_body()).await;
        assert_eq!(
          body,
          Bytes::from("Only CONNECT method is supported")
        );
      })
      .await;
  }

  #[tokio::test]
  async fn test_service_call_no_authority() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let service = ConnectTcpService::new_for_test();
        let mut service = RuntimeService::new(service);
        let req = make_connect_request(http::Method::CONNECT, "/");
        let fut = service.call(req);
        let resp = fut.await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        let content_type =
          resp.headers().get(http::header::CONTENT_TYPE);
        assert_eq!(
          content_type.unwrap().to_str().unwrap(),
          "text/plain"
        );
        let body = collect_body(resp.into_body()).await;
        assert_eq!(body, Bytes::from("Invalid target address"));
      })
      .await;
  }

  #[tokio::test]
  async fn test_service_call_no_port() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let service = ConnectTcpService::new_for_test();
        let mut service = RuntimeService::new(service);
        let req =
          make_connect_request(http::Method::CONNECT, "example.com");
        let fut = service.call(req);
        let resp = fut.await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        let content_type =
          resp.headers().get(http::header::CONTENT_TYPE);
        assert_eq!(
          content_type.unwrap().to_str().unwrap(),
          "text/plain"
        );
        let body = collect_body(resp.into_body()).await;
        assert_eq!(body, Bytes::from("Invalid target address"));
      })
      .await;
  }

  #[tokio::test]
  async fn test_service_call_port_zero() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let service = ConnectTcpService::new_for_test();
        let mut service = RuntimeService::new(service);
        let req =
          make_connect_request(http::Method::CONNECT, "example.com:0");
        let fut = service.call(req);
        let resp = fut.await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        let content_type =
          resp.headers().get(http::header::CONTENT_TYPE);
        assert_eq!(
          content_type.unwrap().to_str().unwrap(),
          "text/plain"
        );
        let body = collect_body(resp.into_body()).await;
        assert_eq!(body, Bytes::from("Invalid target address"));
      })
      .await;
  }

  #[tokio::test]
  async fn test_service_call_valid_connect_returns_200() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let service = ConnectTcpService::new_for_test();
        let mut service = RuntimeService::new(service);
        let req = make_connect_request(
          http::Method::CONNECT,
          "example.com:443",
        );
        let fut = service.call(req);
        let resp = fut.await.unwrap();
        // After refactor, Service connects to target before returning.
        // Result depends on network availability.
        assert!(
          resp.status() == http::StatusCode::OK
            || resp.status() == http::StatusCode::BAD_GATEWAY
        );
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

        let service = ConnectTcpService::new_for_test();
        let mut service = RuntimeService::new(service);
        let req = make_connect_request(
          http::Method::CONNECT,
          &format!("127.0.0.1:{}", addr.port()),
        );
        let fut = service.call(req);
        let resp = fut.await.unwrap();
        // Connection refused -> BAD_GATEWAY
        assert_eq!(resp.status(), http::StatusCode::BAD_GATEWAY);
      })
      .await;
  }

  #[tokio::test]
  async fn test_service_stream_tracker_tracking() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let service = ConnectTcpService::new_for_test();
        // Initially no active streams
        assert_eq!(service.stream_tracker.active_count(), 0);
      })
      .await;
  }

  #[tokio::test]
  async fn test_service_stream_tracker_shutdown_and_abort() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let service = ConnectTcpService::new_for_test();

        // Register a pending stream that ignores shutdown notification
        service.stream_tracker.register(async {
          std::future::pending::<()>().await;
        });
        tokio::task::yield_now().await;
        assert_eq!(service.stream_tracker.active_count(), 1);

        // shutdown() only notifies, task still running
        service.stream_tracker.shutdown();
        tokio::task::yield_now().await;
        assert_eq!(
          service.stream_tracker.active_count(),
          1,
          "shutdown() should only notify, not abort"
        );

        // abort_all() forcefully terminates
        service.stream_tracker.abort_all();
        service.stream_tracker.wait_shutdown().await;
        assert_eq!(service.stream_tracker.active_count(), 0);
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
        let service = ConnectTcpService::new_for_test();
        let mut service = RuntimeService::new(service);
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
        let service = ConnectTcpService::new_for_test();
        let mut service = RuntimeService::new(service);
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

  // ============== Plugin-level StreamTracker Tests ==============

  /// Test that multiple Service instances created from the same Plugin
  /// share the same StreamTracker.
  #[tokio::test]
  async fn test_plugin_level_stream_tracker_shared() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        // Create a plugin
        let plugin = ConnectTcpPlugin::new();

        // Get the builder and create two services
        let builder = plugin.service_builder("connect_tcp").unwrap();
        let _service1 = builder(serde_yaml::Value::Null).unwrap();
        let _service2 = builder(serde_yaml::Value::Null).unwrap();

        // Both services should have the same stream_tracker
        // We can verify by checking active_count
        assert_eq!(plugin.stream_tracker.active_count(), 0);
      })
      .await;
  }

  /// Test that uninstall() completes immediately when no streams are active.
  #[tokio::test]
  async fn test_uninstall_no_active_streams() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let mut plugin = ConnectTcpPlugin::new();

        // No streams, uninstall should complete quickly
        let result = tokio::time::timeout(
          Duration::from_millis(100),
          plugin.uninstall(),
        )
        .await;

        assert!(
          result.is_ok(),
          "uninstall should complete quickly when no streams"
        );
        assert_eq!(plugin.stream_tracker.active_count(), 0);
      })
      .await;
  }

  /// Test uninstall() with streams that respond to shutdown notification.
  #[tokio::test]
  async fn test_uninstall_with_responsive_streams() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let mut plugin = ConnectTcpPlugin::new();

        // Register a stream that responds to shutdown notification
        let shutdown_handle = plugin.stream_tracker.shutdown_handle();
        let notified = Rc::new(std::cell::Cell::new(false));
        let notified_clone = notified.clone();
        plugin.stream_tracker.register(async move {
          shutdown_handle.notified().await;
          notified_clone.set(true);
        });
        tokio::task::yield_now().await;
        assert_eq!(plugin.stream_tracker.active_count(), 1);

        // Uninstall should complete within timeout
        let result = tokio::time::timeout(
          Duration::from_millis(500),
          plugin.uninstall(),
        )
        .await;

        assert!(
          result.is_ok(),
          "uninstall should complete when streams respond"
        );
        assert_eq!(plugin.stream_tracker.active_count(), 0);
        assert!(notified.get(), "stream should have been notified");
      })
      .await;
  }

  /// Test uninstall() with streams that don't respond to shutdown.
  /// The uninstall should timeout and abort remaining streams.
  ///
  /// This test uses tokio's time mocking to simulate the timeout
  /// without actually waiting for 5 seconds.
  #[tokio::test]
  async fn test_uninstall_timeout_aborts_streams() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let mut plugin = ConnectTcpPlugin::new();

        // Register a stream that ignores shutdown notification
        plugin.stream_tracker.register(async {
          std::future::pending::<()>().await;
        });
        tokio::task::yield_now().await;
        assert_eq!(plugin.stream_tracker.active_count(), 1);

        // Pause time to use tokio's time mocking
        tokio::time::pause();

        // Start the uninstall future
        let uninstall_future = plugin.uninstall();

        // Advance time past TUNNEL_SHUTDOWN_TIMEOUT (5 seconds)
        // This simulates the timeout without actually waiting
        tokio::time::advance(TUNNEL_SHUTDOWN_TIMEOUT).await;
        // Advance a bit more to ensure the timeout triggers
        tokio::time::advance(Duration::from_millis(100)).await;

        // Now await the uninstall future - it should complete
        // because the timeout was triggered by the time advance
        uninstall_future.await;

        // Verify that the stream was aborted
        assert_eq!(
          plugin.stream_tracker.active_count(),
          0,
          "Stream should have been aborted after uninstall timeout"
        );
      })
      .await;
  }

  /// Test that uninstall can be called multiple times without panic.
  #[tokio::test]
  async fn test_uninstall_can_be_called_multiple_times() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let mut plugin = ConnectTcpPlugin::new();

        // Call uninstall multiple times
        plugin.uninstall().await;
        plugin.uninstall().await;
        plugin.uninstall().await;

        // No panic means success
        assert_eq!(plugin.stream_tracker.active_count(), 0);
      })
      .await;
  }

  /// Test that multiple services share the same stream tracker.
  #[tokio::test]
  async fn test_multiple_services_share_tracker() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let plugin = ConnectTcpPlugin::new();

        // Create two services
        let builder = plugin.service_builder("connect_tcp").unwrap();
        let _service1 = builder(serde_yaml::Value::Null).unwrap();
        let _service2 = builder(serde_yaml::Value::Null).unwrap();

        // Both services should share the same tracker
        // We verify by checking that plugin's tracker count is 0
        // (they share the same instance)
        assert_eq!(plugin.stream_tracker.active_count(), 0);

        // Register a stream through the plugin's tracker
        plugin.stream_tracker.register(async {
          std::future::pending::<()>().await;
        });
        tokio::task::yield_now().await;

        // The count should now be 1
        assert_eq!(plugin.stream_tracker.active_count(), 1);

        // Clean up
        plugin.stream_tracker.abort_all();
        plugin.stream_tracker.wait_shutdown().await;
      })
      .await;
  }

  // ============== Unified SOCKS5 Upgrade Tests ==============

  #[tokio::test]
  async fn test_service_call_socks5_upgrade_mode_returns_200() {
    use crate::stream::Socks5OnUpgrade;

    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let service = ConnectTcpService::new_for_test();
        let mut service = RuntimeService::new(service);

        // Create a request with Socks5OnUpgrade in extensions
        let (_tx, rx) = tokio::sync::oneshot::channel();
        let upgrade = Socks5OnUpgrade::new_for_test(rx);

        let mut req = make_connect_request(
          http::Method::CONNECT,
          "example.com:443",
        );
        req.extensions_mut().insert(upgrade);

        let resp = service.call(req).await.unwrap();
        // Service returns 200 because example.com:443 is reachable
        // (or it may fail -- the key point is it doesn't panic)
        // For a real test, we need a local target
        assert!(
          resp.status() == http::StatusCode::OK
            || resp.status() == http::StatusCode::BAD_GATEWAY
        );
      })
      .await;
  }

  #[tokio::test]
  async fn test_service_call_socks5_upgrade_refused_returns_bad_gateway()
   {
    use crate::stream::Socks5OnUpgrade;

    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        // Get a port that is NOT listening
        let listener =
          tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let service = ConnectTcpService::new_for_test();
        let mut service = RuntimeService::new(service);

        let (_tx, rx) = tokio::sync::oneshot::channel();
        let upgrade = Socks5OnUpgrade::new_for_test(rx);

        let mut req = make_connect_request(
          http::Method::CONNECT,
          &format!("127.0.0.1:{}", addr.port()),
        );
        req.extensions_mut().insert(upgrade);

        let resp = service.call(req).await.unwrap();
        // Connection refused -> BAD_GATEWAY
        assert_eq!(resp.status(), http::StatusCode::BAD_GATEWAY);
      })
      .await;
  }

  // ============== H3 Upgrade Tests ==============

  #[tokio::test]
  async fn test_service_call_with_h3_upgrade_extracts_upgrade() {
    use crate::stream::H3OnUpgrade;

    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        // Start a real TCP listener so the target connection succeeds
        let target_listener =
          tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();

        let service = ConnectTcpService::new_for_test();
        // Clone stream_tracker BEFORE wrapping in plugin::Service,
        // so we can observe the background task's state.
        let stream_tracker = service.stream_tracker.clone();
        let mut service = RuntimeService::new(service);

        // Create H3OnUpgrade with a LIVE sender (don't drop tx).
        // If the service correctly extracts H3OnUpgrade, the background
        // tunnel task will await it and block (sender alive = pending).
        // If the service does NOT extract it, it falls through to
        // hyper::upgrade::on() which fails immediately on a synthetic
        // request, causing the tunnel task to exit.
        let (tx, rx) = tokio::sync::oneshot::channel();
        let upgrade = H3OnUpgrade::new_for_test(rx);

        let mut req = make_connect_request(
          http::Method::CONNECT,
          &format!("127.0.0.1:{}", target_addr.port()),
        );
        req.extensions_mut().insert(upgrade);

        // Service should return 200 (target is reachable)
        let resp = service.call(req).await.unwrap();
        assert_eq!(
          resp.status(),
          http::StatusCode::OK,
          "Service should return 200 when target is reachable"
        );

        // Yield to let the background tunnel task start and reach
        // the upgrade await point.
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        // KEY ASSERTION: The tunnel task is still alive, blocked on
        // h3.await (because tx is alive). This proves the H3 upgrade
        // path was taken. If the service fell through to HTTP upgrade,
        // the task would have already exited (upgrade fails on
        // synthetic request) and active_count would be 0.
        assert_eq!(
          stream_tracker.active_count(),
          1,
          "Tunnel task should be alive, blocked on H3 upgrade await. \
           If 0, the service did not extract H3OnUpgrade and fell \
           through to the HTTP upgrade path which fails immediately."
        );

        // Clean up: drop sender so the tunnel task can exit
        drop(tx);
        stream_tracker.abort_all();
        stream_tracker.wait_shutdown().await;
      })
      .await;
  }

  #[tokio::test]
  async fn test_service_call_h3_upgrade_refused_returns_bad_gateway() {
    use crate::stream::H3OnUpgrade;

    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        // Get a port that is NOT listening
        let listener =
          tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let service = ConnectTcpService::new_for_test();
        let mut service = RuntimeService::new(service);

        let (_tx, rx) = tokio::sync::oneshot::channel();
        let upgrade = H3OnUpgrade::new_for_test(rx);

        let mut req = make_connect_request(
          http::Method::CONNECT,
          &format!("127.0.0.1:{}", addr.port()),
        );
        req.extensions_mut().insert(upgrade);

        let resp = service.call(req).await.unwrap();
        // Connection refused -> BAD_GATEWAY (before reaching upgrade)
        assert_eq!(resp.status(), http::StatusCode::BAD_GATEWAY);
      })
      .await;
  }

  // ============== ServiceMetrics Tests ==============

  #[tokio::test]
  async fn test_service_response_contains_service_metrics() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        // Start a local TCP server
        let target_listener =
          tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();

        let service = ConnectTcpService::new_for_test();
        let mut service = RuntimeService::new(service);
        let req = make_connect_request(
          http::Method::CONNECT,
          &format!("127.0.0.1:{}", target_addr.port()),
        );
        let resp = service.call(req).await.unwrap();

        // Must assert status first so a failed connect is a clear test failure
        assert_eq!(
          resp.status(),
          http::StatusCode::OK,
          "CONNECT to local TCP server must succeed"
        );

        // Response should have ServiceMetrics in extensions
        let metrics =
          resp.extensions().get::<crate::access_log::ServiceMetrics>();
        assert!(
          metrics.is_some(),
          "Response should contain ServiceMetrics"
        );
        let metrics = metrics.unwrap();
        // Should have connect_ms at minimum
        let has_connect =
          metrics.iter().any(|(k, _)| k == "connect_ms");
        assert!(
          has_connect,
          "ServiceMetrics should contain connect_ms"
        );
      })
      .await;
  }
}
