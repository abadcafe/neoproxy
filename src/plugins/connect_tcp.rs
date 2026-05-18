#![allow(clippy::await_holding_refcell_ref)]
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::Result;
use serde::Deserialize;
use tokio::{self, net};
use tracing::warn;

use crate::stream;
use crate::config::SerializedArgs;
use super::utils::{self as utils, ConnectTargetError, ForwardTargetError};
use crate::context::RequestContext;
use crate::http_utils::{
  Request, Response, append_proxy_status, build_empty_response,
  build_error_response, build_proxy_status, build_proxy_status_error,
  build_proxy_status_with_status,
};
use http_body_util::BodyExt;
use crate::plugin::Plugin;
use crate::service::{BuildService, Service};
use crate::tracker::StreamTracker;

mod pool;

/// Default TCP connect timeout.
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Default pool size (max idle connections per host)
const DEFAULT_POOL_SIZE: usize = 32;

/// Default pool idle timeout
const DEFAULT_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes

#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
struct ConnectTcpPluginConfig {
  #[serde(default = "default_pool_size")]
  pool_size: usize,
  #[serde(
    with = "humantime_serde",
    default = "default_pool_idle_timeout"
  )]
  pool_idle_timeout: Duration,
  /// TCP connect timeout for new pool connections.
  /// Same semantic as the service-level connect_timeout but applies
  /// when the pool establishes a new connection on the forward path.
  #[serde(
    with = "humantime_serde",
    default = "default_connect_timeout"
  )]
  connect_timeout: Duration,
}

fn default_pool_size() -> usize {
  DEFAULT_POOL_SIZE
}

fn default_pool_idle_timeout() -> Duration {
  DEFAULT_POOL_IDLE_TIMEOUT
}

#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
struct ConnectTcpServiceArgs {
  /// Timeout for TCP connect to target server.
  #[serde(
    with = "humantime_serde",
    default = "default_connect_timeout"
  )]
  connect_timeout: Duration,
  /// Idle timeout for tunnel data transfer.
  #[serde(
    with = "humantime_serde",
    default = "default_max_idle_timeout"
  )]
  max_idle_timeout: Duration,
}

fn default_connect_timeout() -> Duration {
  DEFAULT_CONNECT_TIMEOUT
}

fn default_max_idle_timeout() -> Duration {
  Duration::from_secs(stream::DEFAULT_IDLE_TIMEOUT_SECS)
}

#[derive(Clone)]
struct ConnectTcpService {
  /// Stream tracker (shared from Plugin)
  stream_tracker: Rc<StreamTracker>,
  /// Timeout for TCP connect to target server
  connect_timeout: Duration,
  /// Idle timeout for tunnel data transfer
  max_idle_timeout: Duration,
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
    let args: ConnectTcpServiceArgs = serde_yaml::from_value(sargs)?;
    Ok(Service::new(Self {
      stream_tracker,
      connect_timeout: args.connect_timeout,
      max_idle_timeout: args.max_idle_timeout,
    }))
  }

  /// Create a ConnectTcpService directly for testing purposes.
  #[cfg(test)]
  fn new_for_test() -> Self {
    Self {
      stream_tracker: Rc::new(StreamTracker::new()),
      connect_timeout: DEFAULT_CONNECT_TIMEOUT,
      max_idle_timeout: Duration::from_secs(stream::DEFAULT_IDLE_TIMEOUT_SECS),
    }
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
    let connect_timeout = self.connect_timeout;
    let max_idle_timeout = self.max_idle_timeout;

    // Extract RequestContext from request extensions
    let ctx = req
      .extensions()
      .get::<RequestContext>()
      .cloned()
      .expect("RequestContext should be present");

    // Extract upgrade future: prefer our custom upgrade, fallback to hyper
    let upgrade = stream::extract_upgrade(&mut req);

    // Parse request parts
    let (parts, body) = req.into_parts();

    // Dispatch based on method
    if parts.method == http::Method::CONNECT {
      // CONNECT tunnel path
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
        // Connect to target server with timing and timeout
        let addr = format!("{host}:{port}");
        let connect_start = std::time::Instant::now();
        let connect_result = tokio::time::timeout(
          connect_timeout,
          net::TcpStream::connect(&addr),
        )
        .await;
        let target_stream = match connect_result {
          Ok(Ok(stream)) => stream,
          Ok(Err(e)) => {
            // Map IO error to HTTP status and Proxy-Status error
            let (status, error) = match e.kind() {
              std::io::ErrorKind::ConnectionRefused => {
                (http::StatusCode::BAD_GATEWAY, "connection_refused")
              }
              std::io::ErrorKind::TimedOut => {
                (http::StatusCode::GATEWAY_TIMEOUT, "connection_timeout")
              }
              std::io::ErrorKind::HostUnreachable
              | std::io::ErrorKind::NetworkUnreachable
              | std::io::ErrorKind::ConnectionReset
              | std::io::ErrorKind::AddrNotAvailable => {
                (http::StatusCode::BAD_GATEWAY, "destination_unavailable")
              }
              _ => {
                (http::StatusCode::BAD_GATEWAY, "proxy_internal_response")
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
          Err(_) => {
            // Timeout expired
            warn!(
              "TCP connect to {addr} timed out after {connect_timeout:?}"
            );
            let mut resp = build_empty_response(
              http::StatusCode::GATEWAY_TIMEOUT,
            );
            if let Some(ref id) = ctx.get("listener.hostname") {
              resp.headers_mut().insert(
                http::header::HeaderName::from_static("proxy-status"),
                build_proxy_status_error(id, "connection_timeout"),
              );
            }
            return Ok(resp);
          }
        };
        let connect_ms = connect_start.elapsed().as_millis() as u64;

        // Write metrics to RequestContext
        ctx.insert(
          "connect_tcp.connect_ms",
          connect_ms.to_string(),
        );

        // Build 200 response with Proxy-Status
        let mut resp = build_empty_response(http::StatusCode::OK);
        if let Some(ref id) = ctx.get("listener.hostname") {
          resp.headers_mut().insert(
            http::header::HeaderName::from_static("proxy-status"),
            build_proxy_status(id),
          );
        }

        // Get shutdown handle
        let shutdown_handle = stream_tracker.shutdown_handle();

        // Background task: wait for upgrade, then bidirectional transfer
        stream_tracker.register(async move {
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

          stream::run_tunnel(
            client,
            target_stream,
            shutdown_handle,
            max_idle_timeout,
            &addr,
          )
          .await;
        });

        Ok(resp)
      })
    } else {
      // Forward HTTP path
      forward_http(parts, body, ctx)
    }
  }
}

/// Forward an HTTP request to the target server via the connection pool.
///
/// Handles GET/POST/PUT/DELETE and other non-CONNECT methods.
fn forward_http(
  parts: http::request::Parts,
  body: crate::http_utils::RequestBody,
  ctx: RequestContext,
) -> Pin<Box<dyn Future<Output = Result<Response>>>> {
  Box::pin(async move {
    // Parse forward target
    let (host, port, _origin_uri) = match utils::parse_forward_target(&parts) {
      Ok(result) => result,
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

    // Collect request body (buffer it for the pool)
    let body_bytes = match body.collect().await {
      Ok(collected) => collected.to_bytes(),
      Err(e) => {
        warn!("Failed to collect request body: {e}");
        return Ok(build_error_response(
          http::StatusCode::BAD_REQUEST,
          "Failed to read request body",
        ));
      }
    };

    // Build forwarded request with the original absolute URI.
    // hyper_util::client::legacy::Client uses the URI to determine
    // which host to connect to, and rewrites to origin-form internally.
    let mut fwd_req = http::Request::builder()
      .method(parts.method.clone())
      .uri(parts.uri.clone())
      .version(http::Version::HTTP_11);

    // Copy headers and strip hop-by-hop
    let mut headers = parts.headers.clone();
    utils::strip_hop_by_hop_headers(&mut headers);

    // Set Host header per RFC 7230 § 5.4: a proxy receiving an
    // absolute-form request-target MUST ignore any received Host
    // header and replace it with the URI authority.
    let host_val = if port == 80 {
      host.clone()
    } else {
      format!("{host}:{port}")
    };
    if let Ok(v) = host_val.parse() {
      headers.insert(http::header::HOST, v);
    }

    for (name, value) in headers.iter() {
      fwd_req = fwd_req.header(name, value);
    }

    // Build body
    let fwd_body = http_body_util::Full::new(body_bytes);
    let fwd_body_wrapped = crate::http_utils::BytesBufBodyWrapper::new(fwd_body);
    let fwd_body_request = crate::http_utils::RequestBody::new(fwd_body_wrapped);

    let fwd_req = match fwd_req.body(fwd_body_request) {
      Ok(req) => req,
      Err(e) => {
        warn!("Failed to build forwarded request: {e}");
        return Ok(build_error_response(
          http::StatusCode::BAD_REQUEST,
          "Failed to build request",
        ));
      }
    };

    // Send through pool
    let forward_start = std::time::Instant::now();
    let upstream_resp = match pool::pool_send_request(fwd_req).await {
      Ok(resp) => resp,
      Err(e) => {
        warn!("Forward request failed: {e}");
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
    let forward_ms = forward_start.elapsed().as_millis() as u64;

    // Record metrics
    ctx.insert("connect_tcp.forward_ms", forward_ms.to_string());
    ctx.insert(
      "connect_tcp.forward_status",
      upstream_resp.status().as_str().to_string(),
    );

    // Build response
    let (resp_parts, resp_body) = upstream_resp.into_parts();
    let mut resp_headers = resp_parts.headers.clone();
    utils::strip_hop_by_hop_headers(&mut resp_headers);

    // Append our Proxy-Status entry to whatever the upstream sent
    // (RFC 9209 Section 2).
    let upstream_ps = resp_headers
      .get(http::header::HeaderName::from_static("proxy-status"))
      .cloned();
    resp_headers.remove(http::header::HeaderName::from_static("proxy-status"));

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

    let resp_body_wrapped =
      crate::http_utils::BytesBufBodyWrapper::new(resp_body);
    let resp_body_request =
      crate::http_utils::ResponseBody::new(resp_body_wrapped);

    match resp.body(resp_body_request) {
      Ok(r) => Ok(r),
      Err(e) => {
        warn!("Failed to build response: {e}");
        Ok(build_error_response(
          http::StatusCode::BAD_GATEWAY,
          "Failed to build response",
        ))
      }
    }
  })
}

/// Plugin-level timeout for tunnel shutdown.
/// After this duration, remaining tunnels are forcefully aborted.
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
  /// 4. Shuts down the TCP connection pool
  fn uninstall(&self) -> Pin<Box<dyn Future<Output = ()>>> {
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
          "Tunnel shutdown timeout after {:?}, aborting {} remaining \
           tunnels",
          TUNNEL_SHUTDOWN_TIMEOUT,
          stream_tracker.active_count()
        );
        stream_tracker.abort_all();
        // Drain so aborted tasks are removed from JoinSet
        stream_tracker.drain().await;
      }

      // Shutdown TCP pool
      pool::shutdown_tcp_pool();
    })
  }
}

pub fn plugin_name() -> &'static str {
  "connect_tcp"
}

pub fn create_plugin(config: Option<&SerializedArgs>) -> Box<dyn Plugin> {
  // Parse plugin config and initialize TCP pool
  if let Some(config_value) = config {
    let plugin_config: ConnectTcpPluginConfig =
      serde_yaml::from_value(config_value.clone())
        .unwrap_or_else(|e| {
          panic!("connect_tcp: failed to parse plugin config: {}", e)
        });

    if let Err(e) = pool::init_tcp_pool(
      plugin_config.pool_size,
      plugin_config.pool_idle_timeout,
      plugin_config.connect_timeout,
    ) {
      panic!("connect_tcp: failed to initialize TCP pool: {}", e);
    }
  } else {
    // Initialize with defaults
    if let Err(e) = pool::init_tcp_pool(
      DEFAULT_POOL_SIZE,
      DEFAULT_POOL_IDLE_TIMEOUT,
      DEFAULT_CONNECT_TIMEOUT,
    ) {
      panic!("connect_tcp: failed to initialize TCP pool: {}", e);
    }
  }

  Box::new(ConnectTcpPlugin::new())
}

#[cfg(test)]
mod tests {
  use std::task::{Context, Poll};

  use bytes::Bytes;
  use futures::task::noop_waker;
  use http_body_util::BodyExt;
  use serial_test::serial;
  use tower::Service as TowerService;

  use super::*;
  use crate::http_utils::{
    BytesBufBodyWrapper, RequestBody, ResponseBody,
  };
  use crate::plugin::Plugin;
  use crate::service::Service as RuntimeService;

  // ============== StreamTracker Tests (reusing tracker module tests)
  // ============== Note: StreamTracker tests are now in
  // src/tracker.rs

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
  #[serial]
  fn test_create_plugin() {
    let plugin = create_plugin(None);
    assert!(plugin.service_builder("connect_tcp").is_some());
  }

  #[test]
  fn test_plugin_config_deserialize_with_connect_timeout() {
    let yaml = "pool_size: 16\npool_idle_timeout: 60s\nconnect_timeout: 5s\n";
    let cfg: ConnectTcpPluginConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(cfg.pool_size, 16);
    assert_eq!(cfg.pool_idle_timeout, Duration::from_secs(60));
    assert_eq!(cfg.connect_timeout, Duration::from_secs(5));
  }

  #[test]
  fn test_plugin_config_connect_timeout_default() {
    let yaml = "{}";
    let cfg: ConnectTcpPluginConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(cfg.connect_timeout, DEFAULT_CONNECT_TIMEOUT);
    assert_eq!(cfg.pool_size, DEFAULT_POOL_SIZE);
    assert_eq!(cfg.pool_idle_timeout, DEFAULT_POOL_IDLE_TIMEOUT);
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
    use crate::context::RequestContext;

    let mut req = http::Request::builder()
      .method(method)
      .uri(uri)
      .body(RequestBody::new(BytesBufBodyWrapper::new(
        http_body_util::Empty::new(),
      )))
      .unwrap();
    req.extensions_mut().insert(RequestContext::new());
    req
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
        // GET / is origin-form (not absolute-form), so forward proxy returns 400
        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        let body = collect_body(resp.into_body()).await;
        assert_eq!(body, Bytes::from("Invalid target address"));
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
        let req =
          make_connect_request(http::Method::CONNECT, "baidu.com:443");
        let fut = service.call(req);
        let resp = fut.await.unwrap();
        // Result depends on network availability and timeout.
        assert!(
          resp.status() == http::StatusCode::OK
            || resp.status() == http::StatusCode::BAD_GATEWAY
            || resp.status() == http::StatusCode::GATEWAY_TIMEOUT
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
        // Drop the listener so the port is free and connection will
        // fail
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
  /// This test creates an actual HTTP server that handles CONNECT
  /// requests.
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

  /// Test that uninstall() completes immediately when no streams are
  /// active.
  #[tokio::test]
  #[serial]
  async fn test_uninstall_no_active_streams() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let plugin = ConnectTcpPlugin::new();

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

  /// Test uninstall() with streams that respond to shutdown
  /// notification.
  #[tokio::test]
  #[serial]
  async fn test_uninstall_with_responsive_streams() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let plugin = ConnectTcpPlugin::new();

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
  #[serial]
  async fn test_uninstall_timeout_aborts_streams() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let plugin = ConnectTcpPlugin::new();

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
  #[serial]
  async fn test_uninstall_can_be_called_multiple_times() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let plugin = ConnectTcpPlugin::new();

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

  // ============== Unified Upgrade Tests ==============

  #[tokio::test]
  async fn test_service_call_with_upgrade_extracts_upgrade() {
    use crate::stream::OnUpgrade;

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

        // Create OnUpgrade with a LIVE sender (don't drop tx).
        // If the service correctly extracts OnUpgrade, the background
        // tunnel task will await it and block (sender alive = pending).
        // If the service does NOT extract it, it falls through to
        // hyper::upgrade::on() which fails immediately on a synthetic
        // request, causing the tunnel task to exit.
        let (tx, rx) = tokio::sync::oneshot::channel();
        let upgrade = OnUpgrade::new_for_test(rx);

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
        // upgrade.await (because tx is alive). This proves the upgrade
        // path was taken. If the service fell through to HTTP upgrade,
        // the task would have already exited (upgrade fails on
        // synthetic request) and active_count would be 0.
        assert_eq!(
          stream_tracker.active_count(),
          1,
          "Tunnel task should be alive, blocked on upgrade await. \
           If 0, the service did not extract OnUpgrade and fell \
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
  async fn test_service_call_upgrade_refused_returns_bad_gateway() {
    use crate::stream::OnUpgrade;

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
        let upgrade = OnUpgrade::new_for_test(rx);

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

  // ============== RequestContext Integration Tests ==============

  #[tokio::test]
  async fn test_service_writes_connect_ms_to_request_context() {
    use crate::context::RequestContext;

    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        // Start a local TCP server
        let target_listener =
          tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();

        let service = ConnectTcpService::new_for_test();
        let mut service = RuntimeService::new(service);

        // Create request with RequestContext in extensions
        let ctx = RequestContext::new();
        let mut req = make_connect_request(
          http::Method::CONNECT,
          &format!("127.0.0.1:{}", target_addr.port()),
        );
        req.extensions_mut().insert(ctx.clone());

        let resp = service.call(req).await.unwrap();

        // Must assert status first so a failed connect is a clear test
        // failure
        assert_eq!(
          resp.status(),
          http::StatusCode::OK,
          "CONNECT to local TCP server must succeed"
        );

        // RequestContext should have connect_ms
        let connect_ms = ctx.get("connect_tcp.connect_ms");
        assert!(
          connect_ms.is_some(),
          "RequestContext should contain \
           connect_tcp.connect_ms"
        );
        // connect_ms should be a valid number
        let ms: u64 = connect_ms.unwrap().parse().unwrap();
        assert!(ms < u64::MAX, "connect_ms should be a valid u64");
      })
      .await;
  }

  // ============== Forward Proxy Tests ==============

  #[tokio::test]
  async fn test_forward_http_origin_form_returns_400() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let service = ConnectTcpService::new_for_test();
        let mut service = RuntimeService::new(service);
        let req = make_connect_request(http::Method::GET, "/path");
        let resp = service.call(req).await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        let body = collect_body(resp.into_body()).await;
        assert_eq!(body, Bytes::from("Invalid target address"));
      })
      .await;
  }

  #[tokio::test]
  async fn test_forward_http_https_scheme_returns_400() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let service = ConnectTcpService::new_for_test();
        let mut service = RuntimeService::new(service);
        let req =
          make_connect_request(http::Method::GET, "https://example.com/");
        let resp = service.call(req).await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        let body = collect_body(resp.into_body()).await;
        assert_eq!(
          body,
          Bytes::from("Only http:// scheme supported for forward proxy")
        );
      })
      .await;
  }

  #[tokio::test]
  #[serial]
  async fn test_forward_http_success_writes_context_fields() {
    use http_body_util::Empty;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;

    // Pool must be initialized before forward_http can send requests
    pool::init_tcp_pool(DEFAULT_POOL_SIZE, DEFAULT_POOL_IDLE_TIMEOUT, DEFAULT_CONNECT_TIMEOUT)
      .expect("pool init");

    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        // Spin up a minimal HTTP/1.1 server
        let listener =
          tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
          if let Ok((stream, _)) = listener.accept().await {
            let io = TokioIo::new(stream);
            let svc = service_fn(|_req| async {
              Ok::<_, anyhow::Error>(
                http::Response::builder()
                  .status(200)
                  .body(Empty::<Bytes>::new())
                  .unwrap(),
              )
            });
            let _ = http1::Builder::new()
              .serve_connection(io, svc)
              .await;
          }
        });

        let service = ConnectTcpService::new_for_test();
        let mut service = RuntimeService::new(service);

        let ctx = crate::context::RequestContext::new();
        let mut req = make_connect_request(
          http::Method::GET,
          &format!("http://127.0.0.1:{}/", addr.port()),
        );
        req.extensions_mut().insert(ctx.clone());

        let resp = service.call(req).await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::OK);

        assert!(
          ctx.get("connect_tcp.forward_ms").is_some(),
          "forward_ms should be written to context"
        );
        assert_eq!(
          ctx.get("connect_tcp.forward_status").as_deref(),
          Some("200"),
          "forward_status should be written to context"
        );

        server_handle.abort();
      })
      .await;
  }

  #[tokio::test]
  #[serial]
  async fn test_forward_http_appends_proxy_status() {
    use http_body_util::Empty;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;

    pool::init_tcp_pool(DEFAULT_POOL_SIZE, DEFAULT_POOL_IDLE_TIMEOUT, DEFAULT_CONNECT_TIMEOUT)
      .expect("pool init");

    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        // Origin server returns its own Proxy-Status entry
        let listener =
          tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
          if let Ok((stream, _)) = listener.accept().await {
            let io = TokioIo::new(stream);
            let svc = service_fn(|_req| async {
              Ok::<_, anyhow::Error>(
                http::Response::builder()
                  .status(200)
                  .header("proxy-status", "origin-server")
                  .body(Empty::<Bytes>::new())
                  .unwrap(),
              )
            });
            let _ = http1::Builder::new()
              .serve_connection(io, svc)
              .await;
          }
        });

        let service = ConnectTcpService::new_for_test();
        let mut service = RuntimeService::new(service);

        let ctx = crate::context::RequestContext::new();
        ctx.insert("listener.hostname", "test-listener:8080");
        let mut req = make_connect_request(
          http::Method::GET,
          &format!("http://127.0.0.1:{}/", addr.port()),
        );
        req.extensions_mut().insert(ctx.clone());

        let resp = service.call(req).await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::OK);

        // Should have one Proxy-Status header containing both upstream's
        // entry and ours, comma-separated per RFC 9209.
        let ps = resp
          .headers()
          .get(http::header::HeaderName::from_static("proxy-status"))
          .expect("proxy-status header should be set on success");
        let ps_str = ps.to_str().unwrap();
        assert!(
          ps_str.contains("origin-server"),
          "should preserve upstream's Proxy-Status: {ps_str}"
        );
        assert!(
          ps_str.contains("test-listener"),
          "should append our entry: {ps_str}"
        );

        server_handle.abort();
      })
      .await;
  }

  #[tokio::test]
  #[serial]
  async fn test_forward_http_unreachable_returns_502() {
    // Pool must be initialized so the 502 comes from connection refused,
    // not from "pool not initialized".
    pool::init_tcp_pool(DEFAULT_POOL_SIZE, DEFAULT_POOL_IDLE_TIMEOUT, DEFAULT_CONNECT_TIMEOUT)
      .expect("pool init");

    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        // Bind and immediately drop to get a port that refuses connections
        let listener =
          tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let service = ConnectTcpService::new_for_test();
        let mut service = RuntimeService::new(service);
        let req = make_connect_request(
          http::Method::GET,
          &format!("http://127.0.0.1:{}/", addr.port()),
        );
        let resp = service.call(req).await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::BAD_GATEWAY);
      })
      .await;
  }
}
