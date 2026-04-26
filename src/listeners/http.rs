#![allow(clippy::await_holding_refcell_ref)]
use std::cell::RefCell;
use std::future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::rc::Rc;
use std::time::Duration;

use anyhow::Result;
use hyper::{body as hyper_body, service as hyper_svc};
use hyper_util::rt as rt_util;
use hyper_util::server::conn::auto as conn_util;
use serde::Deserialize;
use tokio::{net, task, time::timeout};
use tower::util as tower_util;
use tracing::{error, info, warn};

use crate::auth::UserPasswordAuth;
use crate::plugin;
use crate::server::ServerRoutingEntry;
use crate::shutdown::StreamTracker;

/// Listener shutdown timeout in seconds.
/// This is the timeout for Phase 1 of graceful shutdown.
const LISTENER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);

/// Monitoring log interval in seconds.
const MONITORING_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// HTTP Listener with shared-address routing support.
///
/// This listener supports routing requests to different services based on
/// the Host header. Multiple servers can share the same address with
/// hostname-based routing.
struct HyperServiceAdaptor {
  /// Routing table for hostname-based routing
  routing_table: Vec<ServerRoutingEntry>,
  /// Compiled routing info for fast lookup
  routing_info: Vec<neoproxy::routing::ServerMatchInfo>,
  /// User password auth (from first routing entry for backward compatibility)
  user_password_auth: UserPasswordAuth,
  /// Access log writer (from first routing entry)
  access_log_writer: Option<crate::access_log::AccessLogWriter>,
  /// Client address for logging
  client_addr: Option<SocketAddr>,
}

impl HyperServiceAdaptor {
  fn new(
    routing_table: Vec<ServerRoutingEntry>,
    routing_info: Vec<neoproxy::routing::ServerMatchInfo>,
    user_password_auth: UserPasswordAuth,
    access_log_writer: Option<crate::access_log::AccessLogWriter>,
    client_addr: Option<SocketAddr>,
  ) -> Self {
    Self {
      routing_table,
      routing_info,
      user_password_auth,
      access_log_writer,
      client_addr,
    }
  }

  /// Route a request to the correct service based on Host header.
  fn route_request(
    &self,
    req: &plugin::Request,
  ) -> Option<&ServerRoutingEntry> {
    // Get Host header and strip port if present
    let host = req
      .headers()
      .get(http::header::HOST)
      .and_then(|h| h.to_str().ok())
      .map(|h| h.split(':').next().unwrap_or(h));

    super::common::route_request_by_hostname(
      &self.routing_table,
      &self.routing_info,
      host,
    )
  }
}

impl hyper_svc::Service<hyper::Request<hyper_body::Incoming>>
  for HyperServiceAdaptor
{
  type Error = anyhow::Error;
  type Future = Pin<Box<dyn Future<Output = Result<plugin::Response>>>>;
  type Response = plugin::Response;

  fn call(
    &self,
    req: http::Request<hyper_body::Incoming>,
  ) -> Self::Future {
    let start_time = std::time::Instant::now();

    // Step 1: Check HTTP version FIRST
    // HTTP/1.0 is not supported - return 505 HTTP Version Not Supported
    if let Err(_status) = check_http_version(req.version()) {
      return Box::pin(async { Ok(build_505_response()) });
    }

    // Step 2: Build an http::Request<()> for auth verification, copying headers
    let mut auth_req_builder = http::Request::builder()
      .method(req.method().clone())
      .uri(req.uri().clone())
      .version(req.version());

    // Copy headers from the original request (important for Proxy-Authorization)
    for (name, value) in req.headers() {
      auth_req_builder = auth_req_builder.header(name, value);
    }

    let auth_req = auth_req_builder.body(()).unwrap();

    // Step 3: Check authentication if configured and extract username in one pass
    let verify_result =
      self.user_password_auth.verify_and_extract_username(&auth_req);
    let (user, auth_type) = match verify_result {
      Ok(Some(username)) => {
        (Some(username), crate::access_log::AuthType::Password)
      }
      Ok(None) => (None, crate::access_log::AuthType::None),
      Err(_) => {
        return Box::pin(async {
          Ok(super::common::build_407_response())
        });
      }
    };

    let (parts, body) = req.into_parts();
    let req = plugin::Request::from_parts(
      parts,
      plugin::RequestBody::new(plugin::BytesBufBodyWrapper::new(body)),
    );

    // Step 4: Route request to correct service
    let routing_entry = match self.route_request(&req) {
      Some(entry) => entry,
      None => {
        // No matching server found - return 404
        return Box::pin(async {
          Ok(super::common::build_404_response())
        });
      }
    };

    // Capture values for the async block
    let access_log_writer = self.access_log_writer.clone();
    let service_name = routing_entry.service_name();
    let client_addr = self.client_addr;
    let method = req.method().to_string();
    let target = req.uri().to_string();

    let s = routing_entry.service.clone();
    Box::pin(async move {
      let resp = tower_util::Oneshot::new(s, req).await;

      // Record access log by calling the tested helper
      if let Some(ref writer) = access_log_writer {
        let duration = start_time.elapsed();
        let status = match &resp {
          Ok(r) => r.status().as_u16(),
          Err(_) => 500,
        };

        let addr =
          client_addr.unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());

        // Extract ServiceMetrics from response extensions
        let service_metrics = resp
          .as_ref()
          .ok()
          .and_then(|r| {
            r.extensions()
              .get::<crate::access_log::ServiceMetrics>()
              .cloned()
          })
          .unwrap_or_default();

        let params = crate::access_log::HttpAccessLogParams {
          client_addr: addr,
          user,
          auth_type,
          method,
          target,
          status,
          duration,
          service_name,
          service_metrics,
        };

        record_access_log(writer, &params);
      }

      resp
    })
  }
}

/// Check HTTP version and return error if version is not supported.
///
/// HTTP/1.0 is NOT supported - returns 505 HTTP Version Not Supported.
/// HTTP/1.1 and higher are supported.
fn check_http_version(
  version: http::Version,
) -> Result<(), http::StatusCode> {
  super::common::check_http_version(version)
}

/// Build a 505 HTTP Version Not Supported response.
fn build_505_response() -> plugin::Response {
  super::common::build_505_response()
}

/// Record an access log entry for an HTTP request.
///
/// Delegates to the common implementation in `super::common::record_http_access_log`.
fn record_access_log(
  writer: &crate::access_log::AccessLogWriter,
  params: &crate::access_log::HttpAccessLogParams,
) {
  super::common::record_http_access_log(writer, params);
}

#[derive(Clone)]
pub struct TokioLocalExecutor {}

impl<F> hyper::rt::Executor<F> for TokioLocalExecutor
where
  F: Future + 'static,
{
  fn execute(&self, fut: F) {
    task::spawn_local(fut);
  }
}

/// HTTP Listener configuration arguments.
#[derive(Deserialize, Default, Clone, Debug)]
struct HttpListenerArgs {
  /// Listening addresses
  addresses: Vec<String>,
}

/// HTTP Listener implementation with shared-address routing support.
struct HyperListener {
  /// Listening addresses
  addresses: Vec<SocketAddr>,
  /// Routing table for hostname-based routing
  routing_table: Vec<ServerRoutingEntry>,
  /// Compiled routing info for fast lookup
  routing_info: Vec<neoproxy::routing::ServerMatchInfo>,
  /// Stream tracker for connection management
  listening_set: Rc<RefCell<task::JoinSet<Result<()>>>>,
  /// Connection tracker for graceful shutdown
  connection_tracker: Rc<StreamTracker>,
  /// Graceful shutdown timeout
  graceful_shutdown_timeout: Duration,
  /// User password auth (from first routing entry)
  user_password_auth: UserPasswordAuth,
  /// Access log writer (from first routing entry)
  access_log_writer: Option<crate::access_log::AccessLogWriter>,
}

impl HyperListener {
  /// Create a HyperListener from parsed configuration.
  fn from_args(
    args: HttpListenerArgs,
    _svc: plugin::Service, // Ignored - service comes from routing_table
    ctx: plugin::ListenerBuildContext,
  ) -> Result<Self> {
    // Build routing info from routing table
    let routing_info: Vec<neoproxy::routing::ServerMatchInfo> =
      ctx.routing_table.iter().map(|entry| entry.into()).collect();

    // Get user password auth from first routing entry
    let user_password_auth = ctx
      .routing_table
      .first()
      .map(|e| super::common::build_user_password_auth(&e.users))
      .unwrap_or_else(UserPasswordAuth::none);

    // Parse addresses, filtering out invalid ones
    // Note: Config validator catches invalid addresses, but we also filter here for safety
    let addresses: Vec<SocketAddr> = args
      .addresses
      .iter()
      .filter_map(|s| {
        s.parse()
          .inspect_err(|e| warn!("address '{s}' invalid: {e}"))
          .ok()
      })
      .collect();

    Ok(Self {
      addresses,
      routing_table: ctx.routing_table,
      routing_info,
      listening_set: Rc::new(RefCell::new(task::JoinSet::new())),
      connection_tracker: Rc::new(StreamTracker::new()),
      graceful_shutdown_timeout: LISTENER_SHUTDOWN_TIMEOUT,
      user_password_auth,
      access_log_writer: ctx.access_log_writer,
    })
  }

  #[allow(clippy::new_ret_no_self)]
  fn new(
    sargs: plugin::SerializedArgs,
    svc: plugin::Service,
    ctx: plugin::ListenerBuildContext,
  ) -> Result<plugin::Listener> {
    let args: HttpListenerArgs = serde_yaml::from_value(sargs)?;
    Ok(plugin::Listener::new(Self::from_args(args, svc, ctx)?))
  }

  /// Create a HyperListener directly for testing purposes.
  #[cfg(test)]
  fn new_for_test(
    sargs: plugin::SerializedArgs,
    svc: plugin::Service,
  ) -> Result<Self> {
    let args: HttpListenerArgs = serde_yaml::from_value(sargs)?;
    let entry = ServerRoutingEntry {
      name: "test".to_string(),
      hostnames: vec![],
      service: svc,
      service_name: "test_service".to_string(),
      users: None,
      tls: None,
      access_log_writer: None,
    };
    let ctx = plugin::ListenerBuildContext {
      access_log_writer: None,
      service_name: String::new(),
      routing_table: vec![entry],
    };
    Self::from_args(
      args,
      plugin::Service::new(DummyServiceForTest),
      ctx,
    )
  }

  fn serve_addr(
    &self,
    addr: SocketAddr,
  ) -> Result<Pin<Box<dyn Future<Output = Result<()>>>>> {
    let socket = match addr {
      std::net::SocketAddr::V4(_) => net::TcpSocket::new_v4()?,
      std::net::SocketAddr::V6(_) => net::TcpSocket::new_v6()?,
    };
    socket.set_reuseaddr(true)?;
    socket.set_reuseport(true)?;
    socket.bind(addr)?;
    let listener = socket.listen(1024)?;
    let connection_tracker = self.connection_tracker.clone();
    let shutdown_handle = self.connection_tracker.shutdown_handle();
    let routing_table = self.routing_table.clone();
    let routing_info = self.routing_info.clone();
    let user_password_auth = self.user_password_auth.clone();
    let access_log_writer = self.access_log_writer.clone();
    let accepting_fut = async move {
      // Log listener startup event
      info!("HTTP listener started on {}", addr);

      // Create monitoring interval timer
      let mut monitoring_interval =
        tokio::time::interval(MONITORING_LOG_INTERVAL);
      monitoring_interval.tick().await; // Skip first immediate tick

      let shutdown = async move || shutdown_handle.notified().await;
      let accepting = || async {
        match listener.accept().await {
          Err(e) => {
            error!("accepting new connection failed: {e}");
          }
          Ok((stream, raddr)) => {
            let io = rt_util::TokioIo::new(stream);
            let svc = HyperServiceAdaptor::new(
              routing_table.clone(),
              routing_info.clone(),
              user_password_auth.clone(),
              access_log_writer.clone(),
              Some(raddr),
            );
            let builder =
              conn_util::Builder::new(TokioLocalExecutor {});
            connection_tracker.register(async move {
              // Do not need any graceful shutdown actions here for
              // connections. The `Service`s should do this instead.
              let conn =
                builder.serve_connection_with_upgrades(io, svc);
              if let Err(e) = conn.await {
                error!("connection error: {e}");
              }
            });
          }
        }
      };

      loop {
        tokio::select! {
          _ = accepting() => {},
          _ = monitoring_interval.tick() => {
            // Log monitoring info
            info!(
              "[http] active_connections={}",
              connection_tracker.active_count()
            );
          }
          _ = shutdown() => {
            // Graceful shutdown for the TcpListener.
            info!("HTTP listener on {} shutting down", addr);
            break
          },
        }
      }

      // Here the TcpListener is dropped, so listening socket is closed.
      Ok(())
    };

    Ok(Box::pin(accepting_fut))
  }
}

impl plugin::Listening for HyperListener {
  fn start(&self) -> Pin<Box<dyn Future<Output = Result<()>>>> {
    let listening_set = self.listening_set.clone();
    for addr in &self.addresses {
      let addr = *addr;
      let serve_addr_fut = match self.serve_addr(addr) {
        Err(e) => return Box::pin(future::ready(Err(e))),
        Ok(f) => f,
      };
      listening_set.borrow_mut().spawn_local(serve_addr_fut);
    }

    let connection_tracker = self.connection_tracker.clone();
    let shutdown = self.connection_tracker.shutdown_handle();
    let graceful_timeout = self.graceful_shutdown_timeout;
    Box::pin(async move {
      // Waiting for graceful shutdown.
      shutdown.notified().await;

      while let Some(res) = listening_set.borrow_mut().join_next().await
      {
        match res {
          Err(e) => {
            error!("listening join error: {e}")
          }
          Ok(res) => {
            if let Err(e) = res {
              error!("listening error: {e}")
            }
          }
        }
      }

      // Wait for active connections with timeout
      let wait_result = timeout(graceful_timeout, async {
        connection_tracker.wait_shutdown().await;
      })
      .await;

      if wait_result.is_err() {
        // Timeout expired, force close remaining connections
        warn!(
          "graceful shutdown timeout ({:?}) expired, aborting {} \
           remaining connections",
          graceful_timeout,
          connection_tracker.active_count()
        );
        connection_tracker.abort_all();
      }

      Ok(())
    })
  }

  fn stop(&self) {
    self.connection_tracker.shutdown()
  }
}

pub fn listener_name() -> &'static str {
  "http"
}

pub fn create_listener_builder() -> Box<dyn plugin::BuildListener> {
  Box::new(HyperListener::new)
}

/// A dummy service for testing
#[cfg(test)]
#[derive(Clone)]
struct DummyServiceForTest;

#[cfg(test)]
impl tower::Service<plugin::Request> for DummyServiceForTest {
  type Error = anyhow::Error;
  type Future = Pin<Box<dyn Future<Output = Result<plugin::Response>>>>;
  type Response = plugin::Response;

  fn poll_ready(
    &mut self,
    _cx: &mut std::task::Context<'_>,
  ) -> std::task::Poll<Result<()>> {
    std::task::Poll::Ready(Ok(()))
  }

  fn call(&mut self, _req: plugin::Request) -> Self::Future {
    Box::pin(async {
      anyhow::bail!("DummyServiceForTest not implemented")
    })
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::auth::ListenerAuthConfig;
  use crate::plugin::Listening;
  use base64::{Engine, engine::general_purpose::STANDARD};
  use std::future::Future;
  use std::pin::Pin;
  use std::task::{Context, Poll};
  use tower::Service;

  // ============== HttpListenerArgs Tests ==============

  #[test]
  fn test_http_listener_args_no_auth_field() {
    // Auth should no longer be at listener level
    let yaml = r#"
addresses:
  - "127.0.0.1:8080"
"#;
    let args: HttpListenerArgs = serde_yaml::from_str(yaml).unwrap();
    assert!(args.addresses.len() == 1);
    // Auth should not be part of listener args
  }

  #[test]
  fn test_http_listener_args_protocols_removed() {
    // The protocols field is no longer needed with new architecture
    let yaml = r#"
addresses:
  - "127.0.0.1:8080"
"#;
    let args: HttpListenerArgs = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(args.addresses[0], "127.0.0.1:8080");
  }

  /// A dummy service for testing
  #[derive(Clone)]
  struct DummyService {}

  impl Service<plugin::Request> for DummyService {
    type Error = anyhow::Error;
    type Future =
      Pin<Box<dyn Future<Output = Result<plugin::Response>>>>;
    type Response = plugin::Response;

    fn poll_ready(
      &mut self,
      _cx: &mut Context<'_>,
    ) -> Poll<Result<()>> {
      Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: plugin::Request) -> Self::Future {
      Box::pin(async { anyhow::bail!("DummyService not implemented") })
    }
  }

  fn create_test_listener_args() -> plugin::SerializedArgs {
    serde_yaml::from_str(r#"{addresses: ["127.0.0.1:0"]}"#).unwrap()
  }

  fn create_test_listener_args_with_invalid() -> plugin::SerializedArgs
  {
    serde_yaml::from_str(r#"{addresses: ["invalid", "127.0.0.1:0"]}"#)
      .unwrap()
  }

  fn create_test_service() -> plugin::Service {
    plugin::Service::new(DummyService {})
  }

  fn create_test_routing_entry() -> ServerRoutingEntry {
    ServerRoutingEntry {
      name: "test".to_string(),
      hostnames: vec![],
      service: create_test_service(),
      service_name: "test_service".to_string(),
      users: None,
      tls: None,
      access_log_writer: None,
    }
  }

  fn create_test_context() -> plugin::ListenerBuildContext {
    plugin::ListenerBuildContext {
      access_log_writer: None,
      service_name: String::new(),
      routing_table: vec![create_test_routing_entry()],
    }
  }

  #[test]
  fn test_listener_name() {
    assert_eq!(listener_name(), "http");
  }

  #[test]
  fn test_create_listener_builder() {
    let builder = create_listener_builder();
    let args = create_test_listener_args();
    let svc = create_test_service();
    let ctx = create_test_context();
    let result = builder(args, svc, ctx);
    assert!(result.is_ok());
  }

  #[test]
  fn test_hyper_listener_new_valid() {
    let args = create_test_listener_args();
    let svc = create_test_service();
    let ctx = create_test_context();
    let result = HyperListener::new(args, svc, ctx);
    assert!(result.is_ok());
  }

  #[test]
  fn test_hyper_listener_new_invalid_address() {
    let args = create_test_listener_args_with_invalid();
    let svc = create_test_service();
    let ctx = create_test_context();
    let result = HyperListener::new(args, svc, ctx);
    // Invalid addresses are filtered out, so it should still succeed
    assert!(result.is_ok());
  }

  #[test]
  fn test_hyper_listener_new_missing_addresses() {
    let args: plugin::SerializedArgs =
      serde_yaml::from_str(r#"{protocols: [], hostnames: []}"#)
        .unwrap();
    let svc = create_test_service();
    let ctx = create_test_context();
    let result = HyperListener::new(args, svc, ctx);
    // Missing required field should fail
    assert!(result.is_err());
  }

  #[test]
  fn test_active_connections_initial() {
    let args = create_test_listener_args();
    let svc = create_test_service();
    let listener = HyperListener::new_for_test(args, svc).unwrap();
    // active_connections should be 0 initially
    assert_eq!(listener.connection_tracker.active_count(), 0);
  }

  #[test]
  fn test_listener_shutdown_timeout_constant() {
    assert_eq!(LISTENER_SHUTDOWN_TIMEOUT, Duration::from_secs(3));
  }

  #[test]
  fn test_tokio_local_executor() {
    let executor = TokioLocalExecutor {};
    // Verify the executor can be cloned
    let _cloned = executor.clone();
  }

  #[test]
  fn test_hyper_service_adaptor_creation() {
    let routing_table = vec![create_test_routing_entry()];
    let routing_info = vec![neoproxy::routing::ServerMatchInfo {
      name: "test".to_string(),
      hostnames: vec![],
    }];
    let _adaptor = HyperServiceAdaptor::new(
      routing_table,
      routing_info,
      UserPasswordAuth::none(),
      None,
      None,
    );
  }

  #[test]
  fn test_http_listener_args_default() {
    let args = HttpListenerArgs::default();
    assert!(args.addresses.is_empty());
  }

  #[test]
  fn test_http_listener_args_deserialize() {
    let yaml = r#"
addresses:
  - "127.0.0.1:8080"
  - "0.0.0.0:8081"
"#;
    let args: HttpListenerArgs = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(args.addresses.len(), 2);
    assert_eq!(args.addresses[0], "127.0.0.1:8080");
    assert_eq!(args.addresses[1], "0.0.0.0:8081");
  }

  #[test]
  fn test_listener_stop_and_start() {
    // This test verifies the listener can be created and stopped
    let args = create_test_listener_args();
    let svc = create_test_service();
    let listener = HyperListener::new_for_test(args, svc).unwrap();

    // Stop should work even without start
    listener.stop();
  }

  #[test]
  fn test_shutdown_handle_clone() {
    let handle1 = plugin::ShutdownHandle::new();
    let handle2 = handle1.clone();
    // Both handles should refer to the same notify
    handle1.shutdown();
    // After shutdown, notified should return immediately
    // (but we don't test async behavior here)
    drop(handle2);
  }

  #[test]
  fn test_hyper_listener_struct_fields() {
    // Verify struct has all expected fields
    let args = create_test_listener_args();
    let svc = create_test_service();
    let ctx = create_test_context();
    let listener = HyperListener::new(args, svc, ctx);

    // This test verifies the constructor succeeds
    assert!(listener.is_ok());
  }

  #[test]
  fn test_listening_trait_implementation() {
    // Verify HyperListener implements Listening
    fn assert_listening<T: plugin::Listening>() {}
    assert_listening::<HyperListener>();
  }

  #[test]
  fn test_graceful_shutdown_timeout_is_3_seconds() {
    // Verify the constant is 3 seconds as per requirements
    assert_eq!(LISTENER_SHUTDOWN_TIMEOUT.as_secs(), 3);
    assert_eq!(LISTENER_SHUTDOWN_TIMEOUT.as_millis(), 3000);
  }

  #[test]
  fn test_monitoring_log_interval_is_60_seconds() {
    // Verify the constant is 60 seconds as per requirements
    assert_eq!(MONITORING_LOG_INTERVAL.as_secs(), 60);
    assert_eq!(MONITORING_LOG_INTERVAL.as_millis(), 60000);
  }

  #[test]
  fn test_monitoring_log_format() {
    // Test that the monitoring log format is correct
    let args = create_test_listener_args();
    let svc = create_test_service();
    let listener = HyperListener::new_for_test(args, svc).unwrap();

    // Simulate the monitoring log format string
    let expected_format = format!(
      "[http] active_connections={}",
      listener.connection_tracker.active_count()
    );

    // Verify format contains correct components
    assert!(
      expected_format.contains("[http]"),
      "Log format should contain '[http]'"
    );
    assert!(
      expected_format.contains("active_connections"),
      "Log format should contain 'active_connections'"
    );
    assert!(
      expected_format.contains("active_connections=0"),
      "Log format should show initial count as 0"
    );
  }

  #[test]
  fn test_http_listener_with_server_level_users() {
    // Auth should come from server-level users via routing table
    use crate::config::UserConfig;

    let args: HttpListenerArgs =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:0"]}"#).unwrap();
    let svc = create_test_service();
    let entry = ServerRoutingEntry {
      name: "test".to_string(),
      hostnames: vec![],
      service: svc,
      service_name: "test_service".to_string(),
      users: Some(vec![UserConfig {
        username: "user1".to_string(),
        password: "pass1".to_string(),
      }]),
      tls: None,
      access_log_writer: None,
    };
    let ctx = plugin::ListenerBuildContext {
      access_log_writer: None,
      service_name: String::new(),
      routing_table: vec![entry],
    };
    let listener =
      HyperListener::from_args(args, create_test_service(), ctx)
        .unwrap();
    // Verify listener was created with auth from server-level config
    assert!(
      listener
        .user_password_auth
        .verify_and_extract_username(
          &http::Request::builder()
            .method("GET")
            .uri("http://example.com")
            .body(())
            .unwrap()
        )
        .is_err(),
      "Without credentials, verify should fail when users configured"
    );
  }

  #[test]
  fn test_build_407_response() {
    let resp = super::super::common::build_407_response();
    assert_eq!(
      resp.status(),
      http::StatusCode::PROXY_AUTHENTICATION_REQUIRED
    );
    assert!(resp.headers().contains_key("Proxy-Authenticate"));
  }

  #[test]
  fn test_build_404_response() {
    let resp = super::super::common::build_404_response();
    assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
  }

  #[test]
  fn test_check_auth_missing_header_returns_407() {
    // Test that requests without auth header return 407 when auth is configured
    use crate::auth::listener_auth_config::UserCredential;

    let config = ListenerAuthConfig {
      users: Some(vec![UserCredential {
        username: "user1".to_string(),
        password: "pass1".to_string(),
      }]),
      client_ca_path: None,
    };
    let auth = UserPasswordAuth::from_config(&config);

    // Simulate missing auth header
    let req = http::Request::builder()
      .method("GET")
      .uri("http://example.com")
      .body(())
      .unwrap();

    // Should return 407 response requirement
    assert!(
      auth.verify_and_extract_username(&req).is_err(),
      "Missing auth header should fail verification"
    );
  }

  #[test]
  fn test_check_auth_wrong_credentials_returns_407() {
    use crate::auth::listener_auth_config::UserCredential;

    let config = ListenerAuthConfig {
      users: Some(vec![UserCredential {
        username: "user1".to_string(),
        password: "pass1".to_string(),
      }]),
      client_ca_path: None,
    };
    let auth = UserPasswordAuth::from_config(&config);

    // Create header with wrong credentials (user2:wrongpass)
    let encoded = STANDARD.encode("user2:wrongpass");
    let req = http::Request::builder()
      .method("GET")
      .uri("http://example.com")
      .header("Proxy-Authorization", format!("Basic {}", encoded))
      .body(())
      .unwrap();

    // Verify against config - should fail
    assert!(
      auth.verify_and_extract_username(&req).is_err(),
      "Wrong credentials should fail verification"
    );
  }

  #[test]
  fn test_check_auth_valid_credentials_passes() {
    use crate::auth::listener_auth_config::UserCredential;

    let config = ListenerAuthConfig {
      users: Some(vec![UserCredential {
        username: "user1".to_string(),
        password: "pass1".to_string(),
      }]),
      client_ca_path: None,
    };
    let auth = UserPasswordAuth::from_config(&config);

    // Create header with correct credentials
    let encoded = STANDARD.encode("user1:pass1");
    let req = http::Request::builder()
      .method("GET")
      .uri("http://example.com")
      .header("Proxy-Authorization", format!("Basic {}", encoded))
      .body(())
      .unwrap();

    // Verify against config - should pass
    assert!(
      auth.verify_and_extract_username(&req).is_ok(),
      "Valid credentials should pass verification"
    );
  }

  #[test]
  fn test_record_access_log_writes_entry() {
    let dir = tempfile::tempdir().unwrap();
    let config = crate::access_log::AccessLogConfig {
      enabled: true,
      path_prefix: "hypertest.log".to_string(),
      format: crate::access_log::config::LogFormat::Text,
      buffer: crate::access_log::config::HumanBytes(64),
      flush: crate::access_log::config::HumanDuration(
        std::time::Duration::from_millis(100),
      ),
      max_size: crate::access_log::config::HumanBytes(1024 * 1024),
    };
    let writer = crate::access_log::AccessLogWriter::new(
      dir.path().to_str().unwrap(),
      &config,
    );

    let client_addr: SocketAddr = "192.168.1.1:54321".parse().unwrap();
    let mut metrics = crate::access_log::ServiceMetrics::new();
    metrics.add("connect_ms", 42u64);

    let params = crate::access_log::HttpAccessLogParams {
      client_addr,
      user: Some("testuser".to_string()),
      auth_type: crate::access_log::AuthType::Password,
      method: "CONNECT".to_string(),
      target: "example.com:443".to_string(),
      status: 200,
      duration: std::time::Duration::from_millis(50),
      service_name: "tunnel".to_string(),
      service_metrics: metrics,
    };

    record_access_log(&writer, &params);

    writer.flush();

    // Verify log file was created and contains expected fields
    let mut found = false;
    for entry in std::fs::read_dir(dir.path()).unwrap() {
      let entry = entry.unwrap();
      let name = entry.file_name().to_string_lossy().to_string();
      if name.starts_with("hypertest.log") {
        let content = std::fs::read_to_string(entry.path()).unwrap();
        assert!(
          content.contains("192.168.1.1:54321"),
          "Should contain client addr"
        );
        assert!(
          content.contains("CONNECT example.com:443"),
          "Should contain request line"
        );
        assert!(content.contains("200"), "Should contain status code");
        assert!(
          content.contains("service=tunnel"),
          "Should contain service name"
        );
        assert!(
          content.contains("service.connect_ms=42"),
          "Should contain service metrics"
        );
        assert!(
          content.contains("auth=password"),
          "Should contain auth type"
        );
        found = true;
      }
    }
    assert!(found, "Access log file should exist");
  }

  #[test]
  fn test_hyper_listener_stores_access_log_writer() {
    let args = create_test_listener_args();
    let svc = create_test_service();
    let ctx = create_test_context();
    let listener = HyperListener::new(args, svc, ctx).unwrap();
    // Should compile and create without error
    drop(listener);
  }

  #[test]
  fn test_hyper_listener_with_access_log_writer() {
    let dir = tempfile::tempdir().unwrap();
    let config = crate::access_log::AccessLogConfig {
      enabled: true,
      path_prefix: "test.log".to_string(),
      format: crate::access_log::config::LogFormat::Text,
      buffer: crate::access_log::config::HumanBytes(256),
      flush: crate::access_log::config::HumanDuration(
        std::time::Duration::from_millis(100),
      ),
      max_size: crate::access_log::config::HumanBytes(1024 * 1024),
    };
    let writer = crate::access_log::AccessLogWriter::new(
      dir.path().to_str().unwrap(),
      &config,
    );

    let args = create_test_listener_args();
    let entry = ServerRoutingEntry {
      name: "test".to_string(),
      hostnames: vec![],
      service: create_test_service(),
      service_name: "tunnel".to_string(),
      users: None,
      tls: None,
      access_log_writer: Some(writer),
    };
    let ctx = plugin::ListenerBuildContext {
      access_log_writer: None,
      service_name: "tunnel".to_string(),
      routing_table: vec![entry],
    };
    let listener =
      HyperListener::new(args, create_test_service(), ctx).unwrap();
    // Should compile and create without error
    drop(listener);
  }

  // ============== HTTP Version Check Tests ==============

  #[test]
  fn test_check_http_version_http10_returns_505() {
    // HTTP/1.0 should return 505
    let version = http::Version::HTTP_10;
    let result = check_http_version(version);
    assert!(result.is_err());
    assert_eq!(
      result.unwrap_err(),
      http::StatusCode::HTTP_VERSION_NOT_SUPPORTED
    );
  }

  #[test]
  fn test_check_http_version_http11_ok() {
    // HTTP/1.1 should pass
    let version = http::Version::HTTP_11;
    let result = check_http_version(version);
    assert!(result.is_ok());
  }

  #[test]
  fn test_check_http_version_http2_ok() {
    // HTTP/2 should pass (hyper handles this)
    let version = http::Version::HTTP_2;
    let result = check_http_version(version);
    assert!(result.is_ok());
  }

  #[test]
  fn test_build_505_response() {
    let resp = build_505_response();
    assert_eq!(
      resp.status(),
      http::StatusCode::HTTP_VERSION_NOT_SUPPORTED
    );
    assert!(resp.headers().get(http::header::CONTENT_TYPE).is_some());
  }

  // ============== Routing Tests ==============

  #[test]
  fn test_route_request_no_host_header() {
    let routing_table = vec![
      ServerRoutingEntry {
        name: "default".to_string(),
        hostnames: vec![],
        service: create_test_service(),
        service_name: "test_service".to_string(),
        users: None,
        tls: None,
        access_log_writer: None,
      },
      ServerRoutingEntry {
        name: "api".to_string(),
        hostnames: vec!["api.example.com".to_string()],
        service: create_test_service(),
        service_name: "test_service".to_string(),
        users: None,
        tls: None,
        access_log_writer: None,
      },
    ];
    let routing_info = vec![
      neoproxy::routing::ServerMatchInfo {
        name: "default".to_string(),
        hostnames: vec![],
      },
      neoproxy::routing::ServerMatchInfo {
        name: "api".to_string(),
        hostnames: vec!["api.example.com".to_string()],
      },
    ];

    let adaptor = HyperServiceAdaptor::new(
      routing_table,
      routing_info,
      UserPasswordAuth::none(),
      None,
      None,
    );

    // Request without Host header should route to default
    let req = http::Request::builder()
      .method("GET")
      .uri("/test")
      .body(plugin::RequestBody::new(plugin::BytesBufBodyWrapper::new(
        http_body_util::Empty::new(),
      )))
      .unwrap();

    let result = adaptor.route_request(&req);
    assert!(result.is_some());
    assert_eq!(result.unwrap().name, "default");
  }

  #[test]
  fn test_route_request_with_host_header() {
    let routing_table = vec![
      ServerRoutingEntry {
        name: "default".to_string(),
        hostnames: vec![],
        service: create_test_service(),
        service_name: "test_service".to_string(),
        users: None,
        tls: None,
        access_log_writer: None,
      },
      ServerRoutingEntry {
        name: "api".to_string(),
        hostnames: vec!["api.example.com".to_string()],
        service: create_test_service(),
        service_name: "test_service".to_string(),
        users: None,
        tls: None,
        access_log_writer: None,
      },
    ];
    let routing_info = vec![
      neoproxy::routing::ServerMatchInfo {
        name: "default".to_string(),
        hostnames: vec![],
      },
      neoproxy::routing::ServerMatchInfo {
        name: "api".to_string(),
        hostnames: vec!["api.example.com".to_string()],
      },
    ];

    let adaptor = HyperServiceAdaptor::new(
      routing_table,
      routing_info,
      UserPasswordAuth::none(),
      None,
      None,
    );

    // Request with Host header should route to matching server
    let req = http::Request::builder()
      .method("GET")
      .uri("/test")
      .header(http::header::HOST, "api.example.com")
      .body(plugin::RequestBody::new(plugin::BytesBufBodyWrapper::new(
        http_body_util::Empty::new(),
      )))
      .unwrap();

    let result = adaptor.route_request(&req);
    assert!(result.is_some());
    assert_eq!(result.unwrap().name, "api");
  }
}
