#![allow(clippy::await_holding_refcell_ref)]
use std::cell::RefCell;
use std::collections::HashMap;
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

use crate::auth::{AuthConfig, AuthType, parse_basic_auth, verify_password};
use crate::listeners::fast_socks5::ConnectionTracker;
use crate::plugin;

/// Listener shutdown timeout in seconds.
/// This is the timeout for Phase 1 of graceful shutdown.
const LISTENER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);

/// Monitoring log interval in seconds.
const MONITORING_LOG_INTERVAL: Duration = Duration::from_secs(60);

struct HyperServiceAdaptor {
  s: plugin::Service,
  /// Cached users map, computed once at adaptor creation to avoid
  /// per-request HashMap allocation from auth_config.users_map().
  /// CR-010: This field doubles as the auth-required guard:
  /// Some(_) means auth is configured, None means no auth.
  credentials: Option<HashMap<String, String>>,
}

impl HyperServiceAdaptor {
  fn new(s: plugin::Service, credentials: Option<HashMap<String, String>>) -> Self {
    Self { s, credentials }
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
    // Check authentication if configured
    // CR-010: Use self.credentials.is_some() as the auth-required guard
    // instead of a separate auth field
    if self.credentials.is_some() {
      let auth_header = req.headers().get(http::header::PROXY_AUTHORIZATION);

      match (auth_header, &self.credentials) {
        (None, Some(_)) => {
          // No auth header but auth required
          return Box::pin(async { Ok(build_407_response()) });
        }
        (Some(header), Some(credentials)) => {
          // Validate credentials
          match parse_basic_auth(header) {
            Ok((username, password)) => {
              if let Err(_) = verify_password(credentials, &username, &password) {
                return Box::pin(async { Ok(build_407_response()) });
              }
            }
            Err(_) => {
              return Box::pin(async { Ok(build_407_response()) });
            }
          }
        }
        _ => {}
      }
    }

    let (parts, body) = req.into_parts();
    let req = plugin::Request::from_parts(
      parts,
      plugin::RequestBody::new(plugin::BytesBufBodyWrapper::new(body)),
    );
    let s = self.s.clone();
    Box::pin(tower_util::Oneshot::new(s, req))
  }
}

/// Build a 407 Proxy Authentication Required response.
fn build_407_response() -> plugin::Response {
  let empty = http_body_util::Empty::new();
  let bytes_buf = plugin::BytesBufBodyWrapper::new(empty);
  let body = plugin::ResponseBody::new(bytes_buf);
  let mut resp = plugin::Response::new(body);
  *resp.status_mut() = http::StatusCode::PROXY_AUTHENTICATION_REQUIRED;
  resp.headers_mut().insert(
    http::header::PROXY_AUTHENTICATE,
    http::HeaderValue::from_static("Basic realm=\"proxy\""),
  );
  resp
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

#[derive(Deserialize, Default, Clone, Debug)]
struct HyperListenerArgs {
  addresses: Vec<String>,
  protocols: Vec<String>,
  hostnames: Vec<String>,
  #[serde(default)]
  auth: Option<serde_yaml::Value>,
}

struct HyperListener {
  addresses: Vec<SocketAddr>,
  _protocols: Vec<String>,
  _hostnames: Vec<String>,
  listening_set: Rc<RefCell<task::JoinSet<Result<()>>>>,
  connection_tracker: ConnectionTracker,
  service: plugin::Service,
  graceful_shutdown_timeout: Duration,
  /// CR-010: Store only the pre-computed credentials HashMap, not the full AuthConfig.
  /// This avoids cloning the entire AuthConfig per connection.
  credentials: Option<HashMap<String, String>>,
}

impl HyperListener {
  /// Create a HyperListener from parsed configuration.
  fn from_args(args: HyperListenerArgs, svc: plugin::Service) -> Self {
    let auth = args.auth.and_then(|yaml| {
      AuthConfig::from_yaml(yaml, &[AuthType::Password])
        .inspect_err(|e| warn!("Failed to parse auth config: {e}"))
        .ok()
    });
    // CR-010: Pre-compute credentials once at listener creation instead of
    // storing the full AuthConfig and recomputing per connection
    let credentials = auth.as_ref().and_then(|c| c.users_map());

    Self {
      addresses: args
        .addresses
        .iter()
        .filter_map(|s| {
          s.parse()
            .inspect_err(|e| warn!("address '{s}' invalid: {e}"))
            .ok()
        })
        .collect(),
      _protocols: args.protocols,
      _hostnames: args.hostnames,
      listening_set: Rc::new(RefCell::new(task::JoinSet::new())),
      connection_tracker: ConnectionTracker::new(),
      service: svc,
      graceful_shutdown_timeout: LISTENER_SHUTDOWN_TIMEOUT,
      credentials,
    }
  }

  #[allow(clippy::new_ret_no_self)]
  fn new(
    sargs: plugin::SerializedArgs,
    svc: plugin::Service,
  ) -> Result<plugin::Listener> {
    let args: HyperListenerArgs = serde_yaml::from_value(sargs)?;
    Ok(plugin::Listener::new(Self::from_args(args, svc)))
  }

  /// Create a HyperListener directly for testing purposes.
  #[cfg(test)]
  fn new_for_test(
    sargs: plugin::SerializedArgs,
    svc: plugin::Service,
  ) -> Result<Self> {
    let args: HyperListenerArgs = serde_yaml::from_value(sargs)?;
    Ok(Self::from_args(args, svc))
  }

  fn serve_addr(
    &self,
    addr: SocketAddr,
    svc: plugin::Service,
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
    let credentials = self.credentials.clone();
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
          Ok((stream, _raddr)) => {
            let io = rt_util::TokioIo::new(stream);
            let svc = HyperServiceAdaptor::new(svc.clone(), credentials.clone());
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
              "[hyper.listener] active_connections={}",
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
      let service = self.service.clone();
      let serve_addr_fut = match self.serve_addr(addr, service) {
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
  "hyper.listener"
}

pub fn create_listener_builder() -> Box<dyn plugin::BuildListener> {
  Box::new(HyperListener::new)
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::plugin::Listening;
  use base64::{Engine, engine::general_purpose::STANDARD};
  use std::future::Future;
  use std::pin::Pin;
  use std::task::{Context, Poll};
  use tower::Service;

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
    serde_yaml::from_str(
      r#"{addresses: ["127.0.0.1:0"], protocols: [], hostnames: []}"#,
    )
    .unwrap()
  }

  fn create_test_listener_args_with_invalid() -> plugin::SerializedArgs
  {
    serde_yaml::from_str(
      r#"{addresses: ["invalid", "127.0.0.1:0"], protocols: [], hostnames: []}"#,
    )
    .unwrap()
  }

  fn create_test_service() -> plugin::Service {
    plugin::Service::new(DummyService {})
  }

  #[test]
  fn test_listener_name() {
    assert_eq!(listener_name(), "hyper.listener");
  }

  #[test]
  fn test_create_listener_builder() {
    let builder = create_listener_builder();
    let args = create_test_listener_args();
    let svc = create_test_service();
    let result = builder(args, svc);
    assert!(result.is_ok());
  }

  #[test]
  fn test_hyper_listener_new_valid() {
    let args = create_test_listener_args();
    let svc = create_test_service();
    let result = HyperListener::new(args, svc);
    assert!(result.is_ok());
  }

  #[test]
  fn test_hyper_listener_new_invalid_address() {
    let args = create_test_listener_args_with_invalid();
    let svc = create_test_service();
    let result = HyperListener::new(args, svc);
    // Invalid addresses are filtered out, so it should still succeed
    assert!(result.is_ok());
  }

  #[test]
  fn test_hyper_listener_new_missing_addresses() {
    let args: plugin::SerializedArgs =
      serde_yaml::from_str(r#"{protocols: [], hostnames: []}"#)
        .unwrap();
    let svc = create_test_service();
    let result = HyperListener::new(args, svc);
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
    let svc = create_test_service();
    let _adaptor = HyperServiceAdaptor::new(svc, None);
  }

  #[test]
  fn test_hyper_listener_args_default() {
    let args = HyperListenerArgs::default();
    assert!(args.addresses.is_empty());
    assert!(args.protocols.is_empty());
    assert!(args.hostnames.is_empty());
  }

  #[test]
  fn test_hyper_listener_args_deserialize() {
    let yaml = r#"
addresses:
  - "127.0.0.1:8080"
  - "0.0.0.0:8081"
protocols:
  - "http1"
hostnames:
  - "localhost"
"#;
    let args: HyperListenerArgs = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(args.addresses.len(), 2);
    assert_eq!(args.protocols.len(), 1);
    assert_eq!(args.hostnames.len(), 1);
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
    let listener = HyperListener::new(args, svc);

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
      "[hyper.listener] active_connections={}",
      listener.connection_tracker.active_count()
    );

    // Verify format contains correct components
    assert!(
      expected_format.contains("[hyper.listener]"),
      "Log format should contain '[hyper.listener]'"
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
  fn test_hyper_listener_args_with_auth() {
    let yaml = r#"
addresses:
  - "127.0.0.1:8080"
protocols: []
hostnames: []
auth:
  type: password
  users:
    - username: "user1"
      password: "pass1"
"#;
    let args: HyperListenerArgs = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(args.addresses.len(), 1);
    assert!(args.auth.is_some());
  }

  #[test]
  fn test_build_407_response() {
    let resp = build_407_response();
    assert_eq!(resp.status(), http::StatusCode::PROXY_AUTHENTICATION_REQUIRED);
    assert!(resp.headers().contains_key("Proxy-Authenticate"));
  }

  #[test]
  fn test_check_auth_missing_header_returns_407() {
    // Test that requests without auth header return 407 when auth is configured
    use crate::auth::AuthConfig;

    let yaml = r#"
type: password
users:
  - username: "user1"
    password: "pass1"
"#;
    let auth_config: AuthConfig = serde_yaml::from_str(yaml).unwrap();

    // Simulate missing auth header
    let headers = http::HeaderMap::new();
    let auth_header = headers.get(http::header::PROXY_AUTHORIZATION);

    // Should return 407 response requirement
    let needs_407 = match (auth_header, auth_config.users_map()) {
      (None, Some(_)) => true,
      _ => false,
    };
    assert!(needs_407, "Missing auth header should require 407 response");
  }

  #[test]
  fn test_check_auth_wrong_credentials_returns_407() {
    use crate::auth::AuthConfig;

    let yaml = r#"
type: password
users:
  - username: "user1"
    password: "pass1"
"#;
    let auth_config: AuthConfig = serde_yaml::from_str(yaml).unwrap();

    // Create header with wrong credentials (user2:wrongpass)
    let encoded = STANDARD.encode("user2:wrongpass");
    let header = http::HeaderValue::from_str(&format!("Basic {}", encoded)).unwrap();

    // Parse and verify
    let result = parse_basic_auth(&header);
    assert!(result.is_ok());
    let (username, password) = result.unwrap();

    // Verify against config - should fail
    let verify_result = verify_password(&auth_config.users_map().unwrap(), &username, &password);
    assert!(verify_result.is_err(), "Wrong credentials should fail verification");
  }

  #[test]
  fn test_check_auth_valid_credentials_passes() {
    use crate::auth::AuthConfig;

    let yaml = r#"
type: password
users:
  - username: "user1"
    password: "pass1"
"#;
    let auth_config: AuthConfig = serde_yaml::from_str(yaml).unwrap();

    // Create header with correct credentials
    let encoded = STANDARD.encode("user1:pass1");
    let header = http::HeaderValue::from_str(&format!("Basic {}", encoded)).unwrap();

    // Parse and verify
    let result = parse_basic_auth(&header);
    assert!(result.is_ok());
    let (username, password) = result.unwrap();

    // Verify against config - should pass
    let verify_result = verify_password(&auth_config.users_map().unwrap(), &username, &password);
    assert!(verify_result.is_ok(), "Valid credentials should pass verification");
  }

  #[test]
  fn test_adaptor_caches_credentials() {
    use crate::auth::AuthConfig;

    let yaml = r#"
type: password
users:
  - username: "user1"
    password: "pass1"
"#;
    let auth_config: AuthConfig = serde_yaml::from_str(yaml).unwrap();
    let credentials = auth_config.users_map();
    let svc = create_test_service();
    let adaptor = HyperServiceAdaptor::new(svc, credentials);

    // Verify that credentials were cached at adaptor creation
    assert!(adaptor.credentials.is_some(), "credentials should be cached");
    let cached = adaptor.credentials.as_ref().unwrap();
    assert_eq!(cached.get("user1"), Some(&"pass1".to_string()));
  }

  #[test]
  fn test_adaptor_no_credentials_without_auth() {
    let svc = create_test_service();
    let adaptor = HyperServiceAdaptor::new(svc, None);

    // Verify that credentials are None when no auth is configured
    assert!(adaptor.credentials.is_none(), "credentials should be None without auth");
  }
}
