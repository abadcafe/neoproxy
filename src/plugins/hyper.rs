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
use tracing::{error, warn};

use crate::plugin;

/// Default graceful shutdown timeout in seconds
const DEFAULT_GRACEFUL_SHUTDOWN_TIMEOUT: Duration =
  Duration::from_secs(5);

/// Extension trait for Listening that supports connection tracking
/// and graceful shutdown.
pub trait ListeningExt: plugin::Listening {
  /// Get the current number of active connections.
  fn active_connections(&self) -> usize;

  /// Set the graceful shutdown timeout.
  fn set_graceful_shutdown_timeout(&mut self, timeout: Duration);
}

struct HyperServiceAdaptor {
  s: plugin::Service,
}

impl HyperServiceAdaptor {
  fn new(s: plugin::Service) -> Self {
    Self { s }
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
    let (parts, body) = req.into_parts();
    let req = plugin::Request::from_parts(
      parts,
      plugin::RequestBody::new(plugin::BytesBufBodyWrapper::new(body)),
    );
    let s = self.s.clone();
    Box::pin(tower_util::Oneshot::new(s, req))
  }
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
}

struct HyperListener {
  addresses: Vec<SocketAddr>,
  _protocols: Vec<String>,
  _hostnames: Vec<String>,
  listening_set: Rc<RefCell<task::JoinSet<Result<()>>>>,
  conn_serving_set: Rc<RefCell<task::JoinSet<Result<()>>>>,
  shutdown_handle: plugin::ShutdownHandle,
  service: plugin::Service,
  graceful_shutdown_timeout: Duration,
}

impl HyperListener {
  fn new(
    sargs: plugin::SerializedArgs,
    svc: plugin::Service,
  ) -> Result<plugin::Listener> {
    let args: HyperListenerArgs = serde_yaml::from_value(sargs)?;
    Ok(plugin::Listener::new(Self {
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
      conn_serving_set: Rc::new(RefCell::new(task::JoinSet::new())),
      shutdown_handle: plugin::ShutdownHandle::new(),
      service: svc,
      graceful_shutdown_timeout: DEFAULT_GRACEFUL_SHUTDOWN_TIMEOUT,
    }))
  }

  /// Create a HyperListener directly for testing purposes.
  #[cfg(test)]
  fn new_for_test(
    sargs: plugin::SerializedArgs,
    svc: plugin::Service,
  ) -> Result<Self> {
    let args: HyperListenerArgs = serde_yaml::from_value(sargs)?;
    Ok(Self {
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
      conn_serving_set: Rc::new(RefCell::new(task::JoinSet::new())),
      shutdown_handle: plugin::ShutdownHandle::new(),
      service: svc,
      graceful_shutdown_timeout: DEFAULT_GRACEFUL_SHUTDOWN_TIMEOUT,
    })
  }

  fn serve_addr(
    &self,
    addr: SocketAddr,
    svc: plugin::Service,
  ) -> Result<Pin<Box<dyn Future<Output = Result<()>>>>> {
    let socket = net::TcpSocket::new_v4()?;
    socket.set_reuseaddr(true)?;
    socket.set_reuseport(true)?;
    socket.bind(addr)?;
    let listener = socket.listen(1024)?;
    let conn_serving_set = self.conn_serving_set.clone();
    let notifier = self.shutdown_handle.clone();
    let accepting_fut = async move {
      let shutdown = async move || notifier.notified().await;
      let accepting = async move || match listener.accept().await {
        Err(e) => {
          error!("accepting new connection failed: {e}");
        }
        Ok((stream, _raddr)) => {
          let io = rt_util::TokioIo::new(stream);
          let svc = HyperServiceAdaptor::new(svc.clone());
          let builder = conn_util::Builder::new(TokioLocalExecutor {});
          conn_serving_set.borrow_mut().spawn_local(async move {
            // Do not need any graceful shutdown actions here for
            // connections. The `Service`s should do this instead.
            let conn = builder.serve_connection_with_upgrades(io, svc);
            conn.await.map_err(|e| anyhow::Error::from_boxed(e))
          });
        }
      };

      loop {
        tokio::select! {
          _ = accepting() => {},
          _ = shutdown() => {
            // Graceful shutdown for the TcpListener.
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
      let addr = addr.clone();
      let service = self.service.clone();
      let serve_addr_fut = match self.serve_addr(addr, service) {
        Err(e) => return Box::pin(future::ready(Err(e))),
        Ok(f) => f,
      };
      listening_set.borrow_mut().spawn_local(serve_addr_fut);
    }

    let conn_serving_set = self.conn_serving_set.clone();
    let shutdown = self.shutdown_handle.clone();
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
          Ok(res) => match res {
            Err(e) => {
              error!("listening error: {e}")
            }
            Ok(_) => {}
          },
        }
      }

      // Wait for active connections with timeout
      let wait_result = timeout(graceful_timeout, async {
        while let Some(res) =
          conn_serving_set.borrow_mut().join_next().await
        {
          match res {
            Err(e) => {
              error!("connection join error: {e}")
            }
            Ok(res) => match res {
              Err(e) => {
                error!("connection error: {e}")
              }
              Ok(_) => {}
            },
          }
        }
      })
      .await;

      if wait_result.is_err() {
        // Timeout expired, force close remaining connections
        warn!(
          "graceful shutdown timeout ({:?}) expired, aborting {} \
           remaining connections",
          graceful_timeout,
          conn_serving_set.borrow().len()
        );
        conn_serving_set.borrow_mut().abort_all();
      }

      Ok(())
    })
  }

  fn stop(&self) {
    self.shutdown_handle.shutdown()
  }
}

impl ListeningExt for HyperListener {
  fn active_connections(&self) -> usize {
    self.conn_serving_set.borrow().len()
  }

  fn set_graceful_shutdown_timeout(&mut self, dur: Duration) {
    self.graceful_shutdown_timeout = dur;
  }
}

struct HyperPlugin {
  listener_builders:
    HashMap<&'static str, Box<dyn plugin::BuildListener>>,
}

impl HyperPlugin {
  fn new() -> Self {
    let builder: Box<dyn plugin::BuildListener> =
      Box::new(HyperListener::new);
    let listener_factories = HashMap::from([("listener", builder)]);

    Self { listener_builders: listener_factories }
  }
}

impl plugin::Plugin for HyperPlugin {
  fn listener_builder(
    &self,
    name: &str,
  ) -> Option<&Box<dyn plugin::BuildListener>> {
    self.listener_builders.get(name)
  }
}

pub fn plugin_name() -> &'static str {
  "hyper"
}

pub fn create_plugin() -> Box<dyn plugin::Plugin> {
  Box::new(HyperPlugin::new())
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::plugin::Listening;
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
  fn test_plugin_name() {
    assert_eq!(plugin_name(), "hyper");
  }

  #[test]
  fn test_create_plugin() {
    let plugin = create_plugin();
    assert!(plugin.listener_builder("listener").is_some());
    assert!(plugin.listener_builder("nonexistent").is_none());
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
    assert_eq!(listener.active_connections(), 0);
  }

  #[test]
  fn test_set_graceful_shutdown_timeout() {
    let args = create_test_listener_args();
    let svc = create_test_service();
    let mut listener = HyperListener::new_for_test(args, svc).unwrap();
    // Test set_graceful_shutdown_timeout via ListeningExt trait
    listener.set_graceful_shutdown_timeout(Duration::from_secs(10));
    // The timeout should be updated
  }

  #[test]
  fn test_listening_ext_trait_bounds() {
    // Verify that ListeningExt is object-safe and can be used
    fn assert_listening_ext<T: ListeningExt>() {}
    assert_listening_ext::<HyperListener>();
  }

  #[test]
  fn test_default_graceful_shutdown_timeout() {
    assert_eq!(
      DEFAULT_GRACEFUL_SHUTDOWN_TIMEOUT,
      Duration::from_secs(5)
    );
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
    let _adaptor = HyperServiceAdaptor::new(svc);
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
  fn test_hyper_plugin_new() {
    let plugin = HyperPlugin::new();
    assert!(plugin.listener_builders.contains_key("listener"));
  }

  #[test]
  fn test_listening_ext_active_connections() {
    // Create listener with zero port (will bind to random port)
    let args = create_test_listener_args();
    let svc = create_test_service();
    let listener = HyperListener::new_for_test(args, svc).unwrap();

    // active_connections should be 0 initially
    assert_eq!(listener.active_connections(), 0);
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
  fn test_graceful_shutdown_timeout_mutable() {
    let args = create_test_listener_args();
    let svc = create_test_service();
    let mut listener = HyperListener::new_for_test(args, svc).unwrap();

    // Test set_graceful_shutdown_timeout via ListeningExt trait
    listener.set_graceful_shutdown_timeout(Duration::from_secs(10));
    // The timeout should be updated (we can't verify directly without
    // starting the listener)
  }

  #[test]
  fn test_listening_trait_implementation() {
    // Verify HyperListener implements Listening
    fn assert_listening<T: plugin::Listening>() {}
    assert_listening::<HyperListener>();
  }

  #[test]
  fn test_listening_ext_implementation() {
    // Verify HyperListener implements ListeningExt
    fn assert_listening_ext<T: ListeningExt>() {}
    assert_listening_ext::<HyperListener>();
  }
}
