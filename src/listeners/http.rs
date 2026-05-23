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
use tokio::time::timeout;
use tokio::{net, task};
use tower::util as tower_util;
use tracing::{error, info, warn};

use crate::config::SerializedArgs;
use crate::http_utils::{BytesBufBodyWrapper, Request, RequestBody, Response};
use crate::listener::{
  BuildListener, Listener, ListenerProps, Listening, TransportLayer,
};
use crate::listeners::utils::{
  LISTENER_SHUTDOWN_TIMEOUT, TokioLocalExecutor, build_request_context,
  validate_and_route,
};
use crate::server::{Server, ServerRouter};
#[cfg(test)]
use crate::service::Service;
use crate::tracker::StreamTracker;


/// HTTP Listener with shared-address routing support.
///
/// This listener supports routing requests to different services based
/// on the Host header. Multiple servers can share the same address with
/// hostname-based routing.
struct HyperServiceAdaptor {
  /// Server router for hostname-based routing
  server_router: ServerRouter,
  /// Client (peer) address from accept
  client_addr: Option<SocketAddr>,
  /// Local (server) address from accept
  local_addr: Option<SocketAddr>,
}

impl HyperServiceAdaptor {
  fn new(
    server_routing_table: Vec<Server>,
    client_addr: Option<SocketAddr>,
    local_addr: Option<SocketAddr>,
  ) -> Self {
    let server_router = ServerRouter::build(server_routing_table);
    Self { server_router, client_addr, local_addr }
  }

}

impl hyper_svc::Service<hyper::Request<hyper_body::Incoming>>
  for HyperServiceAdaptor
{
  type Error = anyhow::Error;
  type Future = Pin<Box<dyn Future<Output = Result<Response>>>>;
  type Response = Response;

  fn call(
    &self,
    req: http::Request<hyper_body::Incoming>,
  ) -> Self::Future {
    let (parts, body) = req.into_parts();
    let mut req = Request::from_parts(
      parts,
      RequestBody::new(BytesBufBodyWrapper::new(body)),
    );

    let routing_entry = match validate_and_route(&req, &self.server_router)
    {
      Ok(entry) => entry,
      Err(resp) => return Box::pin(async { Ok(resp) }),
    };

    // Step 5: Build RequestContext with connection-level keys and
    // insert into request extensions. Auth and access logging are
    // now handled by the plugin layer in the service pipeline.
    if let (Some(peer_addr), Some(local_addr)) =
      (self.client_addr, self.local_addr)
    {
      let ctx = build_request_context(
        &peer_addr,
        &local_addr,
        &routing_entry.service_name(),
      );

      req.extensions_mut().insert(ctx);
    }

    // Step 6: Call service (auth/access_log handled by layers)
    let s = routing_entry.service.clone();
    Box::pin(async move { tower_util::Oneshot::new(s, req).await })
  }
}

/// HTTP Listener configuration arguments.
#[derive(Deserialize, Default, Clone, Debug)]
struct HttpListenerArgs {}

/// HTTP Listener implementation with shared-address routing support.
struct HttpListener {
  /// Listening addresses
  addresses: Vec<SocketAddr>,
  /// Server routing table for hostname-based routing
  server_routing_table: Vec<Server>,
  /// Stream tracker for graceful shutdown
  listening_set: Rc<RefCell<task::JoinSet<Result<()>>>>,
  /// Stream tracker for graceful shutdown
  stream_tracker: Rc<StreamTracker>,
  /// Graceful shutdown timeout
  graceful_shutdown_timeout: Duration,
}

impl HttpListener {
  /// Create an HttpListener from parsed configuration.
  fn from_args(
    addresses: Vec<String>,
    server_routing_table: Vec<Server>,
  ) -> Result<Self> {
    // Parse addresses, filtering out invalid ones
    let addresses: Vec<SocketAddr> = addresses
      .iter()
      .filter_map(|s| {
        s.parse()
          .inspect_err(|e| warn!("address '{s}' invalid: {e}"))
          .ok()
      })
      .collect();

    Ok(Self {
      addresses,
      server_routing_table,
      listening_set: Rc::new(RefCell::new(task::JoinSet::new())),
      stream_tracker: Rc::new(StreamTracker::new()),
      graceful_shutdown_timeout: LISTENER_SHUTDOWN_TIMEOUT,
    })
  }

  #[allow(clippy::new_ret_no_self)]
  fn new(
    addresses: Vec<String>,
    sargs: SerializedArgs,
    server_routing_table: Vec<Server>,
  ) -> Result<Listener> {
    let _args: HttpListenerArgs = serde_yaml::from_value(sargs)?;
    Ok(Listener::new(Self::from_args(addresses, server_routing_table)?))
  }

  /// Create an HttpListener directly for testing purposes.
  #[cfg(test)]
  fn new_for_test(
    addresses: Vec<String>,
    svc: Service,
  ) -> Result<Self> {
    let entry = Server {
      hostnames: vec![],
      service: svc,
      service_name: "test_service".to_string(),
      tls: None,
    };
    Self::from_args(addresses, vec![entry])
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
    let stream_tracker = self.stream_tracker.clone();
    let shutdown_handle = self.stream_tracker.shutdown_handle();
    let server_routing_table = self.server_routing_table.clone();
    let accepting_fut = async move {
      // Log listener startup event
      info!("HTTP listener started on {}", addr);

      let shutdown = async move || shutdown_handle.notified().await;
      let accepting = || async {
        match listener.accept().await {
          Err(e) => {
            error!("accepting new connection failed: {e}");
          }
          Ok((stream, raddr)) => {
            let local_addr = stream.local_addr().ok();
            let io = rt_util::TokioIo::new(stream);
            let svc = HyperServiceAdaptor::new(
              server_routing_table.clone(),
              Some(raddr),
              local_addr,
            );
            let builder = conn_util::Builder::new(TokioLocalExecutor);
            stream_tracker.register(async move {
              // Do not need any graceful shutdown actions here for
              // connections. The `Service`s should do this instead.
              let conn =
                builder.serve_connection_with_upgrades(io, svc);
              if let Err(e) = conn.await {
                warn!("connection from {raddr} on {local_addr:?}: {e}");
              }
            });
          }
        }
      };

      loop {
        tokio::select! {
          _ = accepting() => {},
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

impl Listening for HttpListener {
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

    let stream_tracker = self.stream_tracker.clone();
    let shutdown = self.stream_tracker.shutdown_handle();
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
        stream_tracker.wait_shutdown().await;
      })
      .await;

      if wait_result.is_err() {
        // Timeout expired, force close remaining connections
        warn!(
          "graceful shutdown timeout ({:?}) expired, aborting {} \
           remaining connections",
          graceful_timeout,
          stream_tracker.active_count()
        );
        stream_tracker.abort_all();
      }

      Ok(())
    })
  }

  fn stop(&self) {
    self.stream_tracker.shutdown()
  }
}

pub fn listener_name() -> &'static str {
  "http"
}

/// Get listener properties for conflict detection.
pub fn props() -> ListenerProps {
  ListenerProps {
    transport_layer: TransportLayer::Tcp,
    supports_hostname_routing: true,
  }
}

pub fn create_listener_builder() -> Box<dyn BuildListener> {
  Box::new(HttpListener::new)
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::shutdown::ShutdownHandle;

  // ============== HttpListenerArgs Tests ==============

  #[test]
  fn test_http_listener_args_no_auth_field() {
    // Auth should no longer be at listener level
    // HttpListenerArgs now has no fields - addresses are passed
    // separately
    let yaml = r#"{}"#;
    let args: HttpListenerArgs = serde_yaml::from_str(yaml).unwrap();
    // Args should parse successfully without addresses field
    drop(args);
  }

  fn create_test_addresses() -> Vec<String> {
    vec!["127.0.0.1:0".to_string()]
  }

  fn create_test_addresses_with_invalid() -> Vec<String> {
    vec!["invalid".to_string(), "127.0.0.1:0".to_string()]
  }

  fn create_test_args() -> SerializedArgs {
    serde_yaml::from_str(r#"{}"#).unwrap()
  }

  fn create_test_routing_entry() -> Server {
    Server {
      hostnames: vec![],
      service: crate::server::placeholder_service(),
      service_name: "test_service".to_string(),
      tls: None,
    }
  }

  #[test]
  fn test_listener_name() {
    assert_eq!(listener_name(), "http");
  }

  #[test]
  fn test_create_listener_builder() {
    let builder = create_listener_builder();
    let args = create_test_args();
    let result = builder(
      create_test_addresses(),
      args,
      vec![create_test_routing_entry()],
    );
    assert!(result.is_ok());
  }

  #[test]
  fn test_http_listener_new_valid() {
    let args = create_test_args();
    let result = HttpListener::new(
      create_test_addresses(),
      args,
      vec![create_test_routing_entry()],
    );
    assert!(result.is_ok());
  }

  #[test]
  fn test_http_listener_new_invalid_address() {
    let args = create_test_args();
    let result = HttpListener::new(
      create_test_addresses_with_invalid(),
      args,
      vec![create_test_routing_entry()],
    );
    // Invalid addresses are filtered out, so it should still succeed
    assert!(result.is_ok());
  }

  #[test]
  fn test_active_connections_initial() {
    let svc = crate::server::placeholder_service();
    let listener =
      HttpListener::new_for_test(create_test_addresses(), svc).unwrap();
    // active_connections should be 0 initially
    assert_eq!(listener.stream_tracker.active_count(), 0);
  }

  #[test]
  fn test_listener_stop_and_start() {
    // This test verifies the listener can be created and stopped
    let svc = crate::server::placeholder_service();
    let listener =
      HttpListener::new_for_test(create_test_addresses(), svc).unwrap();

    // Stop should work even without start
    listener.stop();
  }

  #[test]
  fn test_shutdown_handle_clone() {
    let handle1 = ShutdownHandle::new();
    let handle2 = handle1.clone();
    // Both handles should refer to the same notify
    handle1.shutdown();
    // After shutdown, notified should return immediately
    // (but we don't test async behavior here)
    drop(handle2);
  }

  #[test]
  fn test_build_404_response() {
    let resp = crate::listeners::utils::build_404_response();
    assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
  }

  // ============== Task 009: ServerRouter Routing Test ==============

  #[test]
  fn test_http_listener_routes_by_hostname() {
    // Create servers with hostname routing
    let servers = vec![
      Server {
        hostnames: vec![],
        service: crate::server::placeholder_service(),
        service_name: "default".to_string(),
        tls: None,
      },
      Server {
        hostnames: vec!["api.example.com".to_string()],
        service: crate::server::placeholder_service(),
        service_name: "api".to_string(),
        tls: None,
      },
    ];
    let args: serde_yaml::Value =
      serde_yaml::from_str(r#"{}"#).unwrap();
    // The builder should accept Vec<Server> and set up routing
    let addresses = vec!["127.0.0.1:0".to_string()];
    let result =
      super::create_listener_builder()(addresses, args, servers);
    assert!(
      result.is_ok(),
      "Listener builder should accept Vec<Server>"
    );
  }

  #[test]
  fn test_http_listener_routes_by_hostname_routing_behavior() {
    // Verify that validate_and_route correctly routes requests based
    // on the Host header via ServerRouter.
    let servers = vec![
      Server {
        hostnames: vec![],
        service: crate::server::placeholder_service(),
        service_name: "default".to_string(),
        tls: None,
      },
      Server {
        hostnames: vec!["api.example.com".to_string()],
        service: crate::server::placeholder_service(),
        service_name: "api".to_string(),
        tls: None,
      },
    ];

    let router = ServerRouter::build(servers);

    // Request with Host header matching api.example.com
    let req_api = http::Request::builder()
      .method("GET")
      .uri("/test")
      .header(http::header::HOST, "api.example.com")
      .body(())
      .unwrap();

    let result = validate_and_route(&req_api, &router);
    assert!(result.is_ok());
    assert_eq!(
      result.unwrap().service_name,
      "api",
      "Request with Host: api.example.com should route to api server"
    );

    // Request with Host header not matching any specific server
    let req_other = http::Request::builder()
      .method("GET")
      .uri("/test")
      .header(http::header::HOST, "other.example.com")
      .body(())
      .unwrap();

    let result = validate_and_route(&req_other, &router);
    assert!(result.is_ok());
    assert_eq!(
      result.unwrap().service_name,
      "default",
      "Request with non-matching Host should route to default server"
    );

    // Request without Host header returns 400
    let req_no_host = http::Request::builder()
      .method("GET")
      .uri("/test")
      .body(())
      .unwrap();

    let result = validate_and_route(&req_no_host, &router);
    match result {
      Err(resp) => assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST),
      Ok(_) => panic!("expected error for missing Host header"),
    }
  }

  // ============== RequestContext Tests ==============

  #[test]
  fn test_build_request_context_has_required_keys() {
    let peer_addr: SocketAddr = "192.168.1.100:54321".parse().unwrap();
    let local_addr: SocketAddr = "10.0.0.1:8080".parse().unwrap();
    let service_name = "web_service";

    let ctx = build_request_context(
      &peer_addr,
      &local_addr,
      service_name,
    );

    assert_eq!(ctx.get("client.ip"), Some("192.168.1.100".to_string()));
    assert_eq!(ctx.get("client.port"), Some("54321".to_string()));
    assert_eq!(ctx.get("server.ip"), Some("10.0.0.1".to_string()));
    assert_eq!(ctx.get("server.port"), Some("8080".to_string()));
    assert_eq!(
      ctx.get("service.name"),
      Some("web_service".to_string())
    );
  }

  #[test]
  fn test_build_request_context_inserts_into_extensions() {
    let peer_addr: SocketAddr = "192.168.1.100:54321".parse().unwrap();
    let local_addr: SocketAddr = "10.0.0.1:8080".parse().unwrap();
    let service_name = "test_svc";

    let ctx = build_request_context(
      &peer_addr,
      &local_addr,
      service_name,
    );

    let mut req = http::Request::builder()
      .method("GET")
      .uri("http://example.com")
      .body(())
      .unwrap();
    req.extensions_mut().insert(ctx.clone());

    let retrieved =
      req.extensions().get::<crate::context::RequestContext>();
    assert!(
      retrieved.is_some(),
      "RequestContext should be in extensions"
    );
    assert_eq!(
      retrieved.unwrap().get("client.ip"),
      Some("192.168.1.100".to_string())
    );
    assert_eq!(
      retrieved.unwrap().get("service.name"),
      Some("test_svc".to_string())
    );
  }

  // ============== Routing Tests ==============

  #[test]
  fn test_route_request_no_host_header() {
    let server_routing_table = vec![
      Server {
        hostnames: vec![],
        service: crate::server::placeholder_service(),
        service_name: "default_service".to_string(),
        tls: None,
      },
      Server {
        hostnames: vec!["api.example.com".to_string()],
        service: crate::server::placeholder_service(),
        service_name: "api_service".to_string(),
        tls: None,
      },
    ];

    let router = ServerRouter::build(server_routing_table);

    // Request without Host header returns 400
    let req = http::Request::builder()
      .method("GET")
      .uri("/test")
      .body(())
      .unwrap();

    let result = validate_and_route(&req, &router);
    match result {
      Err(resp) => assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST),
      Ok(_) => panic!("expected error for missing Host header"),
    }
  }

  #[test]
  fn test_route_request_with_host_header() {
    let server_routing_table = vec![
      Server {
        hostnames: vec![],
        service: crate::server::placeholder_service(),
        service_name: "default_service".to_string(),
        tls: None,
      },
      Server {
        hostnames: vec!["api.example.com".to_string()],
        service: crate::server::placeholder_service(),
        service_name: "api_service".to_string(),
        tls: None,
      },
    ];

    let router = ServerRouter::build(server_routing_table);

    // Request with Host header should route to matching server
    let req = http::Request::builder()
      .method("GET")
      .uri("/test")
      .header(http::header::HOST, "api.example.com")
      .body(())
      .unwrap();

    let result = validate_and_route(&req, &router);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().service_name, "api_service");
  }
}
