#![allow(clippy::borrowed_box)]
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;

use anyhow::Result;
use tower::service_fn;

use crate::service::Service;

/// Create a placeholder service for routing table initialization.
/// The actual service is selected at request time from the routing
/// table.
pub fn placeholder_service() -> Service {
  Service::new(service_fn(|_req| {
    Box::pin(async {
      Err::<Response, _>(anyhow::anyhow!("placeholder"))
    }) as Pin<Box<dyn Future<Output = Result<Response>>>>
  }))
}

// ============================================================================
// Shared-Address Listener Architecture (Task 020)
// ============================================================================

/// A server's routing info and its associated service.
#[derive(Clone)]
pub struct Server {
  /// Hostnames this server responds to
  pub hostnames: Vec<String>,
  /// The service to route requests to
  pub service: Service,
  /// Service name for logging
  pub service_name: String,
  /// Server-level TLS config (for https/http3)
  pub tls: Option<crate::config::ServerTlsConfig>,
}

impl Server {
  /// Get the service name for logging purposes.
  pub fn service_name(&self) -> String {
    self.service_name.clone()
  }
}

/// A router that encapsulates hostname-based routing logic.
///
/// Wraps a list of `Server` entries and provides efficient routing
/// by hostname, supporting exact matches, wildcard matches, and
/// default fallback.
#[derive(Clone)]
pub struct ServerRouter {
  servers: Vec<Rc<Server>>,
}

impl ServerRouter {
  /// Build a router from a list of servers.
  ///
  /// Each server is wrapped in `Rc` for cheap cloning during routing.
  pub fn build(servers: Vec<Server>) -> Self {
    let servers: Vec<Rc<Server>> =
      servers.into_iter().map(Rc::new).collect();
    Self { servers }
  }

  /// Route a request to the appropriate server based on hostname.
  ///
  /// Priority: exact match > wildcard match > default server (no
  /// hostnames). Returns `None` if no match is found.
  pub fn route(&self, hostname: Option<&str>) -> Option<Rc<Server>> {
    match hostname {
      Some(h) => {
        let mut wildcard_match: Option<Rc<Server>> = None;
        let mut default_server: Option<Rc<Server>> = None;

        for server in &self.servers {
          if server.hostnames.is_empty() {
            if default_server.is_none() {
              default_server = Some(server.clone());
            }
            continue;
          }

          for pattern in &server.hostnames {
            if crate::routing::matches_hostname(pattern, h) {
              if pattern.starts_with("*.") {
                if wildcard_match.is_none() {
                  wildcard_match = Some(server.clone());
                }
              } else {
                return Some(server.clone());
              }
            }
          }
        }
        wildcard_match.or(default_server)
      }
      None => {
        self.servers.iter().find(|s| s.hostnames.is_empty()).cloned()
      }
    }
  }
}

use crate::http_utils::Response;

#[cfg(test)]
mod shared_address_tests {
  use super::*;

  #[test]
  fn test_routing_with_server_router() {
    let entries = vec![
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

    let router = ServerRouter::build(entries);

    // Test exact match
    let result = router.route(Some("api.example.com"));
    assert_eq!(result.unwrap().service_name, "api_service");

    // Test fallback to default
    let result = router.route(Some("other.example.com"));
    assert_eq!(result.unwrap().service_name, "default_service");
  }

  #[test]
  fn test_server_routing_entry_renamed_to_server() {
    let entry = Server {
      hostnames: vec![],
      service: placeholder_service(),
      service_name: "test".to_string(),
      tls: None,
    };
    assert_eq!(entry.service_name, "test");
  }
}

#[cfg(test)]
mod server_router_tests {
  use std::rc::Rc;

  use super::*;

  // CR-006: build() returns Self directly, not Result
  #[test]
  fn test_server_router_build_returns_self() {
    let servers = vec![Server {
      hostnames: vec![],
      service: placeholder_service(),
      service_name: "default".to_string(),
      tls: None,
    }];
    let router = ServerRouter::build(servers);
    let result: Option<Rc<Server>> = router.route(None);
    assert!(result.is_some());
    assert_eq!(result.unwrap().service_name, "default");
  }

  #[test]
  fn test_server_router_exact_match() {
    let servers = vec![
      Server {
        hostnames: vec![],
        service: placeholder_service(),
        service_name: "default".to_string(),
        tls: None,
      },
      Server {
        hostnames: vec!["api.example.com".to_string()],
        service: placeholder_service(),
        service_name: "api".to_string(),
        tls: None,
      },
    ];
    let router = ServerRouter::build(servers);
    let result: Option<Rc<Server>> =
      router.route(Some("api.example.com"));
    assert!(result.is_some());
    assert_eq!(result.unwrap().service_name, "api");
  }

  #[test]
  fn test_server_router_default_fallback() {
    let servers = vec![Server {
      hostnames: vec![],
      service: placeholder_service(),
      service_name: "default".to_string(),
      tls: None,
    }];
    let router = ServerRouter::build(servers);
    let result: Option<Rc<Server>> =
      router.route(Some("unknown.example.com"));
    assert!(result.is_some());
    assert_eq!(result.unwrap().service_name, "default");
  }

  #[test]
  fn test_server_router_no_match() {
    let servers = vec![Server {
      hostnames: vec!["api.example.com".to_string()],
      service: placeholder_service(),
      service_name: "api".to_string(),
      tls: None,
    }];
    let router = ServerRouter::build(servers);
    let result: Option<Rc<Server>> =
      router.route(Some("unknown.example.com"));
    assert!(result.is_none());
  }

  #[test]
  fn test_server_router_wildcard_match() {
    let servers = vec![Server {
      hostnames: vec!["*.example.com".to_string()],
      service: placeholder_service(),
      service_name: "wildcard".to_string(),
      tls: None,
    }];
    let router = ServerRouter::build(servers);
    let result: Option<Rc<Server>> =
      router.route(Some("foo.example.com"));
    assert!(result.is_some());
    assert_eq!(result.unwrap().service_name, "wildcard");
  }

  // CR-001: route(None) with default server
  #[test]
  fn test_server_router_none_hostname_with_default() {
    let servers = vec![
      Server {
        hostnames: vec![],
        service: placeholder_service(),
        service_name: "default".to_string(),
        tls: None,
      },
      Server {
        hostnames: vec!["api.example.com".to_string()],
        service: placeholder_service(),
        service_name: "api".to_string(),
        tls: None,
      },
    ];
    let router = ServerRouter::build(servers);
    let result: Option<Rc<Server>> = router.route(None);
    assert!(result.is_some());
    assert_eq!(result.unwrap().service_name, "default");
  }

  // CR-002: wildcard vs exact match priority
  #[test]
  fn test_server_router_wildcard_vs_exact_priority() {
    let servers = vec![
      Server {
        hostnames: vec!["*.example.com".to_string()],
        service: placeholder_service(),
        service_name: "wildcard".to_string(),
        tls: None,
      },
      Server {
        hostnames: vec!["api.example.com".to_string()],
        service: placeholder_service(),
        service_name: "api".to_string(),
        tls: None,
      },
    ];
    let router = ServerRouter::build(servers);

    // Exact match takes priority over wildcard
    let result: Option<Rc<Server>> =
      router.route(Some("api.example.com"));
    assert!(result.is_some());
    assert_eq!(result.unwrap().service_name, "api");

    // Wildcard match for non-exact hostname
    let result: Option<Rc<Server>> =
      router.route(Some("other.example.com"));
    assert!(result.is_some());
    assert_eq!(result.unwrap().service_name, "wildcard");
  }

  // CR-003: route(None) with no default server
  #[test]
  fn test_server_router_none_hostname_no_default() {
    let servers = vec![Server {
      hostnames: vec!["api.example.com".to_string()],
      service: placeholder_service(),
      service_name: "api".to_string(),
      tls: None,
    }];
    let router = ServerRouter::build(servers);
    let result: Option<Rc<Server>> = router.route(None);
    assert!(result.is_none());
  }
}

#[cfg(test)]
mod placeholder_service_tests {
  use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

  use tower::Service;

  use super::*;

  // Create a no-op waker
  fn no_op_clone(_: *const ()) -> RawWaker {
    no_op_raw_waker()
  }
  fn no_op(_: *const ()) {}
  fn no_op_raw_waker() -> RawWaker {
    static VTABLE: RawWakerVTable =
      RawWakerVTable::new(no_op_clone, no_op, no_op, no_op);
    RawWaker::new(std::ptr::null(), &VTABLE)
  }

  #[test]
  fn test_placeholder_service_poll_ready() {
    let waker = unsafe { Waker::from_raw(no_op_raw_waker()) };
    let mut cx = Context::from_waker(&waker);

    let mut service = placeholder_service();
    match service.poll_ready(&mut cx) {
      Poll::Ready(Ok(())) => {}
      _ => panic!("Expected Poll::Ready(Ok(()))"),
    }
  }

  #[test]
  fn test_placeholder_service_call() {
    use http_body_util::BodyExt;
    use http_body_util::combinators::UnsyncBoxBody;

    let mut service = placeholder_service();
    let body: UnsyncBoxBody<bytes::Bytes, anyhow::Error> =
      http_body_util::Empty::<bytes::Bytes>::new()
        .map_err(|e: std::convert::Infallible| anyhow::anyhow!("{}", e))
        .boxed_unsync();
    let request = http::Request::builder()
      .method("GET")
      .uri("/")
      .body(body)
      .unwrap();

    let future = service.call(request);
    // The future should complete with an error
    let rt = tokio::runtime::Runtime::new().unwrap();
    let result = rt.block_on(future);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("placeholder"));
  }
}
