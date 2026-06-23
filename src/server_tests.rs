//! Black-box tests for the server module.

use std::rc::Rc;
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use tower::Service;

use crate::server::{Server, ServerRouter, placeholder_service};

// ============== Hostname Matching Tests ==============

// Note: matches_hostname is private, tested indirectly through ServerRouter.

// ============== Shared Address Tests ==============

#[test]
fn test_routing_with_server_router() {
  let entries = vec![
    Server {
      hostnames: vec![],
      service: placeholder_service(),
      service_name: "default_service".to_string(),
      tls: None,
    },
    Server {
      hostnames: vec!["api.example.com".to_string()],
      service: placeholder_service(),
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

// ============== Server Router Tests ==============

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

// ============== Placeholder Service Tests ==============

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
  let request =
    http::Request::builder().method("GET").uri("/").body(body).unwrap();

  let future = service.call(request);
  // The future should complete with an error
  let rt = tokio::runtime::Runtime::new().unwrap();
  let result = rt.block_on(future);
  assert!(result.is_err());
  assert!(result.unwrap_err().to_string().contains("placeholder"));
}

// ============== Hostname Matching via Router Tests ==============

#[test]
fn test_matches_hostname_exact_via_router() {
  let servers = vec![Server {
    hostnames: vec!["api.example.com".to_string()],
    service: placeholder_service(),
    service_name: "api".to_string(),
    tls: None,
  }];
  let router = ServerRouter::build(servers);
  assert!(router.route(Some("api.example.com")).is_some());
  assert!(router.route(Some("other.example.com")).is_none());
}

#[test]
fn test_matches_hostname_wildcard_via_router() {
  let servers = vec![Server {
    hostnames: vec!["*.example.com".to_string()],
    service: placeholder_service(),
    service_name: "wildcard".to_string(),
    tls: None,
  }];
  let router = ServerRouter::build(servers);
  assert!(router.route(Some("foo.example.com")).is_some());
  assert!(router.route(Some("bar.example.com")).is_some());
  // Wildcard should NOT match the base domain
  assert!(router.route(Some("example.com")).is_none());
  // Wildcard should NOT match multiple levels
  assert!(router.route(Some("foo.bar.example.com")).is_none());
}

#[test]
fn test_matches_hostname_case_insensitive_via_router() {
  let servers = vec![Server {
    hostnames: vec!["api.example.com".to_string()],
    service: placeholder_service(),
    service_name: "api".to_string(),
    tls: None,
  }];
  let router = ServerRouter::build(servers);
  // DNS is case-insensitive
  assert!(router.route(Some("API.EXAMPLE.COM")).is_some());
}
