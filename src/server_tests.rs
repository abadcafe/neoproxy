//! Black-box tests for the server module.

use std::rc::Rc;

use crate::server::{Server, ServerRouter};
use crate::server_fixtures::placeholder_service;

#[test]
fn test_route_ipv6_uses_address_identity_instead_of_spelling() {
  let router = ServerRouter::build(vec![Server {
    hostnames: vec!["2001:db8::1".into()],
    service: placeholder_service(),
    service_name: "ipv6".into(),
    tls: None,
  }]);
  assert_eq!(
    router.route(Some("[2001:0db8:0:0::1]")).unwrap().service_name,
    "ipv6"
  );
}

// ============== Hostname Matching Tests ==============

// Note: matches_hostname is private, tested indirectly through
// ServerRouter.

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

// ============== Server Router Tests ==============

// CR-006: build() returns Self directly, not Result
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

// ============== Hostname Matching via Router Tests ==============

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

#[test]
fn test_route_rejects_empty_wildcard_label_and_accepts_root_dot() {
  let router = ServerRouter::build(vec![Server {
    hostnames: vec!["*.example.com".into()],
    service: placeholder_service(),
    service_name: "wildcard".into(),
    tls: None,
  }]);
  assert!(router.route(Some(".example.com")).is_none());
  assert!(router.route(Some("API.EXAMPLE.COM.")).is_some());
}
#[test]
fn test_requires_client_cert_only_for_nonempty_ca_paths() {
  for (ca_setting, required) in [
    ("", false),
    ("client_ca_certs: []\n", false),
    ("client_ca_certs: [ca.pem]\n", true),
  ] {
    let tls =
      serde_yaml::from_str(&format!("certificates: []\n{ca_setting}"))
        .unwrap();
    let server = crate::server::Server {
      hostnames: vec![],
      service: crate::server_fixtures::placeholder_service(),
      service_name: "client-ca".into(),
      tls: Some(tls),
    };
    assert_eq!(server.requires_client_cert(), required);
  }
}
