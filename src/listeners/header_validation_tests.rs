//! Black-box tests for header_validation module.

use crate::listeners::header_validation::{
  authority_host_mismatch, validate_and_route,
};
use crate::server::{Server, ServerRouter};

fn default_server() -> Server {
  Server {
    hostnames: vec![],
    service: crate::server::placeholder_service(),
    service_name: "default".to_string(),
    tls: None,
  }
}

fn api_server() -> Server {
  Server {
    hostnames: vec!["api.example.com".to_string()],
    service: crate::server::placeholder_service(),
    service_name: "api".to_string(),
    tls: None,
  }
}

fn build_router() -> ServerRouter {
  ServerRouter::build(vec![default_server(), api_server()])
}

// ========== authority_host_mismatch ==========

#[test]
fn test_authority_host_mismatch_matching() {
  assert!(!authority_host_mismatch(
    "api.example.com",
    "api.example.com"
  ));
}

#[test]
fn test_authority_host_mismatch_case_insensitive() {
  assert!(!authority_host_mismatch(
    "API.EXAMPLE.COM",
    "api.example.com"
  ));
}

#[test]
fn test_authority_host_mismatch_mismatching() {
  assert!(authority_host_mismatch(
    "api.example.com",
    "other.example.com"
  ));
}

#[test]
fn test_authority_host_mismatch_empty_authority() {
  assert!(!authority_host_mismatch("", "api.example.com"));
}

#[test]
fn test_authority_host_mismatch_empty_host() {
  assert!(!authority_host_mismatch("api.example.com", ""));
}

// ========== validate_and_route ==========

#[test]
fn test_validate_and_route_with_host_routes_to_matching() {
  let router = build_router();
  let req = http::Request::builder()
    .method("GET")
    .uri("/test")
    .header(http::header::HOST, "api.example.com")
    .body(())
    .unwrap();

  let result = validate_and_route(&req, &router);
  assert!(result.is_ok());
  assert_eq!(result.unwrap().service_name, "api");
}

#[test]
fn test_validate_and_route_unknown_host_routes_to_default() {
  let router = build_router();
  let req = http::Request::builder()
    .method("GET")
    .uri("/test")
    .header(http::header::HOST, "unknown.example.com")
    .body(())
    .unwrap();

  let result = validate_and_route(&req, &router);
  assert!(result.is_ok());
  assert_eq!(result.unwrap().service_name, "default");
}

#[test]
fn test_validate_and_route_without_host_returns_bad_request() {
  let router = build_router();
  let req = http::Request::builder()
    .method("GET")
    .uri("/test")
    .body(())
    .unwrap();

  let result = validate_and_route(&req, &router);
  assert!(result.is_err());
}

#[test]
fn test_authority_host_mismatch_both_empty() {
  assert!(!authority_host_mismatch("", ""));
}

#[test]
fn test_validate_and_route_authority_matches_host() {
  let router = build_router();
  let req = http::Request::builder()
    .method("GET")
    .uri("http://api.example.com/test")
    .header(http::header::HOST, "api.example.com")
    .body(())
    .unwrap();

  let result = validate_and_route(&req, &router);
  assert!(result.is_ok());
  assert_eq!(result.unwrap().service_name, "api");
}

#[test]
fn test_validate_and_route_authority_mismatches_host() {
  let router = build_router();
  let req = http::Request::builder()
    .method("GET")
    .uri("http://other.example.com/test")
    .header(http::header::HOST, "api.example.com")
    .body(())
    .unwrap();

  let result = validate_and_route(&req, &router);
  assert!(result.is_err());
}

#[test]
fn test_validate_and_route_no_route_no_default_returns_404() {
  // Router with only hostname-specific server, no default
  let router = ServerRouter::build(vec![Server {
    hostnames: vec!["specific.example.com".to_string()],
    service: crate::server::placeholder_service(),
    service_name: "specific".to_string(),
    tls: None,
  }]);

  let req = http::Request::builder()
    .method("GET")
    .uri("/test")
    .header(http::header::HOST, "unknown.example.com")
    .body(())
    .unwrap();

  let result = validate_and_route(&req, &router);
  assert!(result.is_err());
}

#[test]
fn test_validate_and_route_host_with_port_strips_port() {
  let router = build_router();
  let req = http::Request::builder()
    .method("GET")
    .uri("/test")
    .header(http::header::HOST, "api.example.com:8080")
    .body(())
    .unwrap();

  let result = validate_and_route(&req, &router);
  assert!(result.is_ok());
  assert_eq!(result.unwrap().service_name, "api");
}
