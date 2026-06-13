//! Common utilities shared across HTTP listeners.
//!
//! This module provides shared functionality for HTTP/HTTPS listeners
//! to avoid code duplication.

use std::future::Future;
use std::rc::Rc;
use std::time::Duration;

use crate::http_utils::{
  BytesBufBodyWrapper, Response, ResponseBody, build_error_response,
};
use crate::server::{Server, ServerRouter};

/// Listener shutdown timeout in seconds.
/// This is the timeout for Phase 1 of graceful shutdown.
pub const LISTENER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);

/// Executor for spawning tasks on the current tokio LocalSet.
#[derive(Clone)]
pub struct TokioLocalExecutor;

impl<F> hyper::rt::Executor<F> for TokioLocalExecutor
where
  F: Future + 'static,
{
  fn execute(&self, fut: F) {
    tokio::task::spawn_local(fut);
  }
}

/// Check if authority and Host header values differ.
///
/// Per RFC 9114 §4.3.1, if both `:authority` and Host are present,
/// they MUST contain the same value. Comparison is case-insensitive.
///
/// # Arguments
/// * `authority_str` - The full authority string (e.g.,
///   "example.com:443")
/// * `host_header` - The raw Host header value
///
/// # Returns
/// `true` if authority and Host differ (mismatch), `false` otherwise
pub fn check_authority_vs_host(
  authority_str: &str,
  host_header: &str,
) -> bool {
  if authority_str.is_empty() || host_header.is_empty() {
    return false;
  }
  authority_str.to_lowercase() != host_header.to_lowercase()
}

/// Validate request headers and route to the correct server.
///
/// Checks that a Host header is present, that it is consistent with
/// `:authority` (if present), and routes the request to a server via
/// the `ServerRouter`.
///
/// Returns `Ok(routing_entry)` on success, or `Err(error_response)`
/// if validation or routing fails.
pub fn validate_and_route<B>(
  req: &http::Request<B>,
  router: &ServerRouter,
) -> Result<Rc<Server>, Response> {
  // Host header is required
  let host_header = match req
    .headers()
    .get(http::header::HOST)
    .and_then(|h| h.to_str().ok())
    .map(|s| s.to_string())
  {
    Some(h) => h,
    None => {
      return Err(build_error_response(
        http::StatusCode::BAD_REQUEST,
        "Bad Request: Host header is required",
      ));
    }
  };

  // If :authority exists, it must equal Host header
  if let Some(authority) = req.uri().authority()
    && check_authority_vs_host(authority.as_ref(), &host_header)
  {
    return Err(build_error_response(
      http::StatusCode::BAD_REQUEST,
      "Bad Request: :authority and Host headers differ",
    ));
  }

  // Route via Host header
  let host = host_header.split(':').next().unwrap_or(&host_header);
  match router.route(Some(host)) {
    Some(entry) => Ok(entry),
    None => Err(build_404_response()),
  }
}

/// Build a 403 Forbidden response.
///
/// This response is sent when a server requires client certificate
/// authentication but the client did not present one.
pub fn build_403_forbidden(msg: &str) -> Response {
  let body =
    http_body_util::Full::new(bytes::Bytes::from(msg.to_string()));
  let bytes_buf = BytesBufBodyWrapper::new(body);
  let body = ResponseBody::new(bytes_buf);
  let mut resp = Response::new(body);
  *resp.status_mut() = http::StatusCode::FORBIDDEN;
  resp.headers_mut().insert(
    http::header::CONTENT_TYPE,
    http::HeaderValue::from_static("text/plain"),
  );
  resp
}

/// Build a 404 Not Found response.
pub fn build_404_response() -> Response {
  let empty = http_body_util::Empty::new();
  let bytes_buf = BytesBufBodyWrapper::new(empty);
  let body = ResponseBody::new(bytes_buf);
  let mut resp = Response::new(body);
  *resp.status_mut() = http::StatusCode::NOT_FOUND;
  resp
}

#[cfg(test)]
mod tests {
  use super::*;

  // ============== Authority vs Host Check Tests ==============

  #[test]
  fn test_check_authority_vs_host_match() {
    assert!(!check_authority_vs_host(
      "api.example.com",
      "api.example.com"
    ));
  }

  #[test]
  fn test_check_authority_vs_host_mismatch() {
    assert!(check_authority_vs_host(
      "api.example.com",
      "other.example.com"
    ));
  }

  #[test]
  fn test_check_authority_vs_host_case_insensitive() {
    assert!(!check_authority_vs_host(
      "API.EXAMPLE.COM",
      "api.example.com"
    ));
  }

  #[test]
  fn test_check_authority_vs_host_with_port() {
    // authority includes port, Host does not — they differ
    assert!(check_authority_vs_host(
      "api.example.com:443",
      "api.example.com"
    ));
  }

  #[test]
  fn test_check_authority_vs_host_both_with_port() {
    assert!(!check_authority_vs_host(
      "api.example.com:443",
      "api.example.com:443"
    ));
  }

  #[test]
  fn test_check_authority_vs_host_empty_authority() {
    assert!(!check_authority_vs_host("", "api.example.com"));
  }

  #[test]
  fn test_check_authority_vs_host_empty_host() {
    assert!(!check_authority_vs_host("api.example.com", ""));
  }

  // ============== validate_and_route Tests ==============

  #[test]
  fn test_validate_and_route_no_host_returns_400() {
    let router = ServerRouter::build(vec![]);
    let req = http::Request::builder()
      .method(http::Method::GET)
      .uri("/")
      .body(())
      .unwrap();
    let result = validate_and_route(&req, &router);
    match result {
      Err(resp) => {
        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST)
      }
      Ok(_) => panic!("expected error"),
    }
  }

  #[test]
  fn test_validate_and_route_authority_host_mismatch_returns_400() {
    let router = ServerRouter::build(vec![]);
    let req = http::Request::builder()
      .method(http::Method::GET)
      .uri("http://other.example.com/")
      .header("host", "api.example.com")
      .body(())
      .unwrap();
    let result = validate_and_route(&req, &router);
    match result {
      Err(resp) => {
        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST)
      }
      Ok(_) => panic!("expected error"),
    }
  }

  #[test]
  fn test_validate_and_route_no_matching_server_returns_404() {
    let router = ServerRouter::build(vec![]);
    let req = http::Request::builder()
      .method(http::Method::GET)
      .uri("/")
      .header("host", "api.example.com")
      .body(())
      .unwrap();
    let result = validate_and_route(&req, &router);
    match result {
      Err(resp) => {
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND)
      }
      Ok(_) => panic!("expected error"),
    }
  }

  // ============== 404 Response Tests ==============

  #[test]
  fn test_build_404_response() {
    let resp = build_404_response();
    assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
  }
}
