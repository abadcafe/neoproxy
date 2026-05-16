//! Common utilities shared across HTTP listeners.
//!
//! This module provides shared functionality for HTTP/HTTPS listeners
//! to avoid code duplication.

use std::future::Future;
use std::time::Duration;

use crate::http_utils::{BytesBufBodyWrapper, Response, ResponseBody};

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

/// Check HTTP version and return error if version is not supported.
///
/// HTTP/1.0 is NOT supported - returns 505 HTTP Version Not Supported.
/// HTTP/1.1 and higher are supported.
pub fn check_http_version(
  version: http::Version,
) -> Result<(), http::StatusCode> {
  match version {
    http::Version::HTTP_10 => {
      Err(http::StatusCode::HTTP_VERSION_NOT_SUPPORTED)
    }
    http::Version::HTTP_11
    | http::Version::HTTP_2
    | http::Version::HTTP_3 => Ok(()),
    _ => Err(http::StatusCode::HTTP_VERSION_NOT_SUPPORTED),
  }
}

/// Build a 505 HTTP Version Not Supported response.
pub fn build_505_response() -> Response {
  let body = http_body_util::Full::new(bytes::Bytes::from(
    "HTTP Version Not Supported",
  ));
  let bytes_buf = BytesBufBodyWrapper::new(body);
  let body = ResponseBody::new(bytes_buf);
  let mut resp = Response::new(body);
  *resp.status_mut() = http::StatusCode::HTTP_VERSION_NOT_SUPPORTED;
  resp.headers_mut().insert(
    http::header::CONTENT_TYPE,
    http::HeaderValue::from_static("text/plain"),
  );
  resp
}


/// Check if authority and Host header values differ.
///
/// Per RFC 9114 §4.3.1, if both `:authority` and Host are present,
/// they MUST contain the same value. Comparison is case-insensitive.
///
/// # Arguments
/// * `authority_str` - The full authority string (e.g., "example.com:443")
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


/// Build a 403 Forbidden response.
///
/// This response is sent when a server requires client certificate
/// authentication but the client did not present one.
pub fn build_403_forbidden(msg: &str) -> Response {
  let body = http_body_util::Full::new(bytes::Bytes::from(msg.to_string()));
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
    assert!(!check_authority_vs_host("api.example.com", "api.example.com"));
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
  fn test_check_http_version_http3_ok() {
    // HTTP/3 should pass
    let version = http::Version::HTTP_3;
    let result = check_http_version(version);
    assert!(result.is_ok());
  }

  #[test]
  fn test_check_http_version_unknown_returns_505() {
    // Unknown versions should return 505
    let version = http::Version::HTTP_09;
    let result = check_http_version(version);
    assert!(result.is_err());
    assert_eq!(
      result.unwrap_err(),
      http::StatusCode::HTTP_VERSION_NOT_SUPPORTED
    );
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

  #[test]
  fn test_build_505_response_content_type() {
    let resp = build_505_response();
    let content_type = resp.headers().get(http::header::CONTENT_TYPE);
    assert!(content_type.is_some());
    assert_eq!(content_type.unwrap(), "text/plain");
  }

  // ============== 404 Response Tests ==============

  #[test]
  fn test_build_404_response() {
    let resp = build_404_response();
    assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
  }
}
