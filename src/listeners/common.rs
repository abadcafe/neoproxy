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

/// Monitoring log interval in seconds.
pub const MONITORING_LOG_INTERVAL: Duration = Duration::from_secs(60);

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

/// Check if SNI matches the Host header.
///
/// Rules:
/// - Comparison is case-insensitive (DNS names are case-insensitive)
/// - Host header port is stripped for comparison
/// - IPv6 brackets are handled (Host may have [::1] format)
/// - Empty SNI or Host is treated as no match
///
/// # Arguments
/// * `sni` - The SNI (Server Name Indication) from TLS handshake
/// * `host_header` - The Host header value from the HTTP request
///
/// # Returns
/// `true` if SNI matches Host, `false` otherwise
pub fn sni_matches_host(sni: &str, host_header: &str) -> bool {
  // Empty strings are not valid matches
  if sni.is_empty() || host_header.is_empty() {
    return false;
  }

  // Extract the host part (strip port if present)
  // For IPv6, Host format is [::1]:port, we need to handle brackets
  let host = if host_header.starts_with('[') {
    // IPv6 format: [::1]:port or [::1]
    if let Some(bracket_end) = host_header.find(']') {
      &host_header[1..bracket_end]
    } else {
      // Malformed IPv6, use as-is
      host_header
    }
  } else {
    // IPv4 or hostname: strip port
    host_header.split(':').next().unwrap_or(host_header)
  };

  // Case-insensitive comparison (DNS is case-insensitive)
  sni.to_lowercase() == host.to_lowercase()
}

/// Build a 421 Misdirected Request response.
///
/// This response is sent when the SNI from TLS handshake does not match
/// the Host header in the HTTP request, indicating a potential
/// cross-protocol attack or misconfiguration.
pub fn build_421_misdirected_response() -> Response {
  let body = http_body_util::Full::new(bytes::Bytes::from(
    "Misdirected Request: SNI does not match Host header",
  ));
  let bytes_buf = BytesBufBodyWrapper::new(body);
  let body = ResponseBody::new(bytes_buf);
  let mut resp = Response::new(body);
  *resp.status_mut() = http::StatusCode::MISDIRECTED_REQUEST;
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

  // ============== SNI/Host Matching Tests ==============

  #[test]
  fn test_sni_host_match_exact() {
    // SNI and Host match exactly
    let sni = "api.example.com";
    let host = "api.example.com";
    assert!(sni_matches_host(sni, host));
  }

  #[test]
  fn test_sni_host_match_different() {
    // SNI and Host are different - should return false
    let sni = "api.example.com";
    let host = "other.example.com";
    assert!(!sni_matches_host(sni, host));
  }

  #[test]
  fn test_sni_host_match_case_insensitive() {
    // DNS comparison should be case-insensitive
    let sni = "API.EXAMPLE.COM";
    let host = "api.example.com";
    assert!(sni_matches_host(sni, host));
  }

  #[test]
  fn test_sni_host_match_with_port() {
    // Host header may include port, should strip for comparison
    let sni = "api.example.com";
    let host = "api.example.com:443";
    assert!(sni_matches_host(sni, host));
  }

  #[test]
  fn test_sni_host_match_empty_sni() {
    // Empty SNI should not match anything
    let sni = "";
    let host = "api.example.com";
    assert!(!sni_matches_host(sni, host));
  }

  #[test]
  fn test_sni_host_match_empty_host() {
    // Empty host should not match anything
    let sni = "api.example.com";
    let host = "";
    assert!(!sni_matches_host(sni, host));
  }

  #[test]
  fn test_sni_host_match_both_empty() {
    // Both empty should not match
    let sni = "";
    let host = "";
    assert!(!sni_matches_host(sni, host));
  }

  #[test]
  fn test_sni_host_match_ipv4_address() {
    // IPv4 addresses should match
    let sni = "192.168.1.1";
    let host = "192.168.1.1";
    assert!(sni_matches_host(sni, host));
  }

  #[test]
  fn test_sni_host_match_ipv4_with_port() {
    // IPv4 with port should match after stripping port
    let sni = "192.168.1.1";
    let host = "192.168.1.1:8443";
    assert!(sni_matches_host(sni, host));
  }

  #[test]
  fn test_sni_host_match_ipv6_address() {
    // IPv6 addresses should match (without brackets in SNI)
    let sni = "::1";
    // This is a special case - we handle it by stripping brackets
    assert!(sni_matches_host(sni, "[::1]"));
  }

  #[test]
  fn test_sni_host_match_ipv6_with_port() {
    // IPv6 with port - Host format is [::1]:443
    let sni = "::1";
    let host = "[::1]:443";
    // Should extract ::1 from [::1]:443
    assert!(sni_matches_host(sni, host));
  }

  #[test]
  fn test_build_421_response() {
    let resp = build_421_misdirected_response();
    assert_eq!(resp.status(), http::StatusCode::MISDIRECTED_REQUEST);
  }

  #[test]
  fn test_build_421_response_content_type() {
    let resp = build_421_misdirected_response();
    let content_type = resp.headers().get(http::header::CONTENT_TYPE);
    assert!(content_type.is_some());
    assert_eq!(content_type.unwrap(), "text/plain");
  }

  #[test]
  fn test_build_421_response_body() {
    let resp = build_421_misdirected_response();
    let body = resp.into_body();
    // We can't easily inspect the body without async, but we can check
    // it exists
    let _ = body;
  }

  // ============== Original Tests ==============

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
