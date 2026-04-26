//! Common utilities shared across HTTP listeners.
//!
//! This module provides shared functionality for HTTP/HTTPS listeners
//! to avoid code duplication.

use std::net::SocketAddr;

use crate::auth::{ListenerAuthConfig, UserPasswordAuth};
use crate::config::UserConfig;
use crate::plugin;
use crate::server::ServerRoutingEntry;

/// Route a request to the correct service based on hostname.
///
/// Returns the matching ServerRoutingEntry or None if no match found.
/// Uses the routing_info for fast hostname matching, with fallback
/// to default server (empty hostnames).
///
/// # Arguments
///
/// * `routing_table` - The table of server routing entries
/// * `routing_info` - Compiled routing info for fast lookup
/// * `hostname` - Optional hostname to match (None routes to default)
pub fn route_request_by_hostname<'a>(
  routing_table: &'a [ServerRoutingEntry],
  routing_info: &[neoproxy::routing::ServerMatchInfo],
  hostname: Option<&str>,
) -> Option<&'a ServerRoutingEntry> {
  match hostname {
    Some(hostname) => {
      let match_info =
        neoproxy::routing::find_matching_server(routing_info, hostname);
      match_info.and_then(|info| {
        routing_table.iter().find(|e| e.name == info.name)
      })
    }
    None => {
      // No hostname - route to default server
      routing_table.iter().find(|e| e.hostnames.is_empty())
    }
  }
}

/// Record an HTTP access log entry.
///
/// This function creates an `AccessLogEntry` from the provided parameters
/// and writes it to the access log writer. It is used by all HTTP-based
/// listeners (HTTP, HTTPS, HTTP/3) to ensure consistent logging format.
///
/// # Arguments
///
/// * `writer` - The access log writer to write the entry to
/// * `params` - The HTTP access log parameters containing all request details
pub fn record_http_access_log(
  writer: &crate::access_log::AccessLogWriter,
  params: &crate::access_log::HttpAccessLogParams,
) {
  let entry = crate::access_log::AccessLogEntry {
    time: time::OffsetDateTime::now_local()
      .unwrap_or_else(|_| time::OffsetDateTime::now_utc()),
    client_ip: params.client_addr.ip().to_string(),
    client_port: params.client_addr.port(),
    user: params.user.clone(),
    auth_type: params.auth_type,
    method: params.method.clone(),
    target: params.target.clone(),
    status: params.status,
    duration_ms: params.duration.as_millis() as u64,
    service: params.service_name.clone(),
    service_metrics: params.service_metrics.clone(),
  };
  writer.write(&entry);
}

/// Record a SOCKS5 access log entry.
///
/// This function creates an `AccessLogEntry` from the individual parameters
/// provided by the SOCKS5 listener and writes it to the access log writer.
/// It accepts individual parameters rather than `HttpAccessLogParams` because
/// SOCKS5 logging has slightly different semantics (target is a host:port
/// string rather than a URI).
///
/// # Arguments
///
/// * `writer` - The access log writer to write the entry to
/// * `client_addr` - The client's socket address
/// * `user` - Optional username if authentication was used
/// * `auth_type` - The type of authentication used
/// * `method` - The SOCKS5 method (typically "CONNECT")
/// * `target` - The target address (host:port)
/// * `status` - The response status code
/// * `duration` - The duration of the request
/// * `service_name` - The name of the service that handled the request
/// * `service_metrics` - Additional metrics from the service
pub fn record_socks5_access_log(
  writer: &crate::access_log::AccessLogWriter,
  client_addr: SocketAddr,
  user: Option<String>,
  auth_type: crate::access_log::AuthType,
  method: String,
  target: String,
  status: u16,
  duration: std::time::Duration,
  service_name: String,
  service_metrics: crate::access_log::ServiceMetrics,
) {
  let entry = crate::access_log::AccessLogEntry {
    time: time::OffsetDateTime::now_local()
      .unwrap_or_else(|_| time::OffsetDateTime::now_utc()),
    client_ip: client_addr.ip().to_string(),
    client_port: client_addr.port(),
    user,
    auth_type,
    method,
    target,
    status,
    duration_ms: duration.as_millis() as u64,
    service: service_name,
    service_metrics,
  };
  writer.write(&entry);
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
pub fn build_505_response() -> plugin::Response {
  let body = http_body_util::Full::new(bytes::Bytes::from(
    "HTTP Version Not Supported",
  ));
  let bytes_buf = plugin::BytesBufBodyWrapper::new(body);
  let body = plugin::ResponseBody::new(bytes_buf);
  let mut resp = plugin::Response::new(body);
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
pub fn build_421_misdirected_response() -> plugin::Response {
  let body = http_body_util::Full::new(bytes::Bytes::from(
    "Misdirected Request: SNI does not match Host header",
  ));
  let bytes_buf = plugin::BytesBufBodyWrapper::new(body);
  let body = plugin::ResponseBody::new(bytes_buf);
  let mut resp = plugin::Response::new(body);
  *resp.status_mut() = http::StatusCode::MISDIRECTED_REQUEST;
  resp.headers_mut().insert(
    http::header::CONTENT_TYPE,
    http::HeaderValue::from_static("text/plain"),
  );
  resp
}

/// Build a 407 Proxy Authentication Required response.
///
/// This response is sent when a request requires proxy authentication.
/// It includes a `Proxy-Authenticate` header with `Basic realm="proxy"`.
pub fn build_407_response() -> plugin::Response {
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

/// Build a 404 Not Found response.
pub fn build_404_response() -> plugin::Response {
  let empty = http_body_util::Empty::new();
  let bytes_buf = plugin::BytesBufBodyWrapper::new(empty);
  let body = plugin::ResponseBody::new(bytes_buf);
  let mut resp = plugin::Response::new(body);
  *resp.status_mut() = http::StatusCode::NOT_FOUND;
  resp
}

/// Build UserPasswordAuth from server-level users config.
///
/// This function creates a `UserPasswordAuth` instance from the optional
/// users configuration. It is used by HTTP, HTTPS, and HTTP/3 listeners
/// to ensure consistent authentication handling.
///
/// # Arguments
///
/// * `users` - Optional list of user configurations from server-level config
///
/// # Returns
///
/// A `UserPasswordAuth` instance that can be used to verify proxy authentication.
pub fn build_user_password_auth(
  users: &Option<Vec<UserConfig>>,
) -> UserPasswordAuth {
  match users {
    Some(users) if !users.is_empty() => {
      let config = ListenerAuthConfig {
        users: Some(
          users
            .iter()
            .map(|u| {
              crate::auth::listener_auth_config::UserCredential {
                username: u.username.clone(),
                password: u.password.clone(),
              }
            })
            .collect(),
        ),
        client_ca_path: None,
      };
      UserPasswordAuth::from_config(&config)
    }
    _ => UserPasswordAuth::none(),
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::future::Future;
  use std::pin::Pin;

  // ============== route_request_by_hostname Tests ==============

  /// Helper to create a dummy service for tests
  fn create_dummy_service() -> crate::plugin::Service {
    #[derive(Clone)]
    struct DummyService;

    impl tower::Service<crate::plugin::Request> for DummyService {
      type Error = anyhow::Error;
      type Future = Pin<
        Box<
          dyn Future<Output = anyhow::Result<crate::plugin::Response>>,
        >,
      >;
      type Response = crate::plugin::Response;

      fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
      ) -> std::task::Poll<anyhow::Result<()>> {
        std::task::Poll::Ready(Ok(()))
      }

      fn call(&mut self, _req: crate::plugin::Request) -> Self::Future {
        Box::pin(async {
          anyhow::bail!("DummyService not implemented")
        })
      }
    }

    crate::plugin::Service::new(DummyService)
  }

  #[test]
  fn test_route_request_by_hostname_exact_match() {
    let routing_table = vec![
      crate::server::ServerRoutingEntry {
        name: "default".to_string(),
        hostnames: vec![],
        service: create_dummy_service(),
        service_name: "default_service".to_string(),
        users: None,
        tls: None,
        access_log_writer: None,
      },
      crate::server::ServerRoutingEntry {
        name: "api".to_string(),
        hostnames: vec!["api.example.com".to_string()],
        service: create_dummy_service(),
        service_name: "api_service".to_string(),
        users: None,
        tls: None,
        access_log_writer: None,
      },
    ];
    let routing_info = vec![
      neoproxy::routing::ServerMatchInfo {
        name: "default".to_string(),
        hostnames: vec![],
      },
      neoproxy::routing::ServerMatchInfo {
        name: "api".to_string(),
        hostnames: vec!["api.example.com".to_string()],
      },
    ];

    let result = route_request_by_hostname(
      &routing_table,
      &routing_info,
      Some("api.example.com"),
    );
    assert!(result.is_some());
    assert_eq!(result.unwrap().name, "api");
  }

  #[test]
  fn test_route_request_by_hostname_default() {
    let routing_table = vec![
      crate::server::ServerRoutingEntry {
        name: "default".to_string(),
        hostnames: vec![],
        service: create_dummy_service(),
        service_name: "default_service".to_string(),
        users: None,
        tls: None,
        access_log_writer: None,
      },
      crate::server::ServerRoutingEntry {
        name: "api".to_string(),
        hostnames: vec!["api.example.com".to_string()],
        service: create_dummy_service(),
        service_name: "api_service".to_string(),
        users: None,
        tls: None,
        access_log_writer: None,
      },
    ];
    let routing_info = vec![
      neoproxy::routing::ServerMatchInfo {
        name: "default".to_string(),
        hostnames: vec![],
      },
      neoproxy::routing::ServerMatchInfo {
        name: "api".to_string(),
        hostnames: vec!["api.example.com".to_string()],
      },
    ];

    // No hostname = route to default
    let result =
      route_request_by_hostname(&routing_table, &routing_info, None);
    assert!(result.is_some());
    assert_eq!(result.unwrap().name, "default");
  }

  #[test]
  fn test_route_request_by_hostname_no_match() {
    let routing_table = vec![crate::server::ServerRoutingEntry {
      name: "api".to_string(),
      hostnames: vec!["api.example.com".to_string()],
      service: create_dummy_service(),
      service_name: "api_service".to_string(),
      users: None,
      tls: None,
      access_log_writer: None,
    }];
    let routing_info = vec![neoproxy::routing::ServerMatchInfo {
      name: "api".to_string(),
      hostnames: vec!["api.example.com".to_string()],
    }];

    // Unknown hostname = no match
    let result = route_request_by_hostname(
      &routing_table,
      &routing_info,
      Some("unknown.example.com"),
    );
    assert!(result.is_none());
  }

  #[test]
  fn test_route_request_by_hostname_wildcard_match() {
    let routing_table = vec![
      crate::server::ServerRoutingEntry {
        name: "default".to_string(),
        hostnames: vec![],
        service: create_dummy_service(),
        service_name: "default_service".to_string(),
        users: None,
        tls: None,
        access_log_writer: None,
      },
      crate::server::ServerRoutingEntry {
        name: "wildcard".to_string(),
        hostnames: vec!["*.example.com".to_string()],
        service: create_dummy_service(),
        service_name: "wildcard_service".to_string(),
        users: None,
        tls: None,
        access_log_writer: None,
      },
    ];
    let routing_info = vec![
      neoproxy::routing::ServerMatchInfo {
        name: "default".to_string(),
        hostnames: vec![],
      },
      neoproxy::routing::ServerMatchInfo {
        name: "wildcard".to_string(),
        hostnames: vec!["*.example.com".to_string()],
      },
    ];

    // Wildcard match - foo.example.com matches *.example.com
    let result = route_request_by_hostname(
      &routing_table,
      &routing_info,
      Some("foo.example.com"),
    );
    assert!(result.is_some());
    assert_eq!(result.unwrap().name, "wildcard");
  }

  #[test]
  fn test_route_request_by_hostname_wildcard_vs_exact_priority() {
    let routing_table = vec![
      crate::server::ServerRoutingEntry {
        name: "wildcard".to_string(),
        hostnames: vec!["*.example.com".to_string()],
        service: create_dummy_service(),
        service_name: "wildcard_service".to_string(),
        users: None,
        tls: None,
        access_log_writer: None,
      },
      crate::server::ServerRoutingEntry {
        name: "api".to_string(),
        hostnames: vec!["api.example.com".to_string()],
        service: create_dummy_service(),
        service_name: "api_service".to_string(),
        users: None,
        tls: None,
        access_log_writer: None,
      },
    ];
    let routing_info = vec![
      neoproxy::routing::ServerMatchInfo {
        name: "wildcard".to_string(),
        hostnames: vec!["*.example.com".to_string()],
      },
      neoproxy::routing::ServerMatchInfo {
        name: "api".to_string(),
        hostnames: vec!["api.example.com".to_string()],
      },
    ];

    // Exact match takes priority over wildcard
    let result = route_request_by_hostname(
      &routing_table,
      &routing_info,
      Some("api.example.com"),
    );
    assert!(result.is_some());
    assert_eq!(result.unwrap().name, "api");

    // Wildcard match for non-exact hostname
    let result = route_request_by_hostname(
      &routing_table,
      &routing_info,
      Some("other.example.com"),
    );
    assert!(result.is_some());
    assert_eq!(result.unwrap().name, "wildcard");
  }

  // ============== Access Log Tests ==============

  #[test]
  fn test_record_http_access_log_writes_entry() {
    let dir = tempfile::tempdir().unwrap();
    let config = crate::access_log::AccessLogConfig {
      enabled: true,
      path_prefix: "commonhtest.log".to_string(),
      format: crate::access_log::config::LogFormat::Text,
      buffer: crate::access_log::config::HumanBytes(64),
      flush: crate::access_log::config::HumanDuration(
        std::time::Duration::from_millis(100),
      ),
      max_size: crate::access_log::config::HumanBytes(1024 * 1024),
    };
    let writer = crate::access_log::AccessLogWriter::new(
      dir.path().to_str().unwrap(),
      &config,
    );

    let client_addr: std::net::SocketAddr =
      "192.168.1.1:54321".parse().unwrap();
    let mut metrics = crate::access_log::ServiceMetrics::new();
    metrics.add("connect_ms", 42u64);

    let params = crate::access_log::HttpAccessLogParams {
      client_addr,
      user: Some("testuser".to_string()),
      auth_type: crate::access_log::AuthType::Password,
      method: "CONNECT".to_string(),
      target: "example.com:443".to_string(),
      status: 200,
      duration: std::time::Duration::from_millis(50),
      service_name: "tunnel".to_string(),
      service_metrics: metrics,
    };

    record_http_access_log(&writer, &params);

    writer.flush();

    // Verify log file was created and contains expected fields
    let mut found = false;
    for entry in std::fs::read_dir(dir.path()).unwrap() {
      let entry = entry.unwrap();
      let name = entry.file_name().to_string_lossy().to_string();
      if name.starts_with("commonhtest.log") {
        let content = std::fs::read_to_string(entry.path()).unwrap();
        assert!(
          content.contains("192.168.1.1:54321"),
          "Should contain client addr"
        );
        assert!(
          content.contains("CONNECT example.com:443"),
          "Should contain request line"
        );
        assert!(content.contains("200"), "Should contain status code");
        assert!(
          content.contains("service=tunnel"),
          "Should contain service name"
        );
        assert!(
          content.contains("service.connect_ms=42"),
          "Should contain service metrics"
        );
        assert!(
          content.contains("auth=password"),
          "Should contain auth type"
        );
        found = true;
      }
    }
    assert!(found, "Access log file should exist");
  }

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
    // We can't easily inspect the body without async, but we can check it exists
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

  // ============== 407 Response Tests ==============

  #[test]
  fn test_build_407_response() {
    let resp = build_407_response();
    assert_eq!(
      resp.status(),
      http::StatusCode::PROXY_AUTHENTICATION_REQUIRED
    );
    let auth_header =
      resp.headers().get(http::header::PROXY_AUTHENTICATE);
    assert!(auth_header.is_some());
    assert_eq!(auth_header.unwrap(), "Basic realm=\"proxy\"");
  }

  // ============== 404 Response Tests ==============

  #[test]
  fn test_build_404_response() {
    let resp = build_404_response();
    assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
  }

  // ============== build_user_password_auth Tests ==============

  #[test]
  fn test_build_user_password_auth_none() {
    let auth = build_user_password_auth(&None);
    let req = http::Request::builder()
      .method("GET")
      .uri("http://example.com")
      .body(())
      .unwrap();
    assert!(auth.verify_and_extract_username(&req).is_ok());
  }

  #[test]
  fn test_build_user_password_auth_empty_list() {
    let auth = build_user_password_auth(&Some(vec![]));
    let req = http::Request::builder()
      .method("GET")
      .uri("http://example.com")
      .body(())
      .unwrap();
    assert!(auth.verify_and_extract_username(&req).is_ok());
  }

  #[test]
  fn test_build_user_password_auth_with_users() {
    use crate::config::UserConfig;

    let users = Some(vec![UserConfig {
      username: "admin".to_string(),
      password: "secret".to_string(),
    }]);
    let auth = build_user_password_auth(&users);

    // Without credentials should fail
    let req = http::Request::builder()
      .method("GET")
      .uri("http://example.com")
      .body(())
      .unwrap();
    assert!(auth.verify_and_extract_username(&req).is_err());

    // With correct credentials should pass
    use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
    let credentials = BASE64.encode("admin:secret");
    let req = http::Request::builder()
      .method("GET")
      .uri("http://example.com")
      .header("Proxy-Authorization", format!("Basic {}", credentials))
      .body(())
      .unwrap();
    let result = auth.verify_and_extract_username(&req);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), Some("admin".to_string()));
  }
}
