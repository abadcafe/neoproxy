use std::fmt;

/// CONNECT target address parse error
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectTargetError {
  NotConnectMethod,
  NoAuthority,
  NoPort,
  PortZero,
}

/// Forward proxy target address parse error
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardTargetError {
  ConnectMethod,
  NotAbsoluteForm,
  UnsupportedScheme,
  NoAuthority,
  PortZero,
}

impl fmt::Display for ConnectTargetError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      ConnectTargetError::NotConnectMethod => {
        write!(f, "not CONNECT method")
      }
      ConnectTargetError::NoAuthority => {
        write!(f, "no authority in URI")
      }
      ConnectTargetError::NoPort => {
        write!(f, "no port in authority")
      }
      ConnectTargetError::PortZero => {
        write!(f, "port is zero")
      }
    }
  }
}

impl std::error::Error for ConnectTargetError {}

impl fmt::Display for ForwardTargetError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      ForwardTargetError::ConnectMethod => {
        write!(f, "CONNECT method not allowed for forward proxy")
      }
      ForwardTargetError::NotAbsoluteForm => {
        write!(f, "URI must be absolute-form (http://host/path)")
      }
      ForwardTargetError::UnsupportedScheme => {
        write!(f, "only http:// scheme supported for forward proxy")
      }
      ForwardTargetError::NoAuthority => {
        write!(f, "no authority in URI")
      }
      ForwardTargetError::PortZero => {
        write!(f, "port is zero")
      }
    }
  }
}

impl std::error::Error for ForwardTargetError {}

/// Parse CONNECT request target address
///
/// # Parameters
/// - `parts`: HTTP request Parts
///
/// # Returns
/// - `Ok((host, port))`: Target hostname and port number
/// - `Err(ConnectTargetError)`: Parse failed
pub fn parse_connect_target(
  parts: &http::request::Parts,
) -> Result<(String, u16), ConnectTargetError> {
  if parts.method != http::Method::CONNECT {
    return Err(ConnectTargetError::NotConnectMethod);
  }

  let authority =
    parts.uri.authority().ok_or(ConnectTargetError::NoAuthority)?;

  let port = authority.port_u16().ok_or(ConnectTargetError::NoPort)?;

  if port == 0 {
    return Err(ConnectTargetError::PortZero);
  }

  Ok((authority.host().to_string(), port))
}

/// Parse forward proxy request target address
///
/// Extracts host, port, and origin-form URI from an absolute-form HTTP
/// request. Only supports http:// scheme (https:// requires CONNECT per RFC).
///
/// # Parameters
/// - `parts`: HTTP request Parts
///
/// # Returns
/// - `Ok((host, port, origin_uri))`: Target hostname, port, and
///   origin-form URI
/// - `Err(ForwardTargetError)`: Parse failed
pub fn parse_forward_target(
  parts: &http::request::Parts,
) -> Result<(String, u16, http::Uri), ForwardTargetError> {
  if parts.method == http::Method::CONNECT {
    return Err(ForwardTargetError::ConnectMethod);
  }

  let uri = &parts.uri;

  let scheme =
    uri.scheme().ok_or(ForwardTargetError::NotAbsoluteForm)?;
  if scheme != &http::uri::Scheme::HTTP {
    return Err(ForwardTargetError::UnsupportedScheme);
  }

  let authority =
    uri.authority().ok_or(ForwardTargetError::NoAuthority)?;

  let port = authority.port_u16().unwrap_or(80);

  if port == 0 {
    return Err(ForwardTargetError::PortZero);
  }

  let host = authority.host().to_string();

  let origin_uri = http::Uri::builder()
    .path_and_query(
      uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/"),
    )
    .build()
    .map_err(|_| ForwardTargetError::NotAbsoluteForm)?;

  Ok((host, port, origin_uri))
}

/// Strip hop-by-hop headers from a request/response
///
/// Per RFC 7230, these headers must not be forwarded to the next hop:
/// - connection, keep-alive, proxy-authenticate, proxy-authorization
/// - te, trailers, transfer-encoding, upgrade
/// - Any header names listed in the Connection header value
pub fn strip_hop_by_hop_headers(headers: &mut http::HeaderMap) {
  // Collect extra names listed in the Connection header value first,
  // before removing Connection itself.
  let connection_tokens: Vec<http::header::HeaderName> = headers
    .get(http::header::CONNECTION)
    .and_then(|v| v.to_str().ok())
    .map(|s| {
      s.split(',').filter_map(|t| t.trim().parse().ok()).collect()
    })
    .unwrap_or_default();

  let hop_by_hop: &[http::header::HeaderName] = &[
    http::header::CONNECTION,
    http::header::TE,
    http::header::TRAILER,
    http::header::TRANSFER_ENCODING,
    http::header::UPGRADE,
    http::header::PROXY_AUTHENTICATE,
    http::header::PROXY_AUTHORIZATION,
    http::header::HeaderName::from_static("keep-alive"),
  ];

  for name in hop_by_hop {
    headers.remove(name);
  }
  for name in &connection_tokens {
    headers.remove(name);
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn make_request_parts(
    method: http::Method,
    uri: &str,
  ) -> http::request::Parts {
    http::Request::builder()
      .method(method)
      .uri(uri)
      .body(())
      .unwrap()
      .into_parts()
      .0
  }

  #[test]
  fn test_parse_connect_target_valid() {
    let parts =
      make_request_parts(http::Method::CONNECT, "example.com:443");
    let result = parse_connect_target(&parts);
    assert_eq!(result, Ok(("example.com".to_string(), 443)));
  }

  #[test]
  fn test_parse_connect_target_not_connect_method() {
    let parts =
      make_request_parts(http::Method::GET, "http://example.com/");
    let result = parse_connect_target(&parts);
    assert_eq!(result, Err(ConnectTargetError::NotConnectMethod));
  }

  #[test]
  fn test_parse_connect_target_no_authority() {
    let parts = make_request_parts(http::Method::CONNECT, "/");
    let result = parse_connect_target(&parts);
    assert_eq!(result, Err(ConnectTargetError::NoAuthority));
  }

  #[test]
  fn test_parse_connect_target_no_port() {
    let parts =
      make_request_parts(http::Method::CONNECT, "example.com");
    let result = parse_connect_target(&parts);
    assert_eq!(result, Err(ConnectTargetError::NoPort));
  }

  #[test]
  fn test_parse_connect_target_port_zero() {
    let parts =
      make_request_parts(http::Method::CONNECT, "example.com:0");
    let result = parse_connect_target(&parts);
    assert_eq!(result, Err(ConnectTargetError::PortZero));
  }

  #[test]
  fn test_parse_connect_target_ipv6_address() {
    let parts = make_request_parts(http::Method::CONNECT, "[::1]:8080");
    let result = parse_connect_target(&parts);
    assert_eq!(result, Ok(("[::1]".to_string(), 8080)));
  }

  #[test]
  fn test_parse_connect_target_ipv4_address() {
    let parts =
      make_request_parts(http::Method::CONNECT, "192.168.1.1:80");
    let result = parse_connect_target(&parts);
    assert_eq!(result, Ok(("192.168.1.1".to_string(), 80)));
  }

  #[test]
  fn test_connect_target_error_display() {
    assert_eq!(
      format!("{}", ConnectTargetError::NotConnectMethod),
      "not CONNECT method"
    );
    assert_eq!(
      format!("{}", ConnectTargetError::NoAuthority),
      "no authority in URI"
    );
    assert_eq!(
      format!("{}", ConnectTargetError::NoPort),
      "no port in authority"
    );
    assert_eq!(
      format!("{}", ConnectTargetError::PortZero),
      "port is zero"
    );
  }

  #[test]
  fn test_connect_target_error_is_error() {
    let err = ConnectTargetError::NotConnectMethod;
    let _err: &dyn std::error::Error = &err;
  }

  // ============== Forward Target Tests ==============

  #[test]
  fn test_parse_forward_target_valid_http() {
    let parts =
      make_request_parts(http::Method::GET, "http://example.com/path");
    let result = parse_forward_target(&parts);
    assert!(result.is_ok());
    let (host, port, uri) = result.unwrap();
    assert_eq!(host, "example.com");
    assert_eq!(port, 80);
    assert_eq!(uri.path_and_query().unwrap().as_str(), "/path");
  }

  #[test]
  fn test_parse_forward_target_http_with_port() {
    let parts = make_request_parts(
      http::Method::POST,
      "http://example.com:8080/api",
    );
    let result = parse_forward_target(&parts);
    assert!(result.is_ok());
    let (host, port, uri) = result.unwrap();
    assert_eq!(host, "example.com");
    assert_eq!(port, 8080);
    assert_eq!(uri.path_and_query().unwrap().as_str(), "/api");
  }

  #[test]
  fn test_parse_forward_target_connect_method() {
    let parts =
      make_request_parts(http::Method::CONNECT, "example.com:443");
    let result = parse_forward_target(&parts);
    assert_eq!(result, Err(ForwardTargetError::ConnectMethod));
  }

  #[test]
  fn test_parse_forward_target_https_scheme() {
    let parts =
      make_request_parts(http::Method::GET, "https://example.com/path");
    let result = parse_forward_target(&parts);
    assert_eq!(result, Err(ForwardTargetError::UnsupportedScheme));
  }

  #[test]
  fn test_parse_forward_target_origin_form() {
    let parts = make_request_parts(http::Method::GET, "/path");
    let result = parse_forward_target(&parts);
    assert_eq!(result, Err(ForwardTargetError::NotAbsoluteForm));
  }

  #[test]
  fn test_parse_forward_target_port_zero() {
    let parts =
      make_request_parts(http::Method::GET, "http://example.com:0/");
    let result = parse_forward_target(&parts);
    assert_eq!(result, Err(ForwardTargetError::PortZero));
  }

  #[test]
  fn test_parse_forward_target_default_port() {
    let parts =
      make_request_parts(http::Method::GET, "http://example.com/");
    let result = parse_forward_target(&parts);
    assert!(result.is_ok());
    let (_host, port, _uri) = result.unwrap();
    assert_eq!(port, 80);
  }

  #[test]
  fn test_strip_hop_by_hop_headers() {
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::CONNECTION, "close".parse().unwrap());
    headers.insert(
      http::header::HeaderName::from_static("keep-alive"),
      "timeout=5".parse().unwrap(),
    );
    headers.insert(
      http::header::PROXY_AUTHORIZATION,
      "Basic abc123".parse().unwrap(),
    );
    headers.insert(
      http::header::CONTENT_TYPE,
      "text/plain".parse().unwrap(),
    );

    strip_hop_by_hop_headers(&mut headers);

    assert!(headers.get(http::header::CONNECTION).is_none());
    assert!(
      headers
        .get(http::header::HeaderName::from_static("keep-alive"))
        .is_none()
    );
    assert!(headers.get(http::header::PROXY_AUTHORIZATION).is_none());
    assert!(headers.get(http::header::CONTENT_TYPE).is_some());
  }

  #[test]
  fn test_strip_hop_by_hop_headers_connection_tokens() {
    // RFC 7230: headers named in Connection value must also be stripped
    let mut headers = http::HeaderMap::new();
    headers.insert(
      http::header::CONNECTION,
      "keep-alive, x-custom-hop".parse().unwrap(),
    );
    headers.insert(
      http::header::HeaderName::from_static("x-custom-hop"),
      "value".parse().unwrap(),
    );
    headers.insert(
      http::header::CONTENT_TYPE,
      "text/plain".parse().unwrap(),
    );

    strip_hop_by_hop_headers(&mut headers);

    assert!(headers.get(http::header::CONNECTION).is_none());
    assert!(
      headers
        .get(http::header::HeaderName::from_static("x-custom-hop"))
        .is_none()
    );
    assert!(headers.get(http::header::CONTENT_TYPE).is_some());
  }

  #[test]
  fn test_forward_target_error_display() {
    assert_eq!(
      format!("{}", ForwardTargetError::ConnectMethod),
      "CONNECT method not allowed for forward proxy"
    );
    assert_eq!(
      format!("{}", ForwardTargetError::NotAbsoluteForm),
      "URI must be absolute-form (http://host/path)"
    );
    assert_eq!(
      format!("{}", ForwardTargetError::UnsupportedScheme),
      "only http:// scheme supported for forward proxy"
    );
  }
}
