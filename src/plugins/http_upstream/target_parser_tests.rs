use super::target_parser::*;

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
  let target = parse_connect_target(&parts).unwrap();
  assert_eq!(target.authority(), "example.com:443");
  assert_eq!(target.uri(), "example.com:443");
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
  let parts = make_request_parts(http::Method::CONNECT, "example.com");
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
  let target = parse_connect_target(&parts).unwrap();
  assert_eq!(target.authority(), "[::1]:8080");
  assert_eq!(target.uri(), "[::1]:8080");
}

#[test]
fn test_parse_connect_target_ipv4_address() {
  let parts =
    make_request_parts(http::Method::CONNECT, "192.168.1.1:80");
  let target = parse_connect_target(&parts).unwrap();
  assert_eq!(target.authority(), "192.168.1.1:80");
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
  let target = result.unwrap();
  assert_eq!(
    target.absolute_uri().to_string().as_str(),
    "http://example.com/path"
  );
  assert_eq!(
    target.host_header_value().unwrap().to_str().unwrap(),
    "example.com"
  );
}

#[test]
fn test_parse_forward_target_http_with_port() {
  let parts = make_request_parts(
    http::Method::POST,
    "http://example.com:8080/api",
  );
  let result = parse_forward_target(&parts);
  assert!(result.is_ok());
  let target = result.unwrap();
  assert_eq!(
    target.absolute_uri().to_string().as_str(),
    "http://example.com:8080/api"
  );
  assert_eq!(
    target.host_header_value().unwrap().to_str().unwrap(),
    "example.com:8080"
  );
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
  let target = result.unwrap();
  assert_eq!(
    target.absolute_uri().to_string(),
    "https://example.com/path"
  );
  assert_eq!(target.host_header_value().unwrap(), "example.com");
}

#[test]
fn test_parse_forward_target_rejects_non_http_schemes() {
  for uri in ["ftp://example.com/path", "ws://example.com/path"] {
    let parts = make_request_parts(http::Method::GET, uri);
    assert_eq!(
      parse_forward_target(&parts),
      Err(ForwardTargetError::UnsupportedScheme)
    );
  }
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
  for uri in ["http://example.com/", "https://example.com/"] {
    let parts = make_request_parts(http::Method::GET, uri);
    let target = parse_forward_target(&parts).unwrap();
    assert_eq!(target.host_header_value().unwrap(), "example.com");
    assert_eq!(target.absolute_uri().to_string(), uri);
  }
}

#[test]
fn test_parse_forward_target_rejects_userinfo() {
  let parts =
    make_request_parts(http::Method::GET, "http://user@example.com/");
  let result = parse_forward_target(&parts);
  assert_eq!(result, Err(ForwardTargetError::InvalidAuthority));
}

#[test]
fn test_forward_target_error_display() {
  assert_eq!(
    format!("{}", ForwardTargetError::ConnectMethod),
    "CONNECT method not allowed for forward proxy"
  );
  assert_eq!(
    format!("{}", ForwardTargetError::NotAbsoluteForm),
    "URI must be absolute-form (http://host/path or https://host/path)"
  );
  assert_eq!(
    format!("{}", ForwardTargetError::UnsupportedScheme),
    "only http:// and https:// schemes supported for forward proxy"
  );
}

#[test]
fn test_parse_connect_target_rejects_non_authority_form_and_userinfo() {
  for uri in ["http://example.com:443/", "user@example.com:443"] {
    let parts = make_request_parts(http::Method::CONNECT, uri);
    assert!(parse_connect_target(&parts).is_err());
  }
}

#[test]
fn test_parse_forward_target_rejects_invalid_port() {
  for uri in ["http://example.com:65536/", "http://example.com:abc/"] {
    let parts = make_request_parts(http::Method::GET, uri);
    assert!(parse_forward_target(&parts).is_err());
  }
}

#[test]
fn test_parse_forward_target_normalizes_empty_port() {
  for (uri, normalized, host) in [
    (
      "http://example.com:/path?q=a:b",
      "http://example.com/path?q=a:b",
      "example.com",
    ),
    ("http://127.0.0.1:/", "http://127.0.0.1/", "127.0.0.1"),
    ("http://[::1]:/path", "http://[::1]/path", "[::1]"),
  ] {
    let parts = make_request_parts(http::Method::GET, uri);
    let target = parse_forward_target(&parts).unwrap();
    assert_eq!(target.absolute_uri().to_string(), normalized);
    assert_eq!(target.host_header_value().unwrap(), host);
  }
}

#[test]
fn test_parse_connect_target_rejects_empty_or_invalid_port() {
  for uri in
    ["example.com:", "[::1]:", "example.com:abc", "example.com:65536"]
  {
    let parts = make_request_parts(http::Method::CONNECT, uri);
    assert!(parse_connect_target(&parts).is_err(), "{uri}");
  }
}

#[test]
fn test_parse_connect_target_accepts_port_boundaries() {
  for port in [1, u16::MAX] {
    let parts = make_request_parts(
      http::Method::CONNECT,
      &format!("example.com:{port}"),
    );
    let target = parse_connect_target(&parts).unwrap();
    assert_eq!(target.uri().port_u16(), Some(port));
  }
}

#[test]
fn test_parse_connect_target_http3_uses_authority_from_decoded_request()
{
  // h3 0.0.8 synthesizes a default path when decoding CONNECT. Its
  // Request URI is an HTTP representation, not an HTTP/1 request line.
  let request = http::Request::builder()
    .method(http::Method::CONNECT)
    .version(http::Version::HTTP_3)
    .uri(
      http::Uri::builder()
        .authority("example.com:443")
        .build()
        .unwrap(),
    )
    .body(())
    .unwrap();
  let target = parse_connect_target(&request.into_parts().0).unwrap();
  assert_eq!(target.authority(), "example.com:443");
  assert_eq!(target.uri().scheme(), None);
  assert_eq!(target.uri().path_and_query(), None);
}

#[test]
fn test_parse_connect_target_preserves_validated_authority() {
  for authority in
    ["127.0.0.1:1", "[2001:db8::1]:65535", "EXAMPLE.COM:00443"]
  {
    let parts = make_request_parts(http::Method::CONNECT, authority);
    let target = parse_connect_target(&parts).unwrap();
    assert_eq!(target.authority(), authority);
    assert_eq!(target.uri().to_string(), authority);
    assert_eq!(target.to_string(), authority);
    assert_eq!(target.clone(), target);
  }
}
