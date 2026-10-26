//! module: hop_headers
//! responsibilities: normalize fields crossing an HTTP hop
//! public operations: strip_connection_headers, strip_trailer_headers,
//! join_cookie_headers
//! data entities: none
//! tests: hop_headers_tests.rs

/// Strip connection-specific fields before forwarding or H3 encoding.
///
/// RFC 9110 §7.6.1 requires removing Connection and every field it
/// nominates. Proxy authentication is a separate hop policy: in
/// particular, a locally generated 407 must retain its challenge.
pub(crate) fn strip_connection_headers(headers: &mut http::HeaderMap) {
  // Collect extra names listed in the Connection header value first,
  // before removing Connection itself.
  let connection_tokens: Vec<http::header::HeaderName> = headers
    .get_all(http::header::CONNECTION)
    .iter()
    .filter_map(|value| value.to_str().ok())
    .flat_map(|value| value.split(','))
    .filter_map(|token| token.trim().parse().ok())
    .collect();

  let hop_by_hop: &[http::header::HeaderName] = &[
    http::header::CONNECTION,
    http::header::TE,
    http::header::TRAILER,
    http::header::TRANSFER_ENCODING,
    http::header::UPGRADE,
    http::header::HeaderName::from_static("keep-alive"),
    http::header::HeaderName::from_static("proxy-connection"),
  ];

  for name in hop_by_hop {
    headers.remove(name);
  }
  for name in &connection_tokens {
    headers.remove(name);
  }
}

/// Normalize trailers while keeping proxy authentication in the
/// initial header section. This is a field-placement rule, independent
/// of an upstream proxy's authentication policy.
pub(crate) fn strip_trailer_headers(headers: &mut http::HeaderMap) {
  strip_connection_headers(headers);
  // RFC 9110 §6.5.1: framing, routing, authentication and content
  // interpretation cannot be deferred until after the body.
  for name in [
    http::header::CONTENT_LENGTH,
    http::header::HOST,
    http::header::AUTHORIZATION,
    http::header::WWW_AUTHENTICATE,
    http::header::PROXY_AUTHENTICATE,
    http::header::PROXY_AUTHORIZATION,
    http::header::CONTENT_ENCODING,
    http::header::CONTENT_TYPE,
    http::header::CONTENT_RANGE,
  ] {
    headers.remove(name);
  }
}

/// RFC 9114 §4.2: HTTP/3 cookie lines must be joined with a semicolon
/// before entering a generic HTTP application or HTTP/1 hop.
pub(crate) fn join_cookie_headers(headers: &mut http::HeaderMap) {
  if headers.get_all(http::header::COOKIE).iter().count() <= 1 {
    return;
  }
  let mut combined = Vec::new();
  for value in headers.get_all(http::header::COOKIE) {
    if !combined.is_empty() {
      combined.extend_from_slice(b"; ");
    }
    combined.extend_from_slice(value.as_bytes());
  }
  let value = http::HeaderValue::from_bytes(&combined)
    .expect("joined valid cookie fields");
  headers.insert(http::header::COOKIE, value);
}
