//! module: hop_headers
//! responsibilities: normalize fields crossing an HTTP hop
//! public operations: strip_connection_headers, strip_trailer_headers,
//! join_cookie_headers, TrailerPolicy::apply
//! data entities: TrailerPolicy
//! tests: hop_headers_tests.rs

/// Strip connection-specific fields before forwarding or H3 encoding.
///
/// RFC 9110 §7.6.1 requires removing Connection and every field it
/// nominates. Proxy authentication is a separate hop policy: in
/// particular, a locally generated 407 must retain its challenge.
pub(crate) fn strip_connection_headers(
  headers: &mut http::HeaderMap,
) -> TrailerPolicy {
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
  let policy = TrailerPolicy { connection_fields: connection_tokens };
  if headers.contains_key(http::header::TRAILER) {
    let mut names = Vec::new();
    for name in headers
      .get_all(http::header::TRAILER)
      .iter()
      .filter_map(|value| value.to_str().ok())
      .flat_map(|value| value.split(','))
      .filter_map(|name| {
        name.trim().parse::<http::header::HeaderName>().ok()
      })
    {
      if policy.allows(&name) && !names.contains(&name) {
        names.push(name);
      }
    }
    headers.remove(http::header::TRAILER);
    if !names.is_empty() {
      let declaration = names
        .iter()
        .map(http::header::HeaderName::as_str)
        .collect::<Vec<_>>()
        .join(", ");
      headers.insert(
        http::header::TRAILER,
        declaration.parse().expect("joined valid trailer field names"),
      );
    }
  }
  policy
}

/// The initial Connection options apply to every later trailer frame.
/// Keep this state after removing the initial Connection field.
#[derive(Clone, Default)]
#[must_use = "retain this policy for message trailers; discard only \
              for headers without content"]
pub(crate) struct TrailerPolicy {
  connection_fields: Vec<http::header::HeaderName>,
}

impl TrailerPolicy {
  pub(crate) fn apply(&self, headers: &mut http::HeaderMap) {
    drop(strip_connection_headers(headers));
    let removed = headers
      .keys()
      .filter(|name| !self.allows(name))
      .cloned()
      .collect::<Vec<_>>();
    for name in removed {
      headers.remove(name);
    }
  }

  fn allows(&self, name: &http::header::HeaderName) -> bool {
    !self.connection_fields.contains(name)
      && !matches!(
        name.as_str(),
        "connection"
          | "te"
          | "trailer"
          | "transfer-encoding"
          | "upgrade"
          | "keep-alive"
          | "proxy-connection"
          | "content-length"
          | "host"
          | "authorization"
          | "www-authenticate"
          | "proxy-authenticate"
          | "proxy-authorization"
          | "content-encoding"
          | "content-type"
          | "content-range"
          | "alt-svc"
      )
  }
}

/// Normalize trailers while keeping proxy authentication in the
/// initial header section. This is a field-placement rule, independent
/// of an upstream proxy's authentication policy.
pub(crate) fn strip_trailer_headers(headers: &mut http::HeaderMap) {
  // RFC 9110 §6.5.1: framing, routing, authentication and content
  // interpretation cannot be deferred until after the body.
  TrailerPolicy::default().apply(headers);
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
