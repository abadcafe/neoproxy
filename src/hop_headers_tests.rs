use crate::hop_headers::strip_connection_headers;

#[test]
fn test_strip_connection_headers() {
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
  headers
    .insert(http::header::CONTENT_TYPE, "text/plain".parse().unwrap());

  drop(strip_connection_headers(&mut headers));

  assert!(headers.get(http::header::CONNECTION).is_none());
  assert!(
    headers
      .get(http::header::HeaderName::from_static("keep-alive"))
      .is_none()
  );
  assert_eq!(
    headers[http::header::PROXY_AUTHORIZATION],
    "Basic abc123"
  );
  assert!(headers.get(http::header::CONTENT_TYPE).is_some());
}

#[test]
fn test_strip_connection_headers_connection_tokens() {
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
  headers
    .insert(http::header::CONTENT_TYPE, "text/plain".parse().unwrap());

  drop(strip_connection_headers(&mut headers));

  assert!(headers.get(http::header::CONNECTION).is_none());
  assert!(
    headers
      .get(http::header::HeaderName::from_static("x-custom-hop"))
      .is_none()
  );
  assert!(headers.get(http::header::CONTENT_TYPE).is_some());
}

#[test]
fn test_strip_connection_headers_all_connection_lines() {
  let mut headers = http::HeaderMap::new();
  headers.append(http::header::CONNECTION, "x-first".parse().unwrap());
  headers.append(http::header::CONNECTION, "x-second".parse().unwrap());
  headers.insert("x-first", "secret".parse().unwrap());
  headers.insert("x-second", "secret".parse().unwrap());
  drop(strip_connection_headers(&mut headers));
  assert!(headers.is_empty());
}

#[test]
fn test_strip_connection_headers_preserves_proxy_auth_challenges() {
  let mut headers = http::HeaderMap::new();
  headers.append(
    http::header::PROXY_AUTHENTICATE,
    "Basic realm=\"proxy\"".parse().unwrap(),
  );
  headers.append(
    http::header::PROXY_AUTHENTICATE,
    "Digest realm=\"proxy\", nonce=\"test\"".parse().unwrap(),
  );
  headers.insert(http::header::CONNECTION, "close".parse().unwrap());
  drop(strip_connection_headers(&mut headers));
  assert_eq!(
    headers.get_all(http::header::PROXY_AUTHENTICATE).iter().count(),
    2
  );
  assert_eq!(
    headers[http::header::PROXY_AUTHENTICATE],
    "Basic realm=\"proxy\""
  );
  assert!(!headers.contains_key(http::header::CONNECTION));
}

#[test]
fn test_strip_trailer_headers_drops_proxy_auth_fields() {
  let mut trailers = http::HeaderMap::new();
  trailers.insert(
    http::header::PROXY_AUTHENTICATE,
    "Basic realm=\"proxy\"".parse().unwrap(),
  );
  trailers.insert(
    http::header::PROXY_AUTHORIZATION,
    "Basic secret".parse().unwrap(),
  );
  trailers.insert("x-checksum", "complete".parse().unwrap());
  crate::hop_headers::strip_trailer_headers(&mut trailers);
  assert!(!trailers.contains_key(http::header::PROXY_AUTHENTICATE));
  assert!(!trailers.contains_key(http::header::PROXY_AUTHORIZATION));
  assert_eq!(trailers["x-checksum"], "complete");
}

#[test]
fn test_join_cookie_headers_preserves_all_cookie_pairs() {
  let mut headers = http::HeaderMap::new();
  headers.append(http::header::COOKIE, "a=1".parse().unwrap());
  headers.append(http::header::COOKIE, "b=2".parse().unwrap());
  crate::hop_headers::join_cookie_headers(&mut headers);
  assert_eq!(headers[http::header::COOKIE], "a=1; b=2");
  assert_eq!(headers.get_all(http::header::COOKIE).iter().count(), 1);
}

#[test]
fn test_strip_trailer_headers_removes_framing_routing_and_authentication()
 {
  let mut trailers = http::HeaderMap::new();
  for name in [
    "content-length",
    "host",
    "authorization",
    "www-authenticate",
    "content-encoding",
    "content-type",
    "content-range",
    "alt-svc",
  ] {
    trailers.insert(
      http::HeaderName::from_static(name),
      "forbidden".parse().unwrap(),
    );
  }
  trailers.insert("digest", "sha-256=value".parse().unwrap());
  crate::hop_headers::strip_trailer_headers(&mut trailers);
  assert_eq!(trailers.len(), 1);
  assert!(trailers.contains_key("digest"));
}

#[test]
fn test_strip_connection_headers_keeps_legal_trailer_declarations() {
  let mut headers = http::HeaderMap::new();
  headers.insert("connection", "x-private".parse().unwrap());
  headers.insert(
    "trailer",
    "x-checksum, X-Private, content-length".parse().unwrap(),
  );
  drop(strip_connection_headers(&mut headers));
  assert_eq!(headers["trailer"], "x-checksum");
}

#[test]
fn test_trailer_policy_removes_initial_connection_options_from_later_frames()
 {
  let mut headers = http::HeaderMap::new();
  headers.insert("connection", "x-private".parse().unwrap());
  let policy = strip_connection_headers(&mut headers);
  let mut trailers = http::HeaderMap::new();
  trailers.insert("x-private", "secret".parse().unwrap());
  trailers.insert("x-checksum", "complete".parse().unwrap());
  trailers.insert("content-length", "7".parse().unwrap());
  policy.apply(&mut trailers);
  assert_eq!(trailers.len(), 1);
  assert_eq!(trailers["x-checksum"], "complete");
}
