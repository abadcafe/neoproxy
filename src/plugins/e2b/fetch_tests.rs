use super::cache::Update;
use super::fetch::{Api, decode};

#[test]
fn test_decode_policy_headers_and_304() {
  let headers = http::HeaderMap::from_iter([
    (http::header::ETAG, http::HeaderValue::from_static("\"12\"")),
    (
      http::header::HeaderName::from_static("x-policy-ttl"),
      http::HeaderValue::from_static("60"),
    ),
  ]);
  let body = br#"{"sandbox_id":"abc","policy":{}}"#;
  assert!(matches!(
    decode(http::StatusCode::OK, &headers, body, "abc", None).unwrap(),
    Update::Modified { version: 12, .. }
  ));
  assert!(matches!(
    decode(
      http::StatusCode::NOT_MODIFIED,
      &headers,
      b"",
      "abc",
      Some(12)
    )
    .unwrap(),
    Update::Unmodified { version: 12, .. }
  ));
  assert!(
    decode(http::StatusCode::NOT_MODIFIED, &headers, b"", "abc", None)
      .is_err()
  );
  assert!(
    decode(
      http::StatusCode::NOT_MODIFIED,
      &headers,
      b"",
      "abc",
      Some(11)
    )
    .is_err()
  );
  assert!(
    decode(http::StatusCode::OK, &headers, body, "other", None)
      .is_err()
  );
  assert!(
    decode(http::StatusCode::BAD_GATEWAY, &headers, body, "abc", None)
      .is_err()
  );
}

#[test]
fn test_decode_rejects_missing_duplicate_invalid_headers() {
  for (etag, ttl) in [
    ("12", "60"),
    ("W/\"12\"", "60"),
    ("\"0\"", "60"),
    ("\"12\"", "0"),
    ("\"12\"", "-1"),
  ] {
    let mut headers = http::HeaderMap::new();
    headers.insert("etag", etag.parse().unwrap());
    headers.insert("x-policy-ttl", ttl.parse().unwrap());
    assert!(
      decode(
        http::StatusCode::OK,
        &headers,
        br#"{"sandbox_id":"abc","policy":{}}"#,
        "abc",
        None
      )
      .is_err()
    );
  }
  assert!(
    decode(
      http::StatusCode::OK,
      &http::HeaderMap::new(),
      b"{}",
      "abc",
      None
    )
    .is_err()
  );
}

#[test]
fn test_new_rejects_invalid_api_url() {
  for url in
    ["/relative", "ftp://api/policy", "http://user:password@api/policy"]
  {
    assert!(Api::new(url, std::time::Duration::from_secs(5)).is_err());
  }
}

#[test]
fn test_new_rejects_unrepresentable_timeout() {
  let _ = rustls::crypto::ring::default_provider().install_default();
  assert!(
    Api::new("http://api/policy", std::time::Duration::MAX).is_err()
  );
}
