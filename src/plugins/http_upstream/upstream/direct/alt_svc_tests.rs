use std::time::Duration;

use http::{HeaderMap, HeaderValue};
use tokio::time::Instant;

use super::alt_svc::AltServices;
use super::origin::{Origin, WireProtocol};

fn origin(value: &str) -> Origin {
  Origin::from_uri(&value.parse().unwrap()).unwrap()
}
fn headers(value: &str) -> HeaderMap {
  let mut headers = HeaderMap::new();
  headers.insert("alt-svc", HeaderValue::from_str(value).unwrap());
  headers
}

#[test]
fn test_observe_caches_routes_by_origin_and_preserves_order() {
  let mut cache = AltServices::default();
  let now = Instant::now();
  let source = origin("https://example.com/path");
  cache.observe(
    &source,
    &headers("h3=\":8443\"; ma=60, h2=\"alt.example:443\""),
    now,
  );
  let routes = cache.routes(&source, now);
  assert_eq!(routes.len(), 2);
  assert_eq!(routes[0].host, "example.com");
  assert_eq!(routes[0].port, 8443);
  assert_eq!(routes[0].protocol, WireProtocol::Http3);
  assert_eq!(routes[1].host, "alt.example");
  assert!(
    cache.routes(&origin("https://other.example/"), now).is_empty()
  );
  assert!(
    cache.routes(&origin("https://example.com:8443/"), now).is_empty()
  );
  assert_eq!(
    cache.routes(&source, now + Duration::from_secs(61)).len(),
    1
  );
}

#[test]
fn test_observe_handles_clear_zero_age_age_and_replacement() {
  let mut cache = AltServices::default();
  let now = Instant::now();
  let source = origin("https://example.com/");
  let mut response = headers("h3=\":443\"; ma=\"60\"");
  response.insert("age", HeaderValue::from_static("50"));
  cache.observe(&source, &response, now);
  assert_eq!(cache.routes(&source, now).len(), 1);
  assert!(
    cache.routes(&source, now + Duration::from_secs(10)).is_empty()
  );
  for value in ["h3=\":443\"; ma=0", "clear"] {
    cache.observe(&source, &headers("h3=\":443\""), now);
    cache.observe(&source, &headers(value), now);
    assert!(cache.routes(&source, now).is_empty());
  }
  let mut response = headers("clear");
  response.append("alt-svc", HeaderValue::from_static("h3=\":443\""));
  cache.observe(&source, &response, now);
  assert!(cache.routes(&source, now).is_empty());
}

#[test]
fn test_observe_parses_quoted_extensions_ipv6_and_multiple_fields() {
  let mut cache = AltServices::default();
  let now = Instant::now();
  let source = origin("https://example.com/");
  let mut response =
    headers("h3=\"[::1]:443\"; extension=\"a,b;c=\\\"x\"; ma=30");
  response.append(
    "alt-svc",
    HeaderValue::from_static("h2=\":8443\"; persist=1"),
  );
  cache.observe(&source, &response, now);
  let routes = cache.routes(&source, now);
  assert_eq!(routes.len(), 2);
  assert_eq!(routes[0].host, "::1");
}

#[test]
fn test_observe_rejects_unusable_or_malformed_advertisements() {
  let source = origin("https://example.com/");
  for value in [
    "h3=:443",
    "h3=\":0\"",
    "h3=\"user@host:443\"",
    "h3=\":443\"; ma=-1",
    "h3=\":443\"; ma=xyz",
    "h3=\":443\"; ma=1; ma=2",
    "h3-29=\":443\"",
    "h3=\":443\"; ma=\"unterminated",
  ] {
    let mut cache = AltServices::default();
    cache.observe(&source, &headers(value), Instant::now());
    assert!(
      cache.routes(&source, Instant::now()).is_empty(),
      "{value}"
    );
  }
}

#[test]
fn test_observe_does_not_learn_from_cleartext_or_connection_fields() {
  let mut cache = AltServices::default();
  let now = Instant::now();
  let plain = origin("http://example.com/");
  cache.observe(&plain, &headers("h3=\":443\""), now);
  assert!(cache.routes(&plain, now).is_empty());
  let secure = origin("https://example.com/");
  let mut response = headers("h3=\":443\"");
  response.insert("connection", HeaderValue::from_static("Alt-Svc"));
  cache.observe(&secure, &response, now);
  assert!(cache.routes(&secure, now).is_empty());
}

#[test]
fn test_invalidate_removes_misdirected_origin_routes() {
  let mut cache = AltServices::default();
  let source = origin("https://example.com/");
  cache.observe(&source, &headers("h3=\":443\""), Instant::now());
  cache.invalidate(&source);
  assert!(cache.routes(&source, Instant::now()).is_empty());
}

#[test]
fn test_observe_saturates_unbounded_decimal_lifetimes_and_age() {
  let mut cache = AltServices::default();
  let source = origin("https://example.com/");
  let now = Instant::now();
  let mut response =
    headers("h3=\":443\"; ma=999999999999999999999999999999");
  cache.observe(&source, &response, now);
  assert_eq!(
    cache.routes(&source, now + Duration::from_secs(86400)).len(),
    1
  );
  response.insert(
    "age",
    HeaderValue::from_static("999999999999999999999999999999"),
  );
  cache.observe(&source, &response, now);
  assert!(cache.routes(&source, now).is_empty());
}

#[test]
fn test_observe_refresh_at_capacity_preserves_other_origins() {
  let mut cache = AltServices::default();
  let now = Instant::now();
  for index in 0..1024 {
    cache.observe(
      &origin(&format!("https://host{index}.test/")),
      &headers("h3=\":443\""),
      now,
    );
  }
  cache.observe(
    &origin("https://host0.test/"),
    &headers("h3=\":8443\""),
    now,
  );
  assert_eq!(
    cache.routes(&origin("https://host1.test/"), now).len(),
    1
  );
  assert_eq!(
    cache.routes(&origin("https://host0.test/"), now)[0].port,
    8443
  );
}
