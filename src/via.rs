//! module: via
//! responsibility: record the received HTTP version at a proxy hop
//! public operations: append
//! data entities: none
//! tests: via_tests.rs

/// RFC 9110 §7.6.3 permits a pseudonym instead of disclosing hostnames.
pub(crate) fn append(
  headers: &mut http::HeaderMap,
  received: http::Version,
) {
  let value = match received {
    http::Version::HTTP_09 => "0.9 neoproxy",
    http::Version::HTTP_10 => "1.0 neoproxy",
    http::Version::HTTP_2 => "2 neoproxy",
    http::Version::HTTP_3 => "3 neoproxy",
    _ => "1.1 neoproxy",
  };
  headers
    .append(http::header::VIA, http::HeaderValue::from_static(value));
}
