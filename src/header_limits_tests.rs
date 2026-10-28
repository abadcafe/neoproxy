//! Public contracts for incoming header budgets.
use crate::header_limits::{RequestLimits, ResponseLimits};

#[test]
fn test_defaults_use_100_fields_and_32_kib() {
  let request = RequestLimits::default().limits();
  let response = ResponseLimits::default().limits();
  assert_eq!(request.count(), 100);
  assert_eq!(request.bytes(), 32 * 1024);
  assert_eq!(response.count(), 100);
  assert_eq!(response.bytes(), 32 * 1024);
}

#[test]
fn test_limits_reject_zero_and_unrepresentable_size() {
  for yaml in [
    "max_request_headers: 0",
    "max_request_header_size: 0",
    "max_request_header_size: 4GiB",
  ] {
    assert!(serde_yaml::from_str::<RequestLimits>(yaml).is_err());
  }
}

#[test]
fn test_count_includes_repeated_fields() {
  let policy: ResponseLimits = serde_yaml::from_str(
    "max_response_headers: 1\nmax_response_header_size: 2KiB",
  )
  .unwrap();
  let mut headers = http::HeaderMap::new();
  headers.append("set-cookie", "a=1".parse().unwrap());
  assert!(policy.limits().accepts(&headers));
  headers.append("set-cookie", "b=2".parse().unwrap());
  assert!(!policy.limits().accepts(&headers));
  assert_eq!(policy.limits().bytes(), 2048);
}
