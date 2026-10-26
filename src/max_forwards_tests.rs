//! Black-box contracts for the proxy forwarding limit.
use crate::max_forwards::apply;

#[test]
fn test_apply_stops_zero_options_and_trace_locally() {
  for (method, status) in [("OPTIONS", 204), ("TRACE", 405)] {
    let mut request = http::Request::builder()
      .method(method)
      .header("max-forwards", "000")
      .body(())
      .unwrap();
    let response = apply(&mut request).unwrap();
    assert_eq!(response.status().as_u16(), status);
    if method == "TRACE" {
      assert!(response.headers().contains_key("allow"));
    }
  }
}

#[test]
fn test_apply_decrements_and_caps_valid_decimal_values() {
  for (input, expected) in [
    ("1", "0"),
    ("002", "1"),
    ("256", "255"),
    ("99999999999999999999999999999999", "255"),
  ] {
    let mut request = http::Request::builder()
      .method("OPTIONS")
      .header("max-forwards", input)
      .body(())
      .unwrap();
    assert!(apply(&mut request).is_none());
    assert_eq!(request.headers()["max-forwards"], expected);
  }
}

#[test]
fn test_apply_rejects_ambiguous_or_invalid_limits() {
  for input in ["", "-1", "+1", "1, 2", "one"] {
    let mut request = http::Request::builder()
      .method("TRACE")
      .header("max-forwards", input)
      .body(())
      .unwrap();
    assert_eq!(
      apply(&mut request).unwrap().status(),
      http::StatusCode::BAD_REQUEST
    );
  }
  let mut request = http::Request::builder()
    .method("OPTIONS")
    .header("max-forwards", "1")
    .header("max-forwards", "2")
    .body(())
    .unwrap();
  assert_eq!(
    apply(&mut request).unwrap().status(),
    http::StatusCode::BAD_REQUEST
  );
}

#[test]
fn test_apply_ignores_other_methods_and_absent_limits() {
  for method in ["GET", "POST", "OPTIONS", "TRACE"] {
    let mut request =
      http::Request::builder().method(method).body(()).unwrap();
    assert!(apply(&mut request).is_none());
  }
  let mut request = http::Request::builder()
    .header("max-forwards", "invalid")
    .body(())
    .unwrap();
  assert!(apply(&mut request).is_none());
  assert_eq!(request.headers()["max-forwards"], "invalid");
}
