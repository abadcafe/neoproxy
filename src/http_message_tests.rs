//! Black-box tests for the http_message module.

use crate::http_message::{build_empty_response, build_error_response};

#[test]
fn test_build_empty_response_ok() {
  let resp = build_empty_response(http::StatusCode::OK);
  assert_eq!(resp.status(), http::StatusCode::OK);
}

#[test]
fn test_build_error_response_with_message() {
  let resp =
    build_error_response(http::StatusCode::BAD_REQUEST, "test error");
  assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
}
