//! Black-box tests for error_response module.

use crate::listeners::error_response::{
  build_403_forbidden, build_404_response,
};

#[test]
fn test_build_403_forbidden_status() {
  let resp = build_403_forbidden("forbidden");
  assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
}

#[test]
fn test_build_403_forbidden_content_type() {
  let resp = build_403_forbidden("forbidden");
  assert_eq!(
    resp.headers().get(http::header::CONTENT_TYPE).unwrap(),
    "text/plain"
  );
}

#[test]
fn test_build_403_forbidden_empty_message() {
  let resp = build_403_forbidden("");
  assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
}

#[test]
fn test_build_404_response_status() {
  let resp = build_404_response();
  assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
}

#[test]
fn test_build_404_response_no_content_type() {
  let resp = build_404_response();
  assert!(resp.headers().get(http::header::CONTENT_TYPE).is_none());
}
