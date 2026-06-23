//! Black-box tests for the http_utils module.

use crate::http_utils::{
  append_proxy_status, build_empty_response, build_error_response,
  build_proxy_status_error, build_proxy_status_with_status,
};

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

#[test]
fn test_build_proxy_status_error() {
  let val = build_proxy_status_error("myproxy", "connection_refused");
  assert_eq!(
    val.to_str().unwrap(),
    "myproxy; error=connection_refused"
  );
}

#[test]
fn test_build_proxy_status_with_status() {
  let val = build_proxy_status_with_status("myproxy", 502);
  assert_eq!(val.to_str().unwrap(), "myproxy; received-status=502");
}

#[test]
fn test_build_proxy_status_error_fallback() {
  let val =
    build_proxy_status_error("my\x00proxy", "connection_refused");
  assert_eq!(val.to_str().unwrap(), "neoproxy; error=unknown");
}

#[test]
fn test_append_proxy_status_no_existing() {
  let existing: Option<&http::HeaderValue> = None;
  let new_entry = build_proxy_status_with_status("myproxy", 200);
  let val = append_proxy_status(existing, &new_entry);
  assert_eq!(val.to_str().unwrap(), "myproxy; received-status=200");
}

#[test]
fn test_append_proxy_status_with_existing() {
  let existing =
    build_proxy_status_error("upproxy", "connection_refused");
  let new_entry = build_proxy_status_with_status("myproxy", 502);
  let val = append_proxy_status(Some(&existing), &new_entry);
  assert_eq!(
    val.to_str().unwrap(),
    "upproxy; error=connection_refused, myproxy; received-status=502"
  );
}

#[test]
fn test_append_proxy_status_multi_member() {
  let existing = build_proxy_status_error("proxy-a", "dns_error");
  let mid = build_proxy_status_with_status("proxy-b", 200);
  let val1 = append_proxy_status(Some(&existing), &mid);
  let new_entry = build_proxy_status_with_status("proxy-c", 502);
  let val2 = append_proxy_status(Some(&val1), &new_entry);
  assert_eq!(
    val2.to_str().unwrap(),
    "proxy-a; error=dns_error, proxy-b; received-status=200, proxy-c; \
     received-status=502"
  );
}
