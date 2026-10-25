use crate::proxy_status::{
  append_proxy_status, build_proxy_status_error,
  build_proxy_status_with_status,
};

#[test]
fn test_build_proxy_status_quotes_non_token_identifiers() {
  assert_eq!(
    build_proxy_status_with_status("127.0.0.1:8080", 200),
    "\"127.0.0.1:8080\"; received-status=200"
  );
  assert_eq!(
    build_proxy_status_error("id; injected=yes", "dns_error"),
    "\"id; injected=yes\"; error=dns_error"
  );
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
  assert_eq!(
    val.to_str().unwrap(),
    "neoproxy; error=connection_refused"
  );
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

#[test]
fn test_proxy_status_rejects_error_parameter_injection_and_empty_list()
{
  let entry = build_proxy_status_error("proxy", "bad; injected=yes");
  assert_eq!(entry, "proxy; error=unknown");
  assert_eq!(
    append_proxy_status(
      Some(&http::HeaderValue::from_static("")),
      &entry
    ),
    entry
  );
}
