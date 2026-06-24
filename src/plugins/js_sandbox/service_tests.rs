use std::task::{Context, Poll};

use futures::task::noop_waker;
use tempfile::TempDir;
use tower::Service;

use super::service_test_support::{
  body_string, make_full_service, make_req, make_simple_req,
  write_js_file,
};

// ============== poll_ready Tests ==============

#[test]
fn test_poll_ready_returns_ready() {
  let tmp = TempDir::new().unwrap();
  let mut svc = make_full_service(tmp.path());
  let waker = noop_waker();
  let mut cx = Context::from_waker(&waker);
  let result = Service::poll_ready(&mut svc, &mut cx);
  assert!(matches!(result, Poll::Ready(Ok(()))));
}

#[test]
fn test_poll_ready_is_idempotent() {
  let tmp = TempDir::new().unwrap();
  let mut svc = make_full_service(tmp.path());
  let waker = noop_waker();
  for _ in 0..10 {
    let mut cx = Context::from_waker(&waker);
    let result = Service::poll_ready(&mut svc, &mut cx);
    assert!(matches!(result, Poll::Ready(Ok(()))));
  }
}

// ============== Error Path Tests ==============

#[tokio::test]
async fn test_missing_sandbox_id_header_returns_400() {
  let tmp = TempDir::new().unwrap();
  let mut svc = make_full_service(tmp.path());
  let req = make_req(None, http::Method::GET, "/", &[], &[]);
  let resp = svc.call(req).await.unwrap();
  assert_eq!(resp.status(), 400);
  assert_eq!(body_string(resp).await, "missing sandbox-id header");
}

#[tokio::test]
async fn test_empty_sandbox_id_returns_404() {
  let tmp = TempDir::new().unwrap();
  let mut svc = make_full_service(tmp.path());
  let req = make_req(Some(""), http::Method::GET, "/", &[], &[]);
  let resp = svc.call(req).await.unwrap();
  assert_eq!(resp.status(), 404);
  assert_eq!(body_string(resp).await, "sandbox not found");
}

#[tokio::test]
async fn test_nonexistent_sandbox_file_returns_404() {
  let tmp = TempDir::new().unwrap();
  let mut svc = make_full_service(tmp.path());
  let req = make_simple_req("nonexistent_handler");
  let resp = svc.call(req).await.unwrap();
  assert_eq!(resp.status(), 404);
  assert_eq!(body_string(resp).await, "sandbox not found");
}

#[tokio::test]
async fn test_sandbox_id_with_slashes_returns_404() {
  let tmp = TempDir::new().unwrap();
  let mut svc = make_full_service(tmp.path());
  // sandbox-id is an opaque identifier; slashes/dots in it just
  // produce a non-existent file path, which correctly returns
  // 404.
  let req =
    make_req(Some("../etc/passwd"), http::Method::GET, "/", &[], &[]);
  let resp = svc.call(req).await.unwrap();
  assert_eq!(resp.status(), 404);
}

// ============== Default Header Tests ==============

#[tokio::test]
async fn test_default_mem_and_cpu_used_when_headers_missing() {
  let tmp = TempDir::new().unwrap();
  write_js_file(
    tmp.path(),
    "hello",
    "export default { async fetch(req) { return new Response('ok', { \
     status: 200 }); } };",
  );
  let mut svc = make_full_service(tmp.path());
  let req = make_simple_req("hello");
  let resp = svc.call(req).await.unwrap();
  assert_eq!(resp.status(), 200);
  assert_eq!(body_string(resp).await, "ok");
}

#[tokio::test]
async fn test_custom_sandbox_mem_header() {
  let tmp = TempDir::new().unwrap();
  write_js_file(
    tmp.path(),
    "hello",
    "export default { async fetch(req) { return new Response('ok', { \
     status: 200 }); } };",
  );
  let mut svc = make_full_service(tmp.path());
  let req = make_req(
    Some("hello"),
    http::Method::GET,
    "/",
    &[],
    &[("sandbox-mem", "256"), ("sandbox-cpu", "10000")],
  );
  let resp = svc.call(req).await.unwrap();
  assert_eq!(resp.status(), 200);
  assert_eq!(body_string(resp).await, "ok");
}

#[tokio::test]
async fn test_invalid_sandbox_mem_uses_default() {
  let tmp = TempDir::new().unwrap();
  write_js_file(
    tmp.path(),
    "hello",
    "export default { async fetch(req) { return new Response('ok', { \
     status: 200 }); } };",
  );
  let mut svc = make_full_service(tmp.path());
  let req = make_req(
    Some("hello"),
    http::Method::GET,
    "/",
    &[],
    &[("sandbox-mem", "not-a-number")],
  );
  let resp = svc.call(req).await.unwrap();
  assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_invalid_sandbox_cpu_uses_default() {
  let tmp = TempDir::new().unwrap();
  write_js_file(
    tmp.path(),
    "hello",
    "export default { async fetch(req) { return new Response('ok', { \
     status: 200 }); } };",
  );
  let mut svc = make_full_service(tmp.path());
  let req = make_req(
    Some("hello"),
    http::Method::GET,
    "/",
    &[],
    &[("sandbox-cpu", "")],
  );
  let resp = svc.call(req).await.unwrap();
  assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_large_mem_and_cpu_values() {
  let tmp = TempDir::new().unwrap();
  write_js_file(
    tmp.path(),
    "hello",
    "export default { async fetch(req) { return new Response('ok', { \
     status: 200 }); } };",
  );
  let mut svc = make_full_service(tmp.path());
  let req = make_req(
    Some("hello"),
    http::Method::GET,
    "/",
    &[],
    &[("sandbox-mem", "999999999"), ("sandbox-cpu", "999999999")],
  );
  let resp = svc.call(req).await.unwrap();
  assert_eq!(resp.status(), 200);
}

// ============== Response Status Code Tests ==============

#[tokio::test]
async fn test_handler_returns_200() {
  let tmp = TempDir::new().unwrap();
  write_js_file(
    tmp.path(),
    "ok200",
    "export default { async fetch(req) { return new \
     Response('success', { status: 200 }); } };",
  );
  let mut svc = make_full_service(tmp.path());
  let req = make_simple_req("ok200");
  let resp = svc.call(req).await.unwrap();
  assert_eq!(resp.status(), 200);
  assert_eq!(body_string(resp).await, "success");
}

#[tokio::test]
async fn test_handler_returns_201() {
  let tmp = TempDir::new().unwrap();
  write_js_file(
    tmp.path(),
    "created201",
    "export default { async fetch(req) { return new \
     Response('created', { status: 201 }); } };",
  );
  let mut svc = make_full_service(tmp.path());
  let req = make_simple_req("created201");
  let resp = svc.call(req).await.unwrap();
  assert_eq!(resp.status(), 201);
  assert_eq!(body_string(resp).await, "created");
}

#[tokio::test]
async fn test_handler_returns_204_no_content() {
  let tmp = TempDir::new().unwrap();
  write_js_file(
    tmp.path(),
    "no_content",
    "export default { async fetch(req) { return new Response(null, { \
     status: 204 }); } };",
  );
  let mut svc = make_full_service(tmp.path());
  let req = make_simple_req("no_content");
  let resp = svc.call(req).await.unwrap();
  assert_eq!(resp.status(), 204);
  let body = resp.into_body().collect().await.unwrap().to_bytes();
  assert!(body.is_empty());
}

#[tokio::test]
async fn test_handler_returns_400() {
  let tmp = TempDir::new().unwrap();
  write_js_file(
    tmp.path(),
    "bad_req",
    "export default { async fetch(req) { return new Response('bad \
     input', { status: 400 }); } };",
  );
  let mut svc = make_full_service(tmp.path());
  let req = make_simple_req("bad_req");
  let resp = svc.call(req).await.unwrap();
  assert_eq!(resp.status(), 400);
  assert_eq!(body_string(resp).await, "bad input");
}

#[tokio::test]
async fn test_handler_returns_500() {
  let tmp = TempDir::new().unwrap();
  write_js_file(
    tmp.path(),
    "server_err",
    "export default { async fetch(req) { return new Response('boom', \
     { status: 500 }); } };",
  );
  let mut svc = make_full_service(tmp.path());
  let req = make_simple_req("server_err");
  let resp = svc.call(req).await.unwrap();
  assert_eq!(resp.status(), 500);
  assert_eq!(body_string(resp).await, "boom");
}

// ============== HTTP Method Tests ==============

#[tokio::test]
async fn test_handler_receives_get_request() {
  let tmp = TempDir::new().unwrap();
  write_js_file(
    tmp.path(),
    "echo_method",
    "export default { async fetch(req) { return new \
     Response(req.method, { status: 200 }); } };",
  );
  let mut svc = make_full_service(tmp.path());
  let req =
    make_req(Some("echo_method"), http::Method::GET, "/", &[], &[]);
  let resp = svc.call(req).await.unwrap();
  assert_eq!(resp.status(), 200);
  assert_eq!(body_string(resp).await, "GET");
}

#[tokio::test]
async fn test_handler_receives_post_request() {
  let tmp = TempDir::new().unwrap();
  write_js_file(
    tmp.path(),
    "echo_method",
    "export default { async fetch(req) { return new \
     Response(req.method, { status: 200 }); } };",
  );
  let mut svc = make_full_service(tmp.path());
  let req =
    make_req(Some("echo_method"), http::Method::POST, "/", &[], &[]);
  let resp = svc.call(req).await.unwrap();
  assert_eq!(resp.status(), 200);
  assert_eq!(body_string(resp).await, "POST");
}

#[tokio::test]
async fn test_handler_receives_put_request() {
  let tmp = TempDir::new().unwrap();
  write_js_file(
    tmp.path(),
    "echo_method",
    "export default { async fetch(req) { return new \
     Response(req.method, { status: 200 }); } };",
  );
  let mut svc = make_full_service(tmp.path());
  let req =
    make_req(Some("echo_method"), http::Method::PUT, "/", &[], &[]);
  let resp = svc.call(req).await.unwrap();
  assert_eq!(resp.status(), 200);
  assert_eq!(body_string(resp).await, "PUT");
}

#[tokio::test]
async fn test_handler_receives_delete_request() {
  let tmp = TempDir::new().unwrap();
  write_js_file(
    tmp.path(),
    "echo_method",
    "export default { async fetch(req) { return new \
     Response(req.method, { status: 200 }); } };",
  );
  let mut svc = make_full_service(tmp.path());
  let req =
    make_req(Some("echo_method"), http::Method::DELETE, "/", &[], &[]);
  let resp = svc.call(req).await.unwrap();
  assert_eq!(resp.status(), 200);
  assert_eq!(body_string(resp).await, "DELETE");
}

#[tokio::test]
async fn test_handler_receives_patch_request() {
  let tmp = TempDir::new().unwrap();
  write_js_file(
    tmp.path(),
    "echo_method",
    "export default { async fetch(req) { return new \
     Response(req.method, { status: 200 }); } };",
  );
  let mut svc = make_full_service(tmp.path());
  let req =
    make_req(Some("echo_method"), http::Method::PATCH, "/", &[], &[]);
  let resp = svc.call(req).await.unwrap();
  assert_eq!(resp.status(), 200);
  assert_eq!(body_string(resp).await, "PATCH");
}

#[tokio::test]
async fn test_post_body_passes_through_to_handler() {
  let tmp = TempDir::new().unwrap();
  write_js_file(
    tmp.path(),
    "echo_body",
    r#"export default { async fetch(req) { const body = await req.text(); return new Response(body, { status: 200 }); } };
"#,
  );
  let mut svc = make_full_service(tmp.path());
  let req = make_req(
    Some("echo_body"),
    http::Method::POST,
    "/upload",
    b"hello-body-data",
    &[("content-type", "text/plain")],
  );
  let resp = svc.call(req).await.unwrap();
  assert_eq!(resp.status(), 200);
  assert_eq!(body_string(resp).await, "hello-body-data");
}

// ============== Request Header Tests ==============

#[tokio::test]
async fn test_request_headers_pass_through_to_handler() {
  let tmp = TempDir::new().unwrap();
  write_js_file(
    tmp.path(),
    "echo_headers",
    "export default { async fetch(req) { const hdr = \
     req.headers.get('x-custom'); return new Response(hdr || 'none', \
     { status: 200 }); } };",
  );
  let mut svc = make_full_service(tmp.path());
  let req = make_req(
    Some("echo_headers"),
    http::Method::GET,
    "/",
    &[],
    &[("x-custom", "my-header-value")],
  );
  let resp = svc.call(req).await.unwrap();
  assert_eq!(resp.status(), 200);
  assert_eq!(body_string(resp).await, "my-header-value");
}

#[tokio::test]
async fn test_request_uri_passes_through_to_handler() {
  let tmp = TempDir::new().unwrap();
  write_js_file(
    tmp.path(),
    "echo_url",
    "export default { async fetch(req) { return new Response(new \
     URL(req.url).pathname + new URL(req.url).search, { status: 200 \
     }); } };",
  );
  let mut svc = make_full_service(tmp.path());
  let req = make_req(
    Some("echo_url"),
    http::Method::GET,
    "/some/path?q=val",
    &[],
    &[],
  );
  let resp = svc.call(req).await.unwrap();
  assert_eq!(resp.status(), 200);
  assert_eq!(body_string(resp).await, "/some/path?q=val");
}

// ============== Response Header Tests ==============

#[tokio::test]
async fn test_response_headers_from_handler() {
  let tmp = TempDir::new().unwrap();
  write_js_file(
    tmp.path(),
    "custom_header",
    r#"export default { async fetch(req) { return new Response('body', { status: 200, headers: { 'x-response': 'from-sandbox', 'content-type': 'text/plain' } }); } };
"#,
  );
  let mut svc = make_full_service(tmp.path());
  let req = make_simple_req("custom_header");
  let resp = svc.call(req).await.unwrap();
  assert_eq!(resp.status(), 200);
  assert_eq!(
    resp.headers().get("x-response").unwrap().to_str().unwrap(),
    "from-sandbox"
  );
  assert_eq!(
    resp.headers().get("content-type").unwrap().to_str().unwrap(),
    "text/plain"
  );
  assert_eq!(body_string(resp).await, "body");
}

#[tokio::test]
async fn test_handler_with_multiple_response_headers() {
  let tmp = TempDir::new().unwrap();
  write_js_file(
    tmp.path(),
    "multi_hdr",
    r#"export default { async fetch(req) { return new Response('ok', { status: 200, headers: { 'x-a': '1', 'x-b': '2', 'x-c': '3' } }); } };
"#,
  );
  let mut svc = make_full_service(tmp.path());
  let req = make_simple_req("multi_hdr");
  let resp = svc.call(req).await.unwrap();
  assert_eq!(resp.status(), 200);
  assert_eq!(resp.headers().get("x-a").unwrap().to_str().unwrap(), "1");
  assert_eq!(resp.headers().get("x-b").unwrap().to_str().unwrap(), "2");
  assert_eq!(resp.headers().get("x-c").unwrap().to_str().unwrap(), "3");
}
