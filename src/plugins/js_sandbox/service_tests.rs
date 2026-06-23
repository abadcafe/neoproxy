use std::path::Path;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures::task::noop_waker;
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::Service;

use super::service::*;
use crate::http_utils::{
  BytesBufBodyWrapper, Request, RequestBody, Response,
};
use crate::plugins::js_sandbox::config::PluginConfig;
use crate::plugins::js_sandbox::pool::SandboxPool;

// ============== Test Helpers ==============

fn make_plugin_config(source_dir: &Path) -> PluginConfig {
  PluginConfig {
    source_dir: source_dir.to_string_lossy().to_string(),
    worker_threads: 1,
    default_cpu_limit_ms: 5000,
    default_mem_limit_mb: 128,
  }
}

/// Full service with a real sandbox pool — needed for execution
/// tests.
fn make_full_service(source_dir: &Path) -> SandboxService {
  let config = make_plugin_config(source_dir);
  let pool = Arc::new(SandboxPool::new(1));
  SandboxService::new(pool, Arc::new(config))
}

/// Full service with multiple workers — for concurrent tests.
fn make_full_service_with_workers(
  source_dir: &Path,
  workers: usize,
) -> SandboxService {
  let config = make_plugin_config(source_dir);
  let pool = Arc::new(SandboxPool::new(workers));
  SandboxService::new(pool, Arc::new(config))
}

fn make_req(
  sandbox_id: Option<&str>,
  method: http::Method,
  uri: &str,
  body: &[u8],
  extra_headers: &[(&str, &str)],
) -> Request {
  let mut builder = http::Request::builder().method(method).uri(uri);
  if let Some(id) = sandbox_id {
    builder = builder.header("sandbox-id", id);
  }
  for (k, v) in extra_headers {
    builder = builder.header(*k, *v);
  }
  let full = http_body_util::Full::new(Bytes::from(body.to_vec()));
  let wrapped = BytesBufBodyWrapper::new(full);
  let req_body = RequestBody::new(wrapped);
  builder.body(req_body).unwrap()
}

fn make_simple_req(sandbox_id: &str) -> Request {
  make_req(Some(sandbox_id), http::Method::GET, "/", &[], &[])
}

async fn body_string(resp: Response) -> String {
  let bytes = resp.into_body().collect().await.unwrap().to_bytes();
  String::from_utf8_lossy(&bytes).to_string()
}

fn write_js_file(dir: &Path, name: &str, code: &str) {
  std::fs::write(dir.join(format!("{name}.js")), code).unwrap();
}

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
    "export default { async fetch(req) { return new Response('ok', \
     { status: 200 }); } };",
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
    "export default { async fetch(req) { return new Response('ok', \
     { status: 200 }); } };",
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
    "export default { async fetch(req) { return new Response('ok', \
     { status: 200 }); } };",
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
    "export default { async fetch(req) { return new Response('ok', \
     { status: 200 }); } };",
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
    "export default { async fetch(req) { return new Response('ok', \
     { status: 200 }); } };",
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
    "export default { async fetch(req) { return new Response(null, \
     { status: 204 }); } };",
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
    "export default { async fetch(req) { return new \
     Response('boom', { status: 500 }); } };",
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
     req.headers.get('x-custom'); return new Response(hdr || \
     'none', { status: 200 }); } };",
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

// ============== JS Error Handling Tests ==============

#[tokio::test]
async fn test_handler_throws_returns_502() {
  let tmp = TempDir::new().unwrap();
  write_js_file(
    tmp.path(),
    "thrower",
    "export default { async fetch(req) { throw new \
     Error('intentional crash'); } };",
  );
  let mut svc = make_full_service(tmp.path());
  let req = make_simple_req("thrower");
  let resp = svc.call(req).await.unwrap();
  assert_eq!(resp.status(), 502);
  // The bridge script catches the error and puts it in
  // x-sandbox-error header
  assert!(resp.headers().contains_key("x-sandbox-error"));
}

#[tokio::test]
async fn test_handler_without_fetch_export_returns_502() {
  let tmp = TempDir::new().unwrap();
  write_js_file(
    tmp.path(),
    "no_fetch",
    "export default { }; // no fetch function",
  );
  let mut svc = make_full_service(tmp.path());
  let req = make_simple_req("no_fetch");
  let resp = svc.call(req).await.unwrap();
  assert_eq!(resp.status(), 502);
  assert!(resp.headers().contains_key("x-sandbox-error"));
}

#[tokio::test]
async fn test_handler_without_default_export_returns_502() {
  let tmp = TempDir::new().unwrap();
  write_js_file(
    tmp.path(),
    "no_export",
    "export const x = 1; // no default export",
  );
  let mut svc = make_full_service(tmp.path());
  let req = make_simple_req("no_export");
  let resp = svc.call(req).await.unwrap();
  assert_eq!(resp.status(), 502);
  assert!(resp.headers().contains_key("x-sandbox-error"));
}

#[tokio::test]
async fn test_handler_with_syntax_error_returns_502() {
  let tmp = TempDir::new().unwrap();
  write_js_file(
    tmp.path(),
    "bad_syntax",
    "export default { async fetch(req) { return @@@; } };", /* syntax error */
  );
  let mut svc = make_full_service(tmp.path());
  let req = make_simple_req("bad_syntax");
  let resp = svc.call(req).await.unwrap();
  assert_eq!(resp.status(), 502);
}

// ============== Response Body Tests ==============

#[tokio::test]
async fn test_handler_returns_empty_body() {
  let tmp = TempDir::new().unwrap();
  write_js_file(
    tmp.path(),
    "empty_body",
    "export default { async fetch(req) { return new Response('', { \
     status: 200 }); } };",
  );
  let mut svc = make_full_service(tmp.path());
  let req = make_simple_req("empty_body");
  let resp = svc.call(req).await.unwrap();
  assert_eq!(resp.status(), 200);
  let body = resp.into_body().collect().await.unwrap().to_bytes();
  assert!(body.is_empty());
}

#[tokio::test]
async fn test_handler_returns_binary_body() {
  let tmp = TempDir::new().unwrap();
  write_js_file(
    tmp.path(),
    "binary_body",
    r#"export default { async fetch(req) { const arr = new Uint8Array([0, 1, 2, 255, 254, 253]); return new Response(arr, { status: 200 }); } };
"#,
  );
  let mut svc = make_full_service(tmp.path());
  let req = make_simple_req("binary_body");
  let resp = svc.call(req).await.unwrap();
  assert_eq!(resp.status(), 200);
  let body = resp.into_body().collect().await.unwrap().to_bytes();
  assert_eq!(body.as_ref(), &[0u8, 1, 2, 255, 254, 253]);
}

#[tokio::test]
async fn test_handler_returns_large_body() {
  let tmp = TempDir::new().unwrap();
  write_js_file(
    tmp.path(),
    "large_body",
    r#"export default { async fetch(req) { const str = 'x'.repeat(100000); return new Response(str, { status: 200 }); } };
"#,
  );
  let mut svc = make_full_service(tmp.path());
  let req = make_simple_req("large_body");
  let resp = svc.call(req).await.unwrap();
  assert_eq!(resp.status(), 200);
  let body = resp.into_body().collect().await.unwrap().to_bytes();
  assert_eq!(body.len(), 100000);
  assert!(body.iter().all(|&b| b == b'x'));
}

// ============== Concurrent Request Tests ==============

#[tokio::test]
async fn test_sequential_requests_to_same_handler() {
  let tmp = TempDir::new().unwrap();
  write_js_file(
    tmp.path(),
    "concurrent",
    "export default { async fetch(req) { return new Response('ok', \
     { status: 200 }); } };",
  );

  let mut svc = make_full_service_with_workers(tmp.path(), 4);

  for _ in 0..20 {
    let req = make_simple_req("concurrent");
    let resp = svc.call(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(body_string(resp).await, "ok");
  }
}

#[tokio::test]
async fn test_sequential_requests_to_different_handlers() {
  let tmp = TempDir::new().unwrap();
  for i in 0..10 {
    write_js_file(
      tmp.path(),
      &format!("handler_{i}"),
      &format!(
        "export default {{ async fetch(req) {{ return new \
         Response('handler-{i}', {{ status: 200 }}); }} }};"
      ),
    );
  }

  let mut svc = make_full_service_with_workers(tmp.path(), 4);

  for i in 0..10 {
    let id = format!("handler_{i}");
    let req = make_simple_req(&id);
    let resp = svc.call(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(body_string(resp).await, format!("handler-{i}"));
  }
}

// ============== JSON Response Tests ==============

#[tokio::test]
async fn test_handler_returns_json() {
  let tmp = TempDir::new().unwrap();
  write_js_file(
    tmp.path(),
    "json_resp",
    r#"export default { async fetch(req) { const data = { hello: 'world', count: 42 }; return new Response(JSON.stringify(data), { status: 200, headers: { 'content-type': 'application/json' } }); } };
"#,
  );
  let mut svc = make_full_service(tmp.path());
  let req = make_simple_req("json_resp");
  let resp = svc.call(req).await.unwrap();
  assert_eq!(resp.status(), 200);
  assert_eq!(
    resp.headers().get("content-type").unwrap().to_str().unwrap(),
    "application/json"
  );
  assert_eq!(
    body_string(resp).await,
    r#"{"hello":"world","count":42}"#
  );
}

// ============== Outbound fetch Tests ==============

#[tokio::test]
async fn test_handler_makes_outbound_fetch() {
  // Start a local HTTP server for the sandbox to fetch
  use bytes::Bytes;
  use http_body_util::Full;
  use hyper_util::rt::TokioIo;
  use tokio::net::TcpListener;

  let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let addr = listener.local_addr().unwrap();

  tokio::spawn(async move {
    loop {
      let (stream, _) = listener.accept().await.unwrap();
      let io = TokioIo::new(stream);
      let svc = hyper::service::service_fn(|_req| async {
        Ok::<_, hyper::Error>(
          hyper::Response::builder()
            .status(200)
            .header("content-type", "text/plain")
            .body(Full::new(Bytes::from("from-upstream")))
            .unwrap(),
        )
      });
      if let Err(e) = hyper::server::conn::http1::Builder::new()
        .serve_connection(io, svc)
        .await
      {
        eprintln!("test server connection error: {e}");
      }
    }
  });

  let tmp = TempDir::new().unwrap();
  let upstream_url = format!("http://127.0.0.1:{}", addr.port());
  write_js_file(
    tmp.path(),
    "fetch_upstream",
    &format!(
      r#"export default {{ async fetch(req) {{ try {{ const resp = await fetch('{upstream_url}'); const body = await resp.text(); return new Response(body, {{ status: resp.status }}); }} catch(e) {{ return new Response(String(e), {{ status: 502 }}); }} }} }};
"#
    ),
  );

  let mut svc = make_full_service(tmp.path());
  let req = make_simple_req("fetch_upstream");
  let resp = svc.call(req).await.unwrap();
  let status = resp.status();
  let body = body_string(resp).await;
  if status != 200 {
    eprintln!("outbound fetch test: status={}, body={}", status, body);
  }
  assert_eq!(status, 200);
  assert_eq!(body, "from-upstream");
}

// ============== Non-ASCII Content Tests ==============

#[tokio::test]
async fn test_handler_returns_unicode_body() {
  let tmp = TempDir::new().unwrap();
  write_js_file(
    tmp.path(),
    "unicode",
    r#"export default { async fetch(req) { return new Response('你好世界 🌍', { status: 200, headers: { 'content-type': 'text/plain; charset=utf-8' } }); } };
"#,
  );
  let mut svc = make_full_service(tmp.path());
  let req = make_simple_req("unicode");
  let resp = svc.call(req).await.unwrap();
  assert_eq!(resp.status(), 200);
  let body = resp.into_body().collect().await.unwrap().to_bytes();
  assert_eq!(std::str::from_utf8(&body).unwrap(), "你好世界 🌍");
}

// ============== Content-Type Tests ==============

#[tokio::test]
async fn test_json_parsing_in_handler() {
  let tmp = TempDir::new().unwrap();
  write_js_file(
    tmp.path(),
    "json_parse",
    r#"export default { async fetch(req) { const data = await req.json(); return new Response(data.name, { status: 200 }); } };
"#,
  );
  let mut svc = make_full_service(tmp.path());
  let req = make_req(
    Some("json_parse"),
    http::Method::POST,
    "/",
    br#"{"name":"test-user"}"#,
    &[("content-type", "application/json")],
  );
  let resp = svc.call(req).await.unwrap();
  assert_eq!(resp.status(), 200);
  assert_eq!(body_string(resp).await, "test-user");
}

// ============== JS Error Handling - More Cases ==============

#[tokio::test]
async fn test_handler_returning_non_response_returns_502() {
  let tmp = TempDir::new().unwrap();
  write_js_file(
    tmp.path(),
    "bad_return",
    "export default { async fetch(req) { return 'not a response'; } \
     };",
  );
  let mut svc = make_full_service(tmp.path());
  let req = make_simple_req("bad_return");
  let resp = svc.call(req).await.unwrap();
  assert_eq!(resp.status(), 502);
  assert!(resp.headers().contains_key("x-sandbox-error"));
}

#[tokio::test]
async fn test_handler_returning_undefined_returns_502() {
  let tmp = TempDir::new().unwrap();
  write_js_file(
    tmp.path(),
    "undefined_return",
    "export default { async fetch(req) { return undefined; } };",
  );
  let mut svc = make_full_service(tmp.path());
  let req = make_simple_req("undefined_return");
  let resp = svc.call(req).await.unwrap();
  assert_eq!(resp.status(), 502);
  assert!(resp.headers().contains_key("x-sandbox-error"));
}

#[tokio::test]
async fn test_empty_source_file_returns_502() {
  let tmp = TempDir::new().unwrap();
  write_js_file(tmp.path(), "empty", " // empty file ");
  let mut svc = make_full_service(tmp.path());
  let req = make_simple_req("empty");
  let resp = svc.call(req).await.unwrap();
  assert_eq!(resp.status(), 502);
  assert!(resp.headers().contains_key("x-sandbox-error"));
}
