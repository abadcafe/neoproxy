use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::Service;

use super::service_test_support::{
  body_string, make_full_service, make_full_service_with_workers,
  make_req, make_simple_req, write_js_file,
};

// ============== JS Error Handling Tests ==============

#[tokio::test]
async fn test_handler_throws_returns_502() {
  let tmp = TempDir::new().unwrap();
  write_js_file(
    tmp.path(),
    "thrower",
    "export default { async fetch(req) { throw new Error('intentional \
     crash'); } };",
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
    "export default { async fetch(req) { return new Response('ok', { \
     status: 200 }); } };",
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
    "export default { async fetch(req) { return 'not a response'; } };",
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
