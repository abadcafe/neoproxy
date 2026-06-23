use super::sandbox::*;
use crate::plugins::js_sandbox::request::{
  IncomingRequest, SandboxConfig,
};

fn make_sandbox_config(source: &str) -> SandboxConfig {
  SandboxConfig {
    sandbox_id: "test".to_string(),
    heap_limit_bytes: 128 * 1024 * 1024,
    cpu_limit_us: 5000 * 1000,
    source_code: source.to_string(),
  }
}

#[test]
fn test_sandbox_simple_response() {
  let config = make_sandbox_config(
    r#"export default { async fetch(req) { return new Response("hello", { status: 200 }); } };"#,
  );
  let sandbox = Sandbox::new(config).expect("sandbox creation failed");
  let request = IncomingRequest {
    method: "GET".to_string(),
    url: "/".to_string(),
    headers: vec![],
    body: vec![],
  };
  let resp = sandbox.execute(request).expect("sandbox execute failed");
  assert_eq!(resp.status, 200);
  assert_eq!(String::from_utf8_lossy(&resp.body), "hello");
}

#[test]
fn test_sandbox_error_response() {
  let config = make_sandbox_config(
    r#"export default { async fetch(req) { throw new Error("boom"); } };"#,
  );
  let sandbox = Sandbox::new(config).expect("sandbox creation failed");
  let request = IncomingRequest {
    method: "GET".to_string(),
    url: "/".to_string(),
    headers: vec![],
    body: vec![],
  };
  let resp = sandbox.execute(request).expect("sandbox execute failed");
  assert_eq!(resp.status, 502);
  assert!(resp.headers.iter().any(|(k, _)| k == "x-sandbox-error"));
}
