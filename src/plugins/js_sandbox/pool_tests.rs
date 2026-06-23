use super::pool::*;
use crate::plugins::js_sandbox::request::{
  IncomingRequest, SandboxConfig,
};

#[test]
fn test_pool_worker_starts() {
  let pool = SandboxPool::new(1);

  let config = SandboxConfig {
          sandbox_id: "test".to_string(),
          heap_limit_bytes: 128 * 1024 * 1024,
          cpu_limit_us: 5000 * 1000,
          source_code: r#"export default { async fetch(req) { return new Response("ok", { status: 200 }); } };"#.to_string(),
      };
  let request = IncomingRequest {
    method: "GET".to_string(),
    url: "/".to_string(),
    headers: vec![],
    body: vec![],
  };

  let rx = pool.execute(config, request);

  let result = rx.blocking_recv().expect("channel closed");
  let resp = result.expect("sandbox execute failed");
  assert_eq!(resp.status, 200);

  pool.shutdown();
}
