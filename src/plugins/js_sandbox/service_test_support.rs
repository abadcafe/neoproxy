use std::path::Path;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::BodyExt;

use super::service::SandboxService;
use crate::http_message::{
  BytesBufBodyWrapper, Request, RequestBody, Response,
};
use crate::plugins::js_sandbox::config::PluginConfig;
use crate::plugins::js_sandbox::pool::SandboxPool;

fn make_plugin_config(source_dir: &Path) -> PluginConfig {
  PluginConfig {
    source_dir: source_dir.to_string_lossy().to_string(),
    worker_threads: 1,
    default_cpu_limit_ms: 5000,
    default_mem_limit_mb: 128,
  }
}

pub(super) fn make_full_service(source_dir: &Path) -> SandboxService {
  let config = make_plugin_config(source_dir);
  let pool = Arc::new(SandboxPool::new(1));
  SandboxService::new(pool, Arc::new(config))
}

pub(super) fn make_full_service_with_workers(
  source_dir: &Path,
  workers: usize,
) -> SandboxService {
  let config = make_plugin_config(source_dir);
  let pool = Arc::new(SandboxPool::new(workers));
  SandboxService::new(pool, Arc::new(config))
}

pub(super) fn make_req(
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

pub(super) fn make_simple_req(sandbox_id: &str) -> Request {
  make_req(Some(sandbox_id), http::Method::GET, "/", &[], &[])
}

pub(super) async fn body_string(resp: Response) -> String {
  let bytes = resp.into_body().collect().await.unwrap().to_bytes();
  String::from_utf8_lossy(&bytes).to_string()
}

pub(super) fn write_js_file(dir: &Path, name: &str, code: &str) {
  std::fs::write(dir.join(format!("{name}.js")), code).unwrap();
}
