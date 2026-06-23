use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::Result;
use http_body_util::BodyExt;
use tracing::{error, warn};

use crate::http_utils::{
  BytesBufBodyWrapper, Request, Response, ResponseBody,
};
use crate::plugins::js_sandbox::config::PluginConfig;
use crate::plugins::js_sandbox::pool::SandboxPool;
use crate::plugins::js_sandbox::request::{
  IncomingRequest, SandboxConfig,
};

#[derive(Clone)]
pub struct SandboxService {
  pool: Option<Arc<SandboxPool>>,
  config: Arc<PluginConfig>,
}

impl SandboxService {
  pub fn new(
    pool: Arc<SandboxPool>,
    config: Arc<PluginConfig>,
  ) -> Self {
    Self { pool: Some(pool), config }
  }
}

impl tower::Service<Request> for SandboxService {
  type Error = anyhow::Error;
  type Future = Pin<Box<dyn Future<Output = Result<Response>>>>;
  type Response = Response;

  fn poll_ready(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<Result<(), Self::Error>> {
    cx.waker().wake_by_ref();
    Poll::Ready(Ok(()))
  }

  fn call(&mut self, req: Request) -> Self::Future {
    let pool = self.pool.clone();
    let config = self.config.clone();

    Box::pin(async move {
      let (parts, body) = req.into_parts();

      // Extract sandbox parameters from headers
      let sandbox_id = parts
        .headers
        .get("sandbox-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

      let sandbox_id = match sandbox_id {
        Some(id) => id,
        None => {
          warn!("request missing sandbox-id header");
          return Ok(make_error_response(
            400,
            "missing sandbox-id header",
          ));
        }
      };

      let mem_limit_mb: u64 = parts
        .headers
        .get("sandbox-mem")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(config.default_mem_limit_mb);

      let cpu_limit_ms: u64 = parts
        .headers
        .get("sandbox-cpu")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(config.default_cpu_limit_ms);

      // Read source code
      let source_dir = PathBuf::from(&config.source_dir);
      let source_path = source_dir.join(format!("{sandbox_id}.js"));
      let source_code = match std::fs::read_to_string(&source_path) {
        Ok(code) => code,
        Err(e) => {
          error!(
            "failed to read source {}: {e}",
            source_path.display()
          );
          return Ok(make_error_response(404, "sandbox not found"));
        }
      };

      // Read request body
      let body_bytes = body.collect().await?.to_bytes();
      let headers: Vec<(String, String)> = parts
        .headers
        .iter()
        .filter_map(|(k, v)| {
          v.to_str()
            .ok()
            .map(|s| (k.as_str().to_string(), s.to_string()))
        })
        .collect();

      let sandbox_config = SandboxConfig {
        sandbox_id: sandbox_id.clone(),
        heap_limit_bytes: (mem_limit_mb * 1024 * 1024) as usize,
        cpu_limit_us: (cpu_limit_ms * 1000) as u32,
        source_code,
      };

      let incoming = IncomingRequest {
        method: parts.method.to_string(),
        url: parts.uri.to_string(),
        headers,
        body: body_bytes.to_vec(),
      };

      let pool = match pool {
        Some(p) => p,
        None => {
          return Ok(make_error_response(503, "sandbox unavailable"));
        }
      };

      let rx = pool.execute(sandbox_config, incoming);

      match rx.await {
        Ok(Ok(resp)) => Ok(make_response(resp)),
        Ok(Err(e)) => {
          error!("sandbox error for {sandbox_id}: {e}");
          Ok(make_error_response(502, "sandbox execution error"))
        }
        Err(_) => {
          error!("sandbox channel closed for {sandbox_id}");
          Ok(make_error_response(503, "sandbox unavailable"))
        }
      }
    })
  }
}

fn make_response(
  resp: crate::plugins::js_sandbox::request::OutgoingResponse,
) -> Response {
  let body_bytes = resp.body;
  let full = http_body_util::Full::new(body_bytes.into());
  let bytes_buf = BytesBufBodyWrapper::new(full);
  let resp_body = ResponseBody::new(bytes_buf);

  let mut builder = http::Response::builder().status(resp.status);
  for (k, v) in resp.headers {
    if let Ok(name) = http::header::HeaderName::from_bytes(k.as_bytes())
    {
      if let Ok(val) = http::header::HeaderValue::from_str(&v) {
        builder = builder.header(name, val);
      }
    }
  }

  builder.body(resp_body).unwrap()
}

fn make_error_response(status: u16, message: &str) -> Response {
  let full =
    http_body_util::Full::new(bytes::Bytes::from(message.to_string()));
  let bytes_buf = BytesBufBodyWrapper::new(full);
  let resp_body = ResponseBody::new(bytes_buf);
  http::Response::builder().status(status).body(resp_body).unwrap()
}
