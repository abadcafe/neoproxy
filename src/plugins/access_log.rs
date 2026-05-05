//! Access log plugin.

pub mod config;
pub mod context;
pub mod formatter;
pub mod writer;

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::OnceLock;
use std::task::{Context, Poll};
use std::time::Instant;

use tokio::sync::mpsc;

use self::config::AccessLogConfig;
use self::context::AccessLogEntry;
use self::writer::AccessLogWriter;
use crate::context::RequestContext;
use crate::http_utils::{Request, Response};
use crate::plugin::Plugin;
use crate::service::{BuildLayer, Layer, Service};

/// Channel capacity
const QUEUE_SIZE: usize = 4096;

/// Log entry sent through channel.
pub struct LogEntry {
  pub entry: AccessLogEntry,
}

/// Global log service (shared across all server threads).
static LOG_SERVICE: OnceLock<LogService> = OnceLock::new();

pub struct LogService {
  tx: mpsc::Sender<LogEntry>,
}

impl LogService {
  fn init() -> &'static Self {
    LOG_SERVICE.get_or_init(|| {
      let (tx, rx) = mpsc::channel(QUEUE_SIZE);

      std::thread::Builder::new()
        .name("access-log-writer".to_string())
        .spawn(move || {
          Self::writer_loop(rx);
        })
        .expect("failed to spawn access-log-writer thread");

      Self { tx }
    })
  }

  fn writer_loop(mut rx: mpsc::Receiver<LogEntry>) {
    let mut wtr = AccessLogWriter::new();

    while let Some(log) = rx.blocking_recv() {
      wtr.write(&log.entry);
      wtr.flush();
    }

    wtr.flush();
  }

  pub fn sender(&self) -> mpsc::Sender<LogEntry> {
    self.tx.clone()
  }
}

/// Access log plugin providing file layer.
pub struct AccessLogPlugin {
  layer_builders: HashMap<&'static str, Box<dyn BuildLayer>>,
}

impl AccessLogPlugin {
  pub fn new() -> Self {
    let file_layer_builder: Box<dyn BuildLayer> = Box::new(|args| {
      let config: AccessLogConfig = serde_yaml::from_value(args)?;
      let service = LogService::init();

      Ok(Layer::new(AccessLogLayer {
        tx: service.sender(),
        context_fields: config.context_fields,
      }))
    });

    Self {
      layer_builders: HashMap::from([("file", file_layer_builder)]),
    }
  }

  pub fn plugin_name() -> &'static str {
    "access_log"
  }

  pub fn create_plugin() -> Box<dyn Plugin> {
    Box::new(Self::new())
  }
}

impl Plugin for AccessLogPlugin {
  fn layer_builder(&self, name: &str) -> Option<&Box<dyn BuildLayer>> {
    self.layer_builders.get(name)
  }
}

/// Layer that creates AccessLogMiddleware instances.
struct AccessLogLayer {
  tx: mpsc::Sender<LogEntry>,
  context_fields: Vec<String>,
}

impl tower::Layer<Service> for AccessLogLayer {
  type Service = Service;

  fn layer(&self, inner: Service) -> Service {
    Service::new(AccessLogMiddleware {
      inner,
      tx: self.tx.clone(),
      context_fields: self.context_fields.clone(),
    })
  }
}

/// Middleware that logs access entries.
struct AccessLogMiddleware {
  inner: Service,
  tx: mpsc::Sender<LogEntry>,
  context_fields: Vec<String>,
}

impl Clone for AccessLogMiddleware {
  fn clone(&self) -> Self {
    Self {
      inner: self.inner.clone(),
      tx: self.tx.clone(),
      context_fields: self.context_fields.clone(),
    }
  }
}

impl tower::Service<Request> for AccessLogMiddleware {
  type Error = anyhow::Error;
  type Future = Pin<Box<dyn Future<Output = anyhow::Result<Response>>>>;
  type Response = Response;

  fn poll_ready(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<anyhow::Result<()>> {
    self.inner.poll_ready(cx)
  }

  fn call(&mut self, req: Request) -> Self::Future {
    let start = Instant::now();
    let tx = self.tx.clone();
    let context_fields = self.context_fields.clone();

    let method = req.method().to_string();
    let target = req.uri().to_string();

    let ctx = req
      .extensions()
      .get::<RequestContext>()
      .cloned()
      .unwrap_or_default();

    let mut inner = self.inner.clone();

    Box::pin(async move {
      let result = inner.call(req).await;

      let entry = build_log_entry(
        &result,
        start,
        ctx,
        context_fields,
        &method,
        &target,
      );

      let _ = tx.try_send(LogEntry { entry });

      match result {
        Ok(response) => Ok(response),
        Err(_) => Ok(crate::http_utils::build_empty_response(
          http::StatusCode::INTERNAL_SERVER_ERROR,
        )),
      }
    })
  }
}

fn build_log_entry(
  result: &anyhow::Result<Response>,
  start: Instant,
  ctx: RequestContext,
  context_fields: Vec<String>,
  method: &str,
  target: &str,
) -> AccessLogEntry {
  use time::OffsetDateTime;

  let time = OffsetDateTime::now_utc();
  let duration_ms = start.elapsed().as_millis() as u64;

  let client_ip = ctx.get("client.ip").unwrap_or_default();
  let client_port: u16 =
    ctx.get("client.port").and_then(|s| s.parse().ok()).unwrap_or(0);
  let server_ip = ctx.get("server.ip").unwrap_or_default();
  let server_port: u16 =
    ctx.get("server.port").and_then(|s| s.parse().ok()).unwrap_or(0);
  let service = ctx.get("service.name").unwrap_or_default();

  let extensions: HashMap<String, String> = context_fields
    .iter()
    .filter_map(|key| ctx.get(key).map(|v| (key.clone(), v)))
    .collect();

  match result {
    Ok(response) => AccessLogEntry {
      time,
      client_ip,
      client_port,
      server_ip,
      server_port,
      method: method.to_string(),
      target: target.to_string(),
      status: response.status().as_u16(),
      duration_ms,
      service,
      err: None,
      extensions,
    },
    Err(e) => AccessLogEntry {
      time,
      client_ip,
      client_port,
      server_ip,
      server_port,
      method: method.to_string(),
      target: target.to_string(),
      status: 500,
      duration_ms,
      service,
      err: Some(e.to_string()),
      extensions,
    },
  }
}

#[cfg(test)]
mod log_service_tests {
  #[test]
  fn test_log_service_init() {
    let service = crate::plugins::access_log::LogService::init();
    let _tx = service.sender();
  }

  #[test]
  fn test_log_service_init_idempotent() {
    let s1 = crate::plugins::access_log::LogService::init();
    let s2 = crate::plugins::access_log::LogService::init();
    // Both point to the same static
    let _ = (s1, s2);
  }
}

#[cfg(test)]
mod build_log_entry_tests {
  use std::time::Instant;

  use super::*;
  use crate::context::RequestContext;

  fn make_ok_result() -> anyhow::Result<Response> {
    Ok(crate::http_utils::build_empty_response(http::StatusCode::OK))
  }

  fn make_err_result() -> anyhow::Result<Response> {
    Err(anyhow::anyhow!("connection refused"))
  }

  #[test]
  fn test_build_log_entry_success_status() {
    let ctx = RequestContext::new();
    let entry = build_log_entry(
      &make_ok_result(),
      Instant::now(),
      ctx,
      vec![],
      "GET",
      "http://example.com/",
    );
    assert_eq!(entry.status, 200);
    assert!(entry.err.is_none());
  }

  #[test]
  fn test_build_log_entry_error_status_and_message() {
    let ctx = RequestContext::new();
    let entry = build_log_entry(
      &make_err_result(),
      Instant::now(),
      ctx,
      vec![],
      "CONNECT",
      "example.com:443",
    );
    assert_eq!(entry.status, 500);
    assert!(entry.err.is_some());
    assert!(entry.err.unwrap().contains("connection refused"));
  }

  #[test]
  fn test_build_log_entry_extracts_client_ip() {
    let ctx = RequestContext::new();
    ctx.insert("client.ip", "192.168.1.100");
    ctx.insert("client.port", "54321");
    let entry = build_log_entry(
      &make_ok_result(),
      Instant::now(),
      ctx,
      vec![],
      "GET",
      "/",
    );
    assert_eq!(entry.client_ip, "192.168.1.100");
    assert_eq!(entry.client_port, 54321);
  }

  #[test]
  fn test_build_log_entry_extracts_server_ip() {
    let ctx = RequestContext::new();
    ctx.insert("server.ip", "10.0.0.1");
    ctx.insert("server.port", "8080");
    let entry = build_log_entry(
      &make_ok_result(),
      Instant::now(),
      ctx,
      vec![],
      "GET",
      "/",
    );
    assert_eq!(entry.server_ip, "10.0.0.1");
    assert_eq!(entry.server_port, 8080);
  }

  #[test]
  fn test_build_log_entry_extracts_service_name() {
    let ctx = RequestContext::new();
    ctx.insert("service.name", "tunnel");
    let entry = build_log_entry(
      &make_ok_result(),
      Instant::now(),
      ctx,
      vec![],
      "CONNECT",
      "example.com:443",
    );
    assert_eq!(entry.service, "tunnel");
  }

  #[test]
  fn test_build_log_entry_extracts_extensions() {
    let ctx = RequestContext::new();
    ctx.insert("auth.basic_auth.user", "admin");
    ctx.insert("connect_tcp.connect_tcp.connect_ms", "42");
    let entry = build_log_entry(
      &make_ok_result(),
      Instant::now(),
      ctx,
      vec![
        "auth.basic_auth.user".to_string(),
        "connect_tcp.connect_tcp.connect_ms".to_string(),
      ],
      "GET",
      "/",
    );
    assert_eq!(
      entry.extensions.get("auth.basic_auth.user"),
      Some(&"admin".to_string())
    );
    assert_eq!(
      entry.extensions.get("connect_tcp.connect_tcp.connect_ms"),
      Some(&"42".to_string())
    );
  }

  #[test]
  fn test_build_log_entry_missing_context_defaults() {
    let ctx = RequestContext::new();
    let entry = build_log_entry(
      &make_ok_result(),
      Instant::now(),
      ctx,
      vec![],
      "GET",
      "/",
    );
    assert_eq!(entry.client_ip, "");
    assert_eq!(entry.client_port, 0);
    assert_eq!(entry.server_ip, "");
    assert_eq!(entry.server_port, 0);
    assert_eq!(entry.service, "");
    assert!(entry.extensions.is_empty());
  }

  #[test]
  fn test_build_log_entry_preserves_method_and_target() {
    let ctx = RequestContext::new();
    let entry = build_log_entry(
      &make_ok_result(),
      Instant::now(),
      ctx,
      vec![],
      "CONNECT",
      "example.com:443",
    );
    assert_eq!(entry.method, "CONNECT");
    assert_eq!(entry.target, "example.com:443");
  }

  #[test]
  fn test_build_log_entry_invalid_port_defaults_to_zero() {
    let ctx = RequestContext::new();
    ctx.insert("client.port", "not_a_number");
    ctx.insert("server.port", "99999");
    let entry = build_log_entry(
      &make_ok_result(),
      Instant::now(),
      ctx,
      vec![],
      "GET",
      "/",
    );
    assert_eq!(entry.client_port, 0);
    assert_eq!(entry.server_port, 0);
  }

  #[test]
  fn test_build_log_entry_extensions_only_includes_requested_keys() {
    let ctx = RequestContext::new();
    ctx.insert("auth.basic_auth.user", "admin");
    ctx.insert("other.key", "value");
    let entry = build_log_entry(
      &make_ok_result(),
      Instant::now(),
      ctx,
      vec!["auth.basic_auth.user".to_string()],
      "GET",
      "/",
    );
    assert_eq!(entry.extensions.len(), 1);
    assert!(entry.extensions.contains_key("auth.basic_auth.user"));
    assert!(!entry.extensions.contains_key("other.key"));
  }
}

#[cfg(test)]
mod plugin_tests {
  use crate::plugin::Plugin;

  #[test]
  fn test_access_log_plugin_has_file_layer() {
    let plugin = crate::plugins::access_log::AccessLogPlugin::new();
    assert!(plugin.layer_builder("file").is_some());
  }

  #[test]
  fn test_access_log_plugin_no_unknown_layer() {
    let plugin = crate::plugins::access_log::AccessLogPlugin::new();
    assert!(plugin.layer_builder("unknown").is_none());
  }

  #[test]
  fn test_access_log_file_layer_builds_with_empty_config() {
    let plugin = crate::plugins::access_log::AccessLogPlugin::new();
    let builder = plugin.layer_builder("file").unwrap();
    let layer = builder(serde_yaml::Value::Null);
    assert!(layer.is_ok());
  }

  #[test]
  fn test_access_log_file_layer_builds_with_context_fields() {
    let plugin = crate::plugins::access_log::AccessLogPlugin::new();
    let builder = plugin.layer_builder("file").unwrap();
    let args = serde_yaml::from_str(
      r#"
context_fields:
  - auth.basic_auth.user
"#,
    )
    .unwrap();
    let layer = builder(args);
    assert!(layer.is_ok());
  }
}
