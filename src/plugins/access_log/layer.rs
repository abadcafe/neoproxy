//! Tower layer and middleware for access logging.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::mpsc;
use std::task::{Context, Poll};
use std::time::Instant;

use tracing::warn;

use super::context::AccessLogEntry;
use super::registry::LogEntry;
use crate::context::RequestContext;
use crate::http_utils::{Request, Response};
use crate::service::Service;

/// Layer that creates AccessLogMiddleware instances.
pub struct AccessLogLayer {
  pub tx: mpsc::SyncSender<LogEntry>,
  pub context_fields: Vec<String>,
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
  tx: mpsc::SyncSender<LogEntry>,
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

      if let Err(e) = tx.try_send(LogEntry { entry }) {
        match e {
          std::sync::mpsc::TrySendError::Full(_) => {
            warn!("access_log: channel full, dropping log entry");
          }
          std::sync::mpsc::TrySendError::Disconnected(_) => {
            warn!("access_log: channel closed, dropping log entry");
          }
        }
      }

      match result {
        Ok(response) => Ok(response),
        Err(_) => Ok(crate::http_utils::build_empty_response(
          http::StatusCode::INTERNAL_SERVER_ERROR,
        )),
      }
    })
  }
}

pub(crate) fn build_log_entry(
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

  // CR-002 fix: Preserve full context field keys (no stripping).
  // Previously, the first dot-separated segment was stripped from keys
  // (e.g., "auth.user" became "user"). This caused silent data loss
  // when different prefixes shared the same suffix (e.g., "auth.user"
  // and "audit.user" both became "user", and the HashMap silently
  // dropped one value). Using the full key preserves uniqueness since
  // RequestContext keys are already unique.
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
