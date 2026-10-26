//! module: plugins::access_log::layer
//! responsibility: observe service results through a log delivery
//! contract
//! public operations: DeliveryError, LogSink, AccessLogLayer, new,
//! build_log_entry
//! data entities: DeliveryError, AccessLogLayer, AccessLogMiddleware
//! tests: layer_tests.rs

//! Tower layer and middleware for access logging.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use tracing::warn;

use super::context::AccessLogEntry;
use crate::context::RequestContext;
use crate::http_message::{Request, Response};
use crate::service::Service;

/// The middleware defines its delivery contract; writer backends
/// implement it without exposing a channel or registry representation.
#[derive(Clone, Copy, Debug)]
pub(crate) enum DeliveryError {
  Full,
  Stopped,
}
pub(crate) trait LogSink: Send + Sync {
  fn record(&self, entry: AccessLogEntry) -> Result<(), DeliveryError>;
}

/// Layer that creates AccessLogMiddleware instances.
pub(crate) struct AccessLogLayer {
  sink: Arc<dyn LogSink>,
  context_fields: Arc<[String]>,
}

impl AccessLogLayer {
  pub(crate) fn new(
    sink: Arc<dyn LogSink>,
    context_fields: Vec<String>,
  ) -> Self {
    Self { sink, context_fields: context_fields.into() }
  }
}

impl tower::Layer<Service> for AccessLogLayer {
  type Service = Service;

  fn layer(&self, inner: Service) -> Service {
    Service::new(AccessLogMiddleware {
      inner,
      sink: self.sink.clone(),
      context_fields: self.context_fields.clone(),
    })
  }
}

/// Middleware that logs access entries.
struct AccessLogMiddleware {
  inner: Service,
  sink: Arc<dyn LogSink>,
  context_fields: Arc<[String]>,
}

impl Clone for AccessLogMiddleware {
  fn clone(&self) -> Self {
    Self {
      inner: self.inner.clone(),
      sink: self.sink.clone(),
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
    let sink = self.sink.clone();
    let context_fields = self.context_fields.clone();

    let method = req.method().to_string();
    let target = req.uri().to_string();

    let ctx = req
      .extensions()
      .get::<RequestContext>()
      .cloned()
      .unwrap_or_default();

    let future = self.inner.call(req);

    Box::pin(async move {
      let result = future.await;

      let entry = build_log_entry(
        &result,
        start,
        ctx,
        &context_fields,
        &method,
        &target,
      );

      if let Err(e) = sink.record(entry) {
        match e {
          DeliveryError::Full => {
            warn!("access_log: sink full, dropping log entry");
          }
          DeliveryError::Stopped => {
            warn!("access_log: sink stopped, dropping log entry");
          }
        }
      }

      result
    })
  }
}

pub(crate) fn build_log_entry(
  result: &anyhow::Result<Response>,
  start: Instant,
  ctx: RequestContext,
  context_fields: &[String],
  method: &str,
  target: &str,
) -> AccessLogEntry {
  use time::OffsetDateTime;

  let time = OffsetDateTime::now_utc();
  let duration_ms = start.elapsed().as_millis() as u64;

  let client_ip = ctx
    .client_addr()
    .map(|address| address.ip().to_string())
    .unwrap_or_default();
  let client_port =
    ctx.client_addr().map(|address| address.port()).unwrap_or(0);
  let server_ip = ctx
    .server_addr()
    .map(|address| address.ip().to_string())
    .unwrap_or_default();
  let server_port =
    ctx.server_addr().map(|address| address.port()).unwrap_or(0);
  let service = ctx.service_name().unwrap_or_default().to_owned();

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
