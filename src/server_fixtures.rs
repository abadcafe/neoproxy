//! Test-only services for server routing consumers.

use std::future::Future;
use std::pin::Pin;

use anyhow::Result;
use tower::service_fn;

use crate::http_message::Response;
use crate::service::Service;

/// Supply a service for tests that exercise routing without invocation.
pub(crate) fn placeholder_service() -> Service {
  Service::new(service_fn(|_req| {
    Box::pin(async {
      Err::<Response, _>(anyhow::anyhow!("placeholder"))
    }) as Pin<Box<dyn Future<Output = Result<Response>>>>
  }))
}
