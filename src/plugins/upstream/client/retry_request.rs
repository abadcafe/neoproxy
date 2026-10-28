//! module: retry_request
//! responsibility: gate request replay by send progress and body
//! consumption public operations: RetryRequest::{new,body,can_retry},
//! Progress::{mark,mark_request,unsent} data entities: RetryRequest,
//! RetainedBody, Progress tests: retry_request_tests.rs,
//! test_non_idempotent_retry.py
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use http_body::{Body, Frame, SizeHint};

use crate::http_message::RequestBody;

#[derive(Clone, Default)]
pub(super) struct Progress(Arc<AtomicBool>);
impl Progress {
  pub(super) fn mark(&self) {
    self.0.store(true, Ordering::Relaxed);
  }

  pub(super) fn unsent<T>(request: &http::Request<T>) {
    if let Some(progress) = request.extensions().get::<Self>() {
      progress.0.store(false, Ordering::Relaxed);
    }
  }

  pub(super) fn mark_request<T>(request: &http::Request<T>) {
    if let Some(progress) = request.extensions().get::<Self>() {
      progress.mark();
    }
  }
}
pub(super) struct RetryRequest {
  body: Arc<std::sync::Mutex<RequestBody>>,
  consumed: Arc<AtomicBool>,
}
struct RetainedBody {
  body: Arc<std::sync::Mutex<RequestBody>>,
  consumed: Arc<AtomicBool>,
}
impl RetryRequest {
  pub(super) fn new(body: RequestBody) -> Self {
    Self {
      body: Arc::new(std::sync::Mutex::new(body)),
      consumed: Arc::new(AtomicBool::new(false)),
    }
  }

  pub(super) fn body(&self) -> RequestBody {
    RequestBody::new(RetainedBody {
      body: self.body.clone(),
      consumed: self.consumed.clone(),
    })
  }

  pub(super) fn can_retry(
    &self,
    progress: &Progress,
    method: &http::Method,
    non_idempotent: bool,
  ) -> bool {
    !self.consumed.load(Ordering::Relaxed)
      && (!progress.0.load(Ordering::Relaxed)
        || non_idempotent
        || matches!(
          *method,
          http::Method::GET
            | http::Method::HEAD
            | http::Method::PUT
            | http::Method::DELETE
            | http::Method::OPTIONS
            | http::Method::TRACE
        ))
  }
}
impl Body for RetainedBody {
  type Data = bytes::Bytes;
  type Error = anyhow::Error;

  fn poll_frame(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    let result = Pin::new(
      &mut *self.body.lock().expect("request body lock poisoned"),
    )
    .poll_frame(cx);
    if matches!(&result, Poll::Ready(Some(_))) {
      self.consumed.store(true, Ordering::Relaxed);
    }
    result
  }

  fn is_end_stream(&self) -> bool {
    self
      .body
      .lock()
      .expect("request body lock poisoned")
      .is_end_stream()
  }

  fn size_hint(&self) -> SizeHint {
    self.body.lock().expect("request body lock poisoned").size_hint()
  }
}
