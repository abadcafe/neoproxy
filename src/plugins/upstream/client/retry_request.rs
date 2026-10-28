//! module: retry_request
//! responsibility: retain unconsumed request bodies for pre-send
//! connection failover public operations:
//! RetryRequest::{new,body,can_retry}, Progress::{mark,mark_request}
//! data entities: RetryRequest, RetainedBody, Progress
//! tests: test_upstream_nodes.py
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use http_body::{Body, Frame, SizeHint};

use crate::http_message::RequestBody;

#[derive(Clone, Default)]
pub(super) struct Progress(Arc<AtomicBool>, Arc<AtomicBool>);
impl Progress {
  pub(super) fn waiting(&self, value: bool) {
    self.1.store(value, Ordering::Relaxed);
  }

  pub(super) fn is_waiting(&self) -> bool {
    self.1.load(Ordering::Relaxed)
  }

  pub(super) fn mark(&self) {
    self.0.store(true, Ordering::Relaxed);
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

  pub(super) fn can_retry(&self, progress: &Progress) -> bool {
    !self.consumed.load(Ordering::Relaxed)
      && !progress.0.load(Ordering::Relaxed)
  }
}
impl Body for RetainedBody {
  type Data = bytes::Bytes;
  type Error = anyhow::Error;

  fn poll_frame(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    self.consumed.store(true, Ordering::Relaxed);
    Pin::new(
      &mut *self.body.lock().expect("request body lock poisoned"),
    )
    .poll_frame(cx)
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
