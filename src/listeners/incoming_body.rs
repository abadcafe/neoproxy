//! module: incoming_body
//! responsibility: enforce streaming request-body receive policy
//! public operations: IncomingBody::wrap, Failure::{status,notified}
//! data entities: IncomingBody, Failure, FailureState
//! tests: incoming_body_tests.rs
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};

use super::http_policy::HttpPolicy;
use crate::http_message::RequestBody;

#[derive(Default)]
struct FailureState {
  status: AtomicU16,
  notify: tokio::sync::Notify,
}
#[derive(Clone, Default)]
pub(super) struct Failure(Arc<FailureState>);
impl Failure {
  pub(super) fn status(&self) -> Option<http::StatusCode> {
    match self.0.status.load(Ordering::Acquire) {
      0 => None,
      value => Some(
        http::StatusCode::from_u16(value)
          .expect("published HTTP status"),
      ),
    }
  }

  pub(super) async fn notified(&self) {
    self.0.notify.notified().await;
  }

  fn report(&self, status: http::StatusCode) {
    self.0.status.store(status.as_u16(), Ordering::Release);
    self.0.notify.notify_one();
  }
}
pub(super) struct IncomingBody {
  inner: RequestBody,
  policy: HttpPolicy,
  timer: Option<Pin<Box<tokio::time::Sleep>>>,
  reads: crate::io_progress::Progress,
  failure: Failure,
  done: bool,
}
impl IncomingBody {
  pub(super) fn wrap(
    inner: RequestBody,
    policy: HttpPolicy,
    reads: Option<crate::io_progress::Progress>,
  ) -> (RequestBody, Failure) {
    let failure = Failure::default();
    let body = Self {
      inner,
      policy,
      timer: None,
      reads: reads.unwrap_or_default(),
      failure: failure.clone(),
      done: false,
    };
    (RequestBody::new(body), failure)
  }

  fn fail(
    &mut self,
    status: http::StatusCode,
  ) -> Poll<Option<anyhow::Result<Frame<Bytes>>>> {
    self.done = true;
    self.timer = None;
    self.failure.report(status);
    Poll::Ready(Some(Err(anyhow::anyhow!("{status}"))))
  }
}
impl Body for IncomingBody {
  type Data = Bytes;
  type Error = anyhow::Error;

  fn poll_frame(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<anyhow::Result<Frame<Bytes>>>> {
    let this = self.get_mut();
    if this.done {
      return Poll::Ready(None);
    }
    match Pin::new(&mut this.inner).poll_frame(cx) {
      Poll::Ready(result) => {
        this.timer = None;
        if let Some(Ok(frame)) = &result
          && let Some(trailers) = frame.trailers_ref()
          && !this.policy.request_limits.limits().accepts(trailers)
        {
          return this
            .fail(http::StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE);
        }
        if matches!(result, None | Some(Err(_))) {
          this.done = true;
        }
        Poll::Ready(result.map(|result| {
          result.map(|frame| match frame.into_trailers() {
            Ok(mut trailers) => {
              crate::hop_headers::strip_trailer_headers(&mut trailers);
              Frame::trailers(trailers)
            }
            Err(frame) => frame,
          })
        }))
      }
      Poll::Pending => {
        if this.reads.poll_stalled(
          &mut this.timer,
          this.policy.body_read_timeout.duration(),
          cx,
        ) {
          this.fail(http::StatusCode::REQUEST_TIMEOUT)
        } else {
          Poll::Pending
        }
      }
    }
  }

  fn is_end_stream(&self) -> bool {
    self.done || self.inner.is_end_stream()
  }

  fn size_hint(&self) -> SizeHint {
    self.inner.size_hint()
  }
}
