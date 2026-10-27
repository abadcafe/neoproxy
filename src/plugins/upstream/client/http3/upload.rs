//! module: upload
//! responsibilities: stream an upstream H3 request concurrently with
//! its response public operations: Upload::start, Future
//! data entities: Upload, UploadError, RequestWriter
//! tests: HTTP/3 duplex integration regressions

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body_util::BodyExt;
use tokio::sync::oneshot;
use tokio::task::AbortHandle;

use crate::http_message::RequestBody;
use crate::plugins::upstream::error::UpstreamError;
use crate::tracker::StreamTracker;

pub(super) struct Upload {
  task: AbortHandle,
  result: oneshot::Receiver<Result<(), UpstreamError>>,
}

struct RequestWriter {
  stream: h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
  finished: bool,
}

// Retain transport error codes until the upload direction decides
// whether a peer stop is completion or failure.
enum UploadError {
  Body(anyhow::Error),
  Transport(h3::error::StreamError),
}

impl RequestWriter {
  fn complete(
    &mut self,
    result: Result<(), UploadError>,
  ) -> Result<(), UpstreamError> {
    let result = match result {
      Ok(()) => Ok(()),
      // RFC 9114 §4.1: a server can reject an upload while still
      // sending its final response. Only this stream-direction stop
      // is successful; connection closure and other reset codes
      // remain failures. h3's is_h3_no_error also covers connection
      // errors and omits RemoteTerminate, so inspect the public enum.
      Err(UploadError::Transport(
        h3::error::StreamError::RemoteTerminate { code, .. },
      )) if code == h3::error::Code::H3_NO_ERROR => Ok(()),
      Err(UploadError::Transport(error)) => {
        Err(UpstreamError::ConnectionTerminated(error.to_string()))
      }
      Err(UploadError::Body(error)) => {
        Err(UpstreamError::ProxyInternalError(error.to_string()))
      }
    };
    self.finished = result.is_ok();
    result
  }
}

impl Drop for RequestWriter {
  fn drop(&mut self) {
    if !self.finished {
      self.stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
    }
  }
}

impl Upload {
  pub(super) fn start(
    stream: h3::client::RequestStream<
      h3_quinn::SendStream<Bytes>,
      Bytes,
    >,
    mut body: RequestBody,
    tracker: &StreamTracker,
    request_id: Option<crate::request_id::RequestId>,
  ) -> Self {
    let (sender, result) = oneshot::channel();
    // Construct before spawning: even cancellation before the first
    // task poll must reset instead of finishing a truncated request.
    let mut writer = RequestWriter { stream, finished: false };
    let task = tracker.register(async move {
      let result = async {
        while let Some(frame) = body.frame().await {
          let frame = frame.map_err(UploadError::Body)?;
          match frame.into_data() {
            Ok(data) => {
              let bytes = data.len();
              tracing::trace!(
                request_id =
                  request_id.as_ref().map(tracing::field::display),
                bytes,
                "H3 request content sending"
              );
              writer
                .stream
                .send_data(data)
                .await
                .map_err(UploadError::Transport)?;
              tracing::trace!(
                request_id =
                  request_id.as_ref().map(tracing::field::display),
                bytes,
                "H3 request content sent"
              );
            }
            Err(frame) => {
              if let Ok(mut trailers) = frame.into_trailers() {
                crate::hop_headers::strip_trailer_headers(
                  &mut trailers,
                );
                writer
                  .stream
                  .send_trailers(trailers)
                  .await
                  .map_err(UploadError::Transport)?;
                break;
              }
            }
          }
        }
        writer.stream.finish().await.map_err(UploadError::Transport)?;
        Ok::<(), UploadError>(())
      }
      .await;
      let result = writer.complete(result);
      let _ = sender.send(result);
    });
    Self { task, result }
  }
}

impl Future for Upload {
  type Output = Result<(), UpstreamError>;

  fn poll(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Self::Output> {
    Pin::new(&mut self.result).poll(cx).map(|result| {
      result.unwrap_or_else(|_| {
        Err(UpstreamError::ConnectionTerminated(
          "request upload cancelled".into(),
        ))
      })
    })
  }
}

impl Drop for Upload {
  fn drop(&mut self) {
    self.task.abort();
  }
}
