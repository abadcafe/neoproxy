//! module: upload
//! responsibilities: stream an upstream H3 request concurrently with
//! its response public operations: Upload::start, Future
//! data entities: Upload
//! tests: HTTP/3 duplex integration regressions

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body_util::BodyExt;
use tokio::sync::oneshot;
use tokio::task::AbortHandle;

use crate::http_message::RequestBody;
use crate::plugins::http_upstream::error::UpstreamError;
use crate::tracker::StreamTracker;

pub(super) struct Upload {
  task: AbortHandle,
  result: oneshot::Receiver<Result<(), UpstreamError>>,
}

struct RequestWriter {
  stream: h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
  finished: bool,
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
  ) -> Self {
    let (sender, result) = oneshot::channel();
    // Construct before spawning: even cancellation before the first
    // task poll must reset instead of finishing a truncated request.
    let mut writer = RequestWriter { stream, finished: false };
    let task = tracker.register(async move {
      let result = async {
        while let Some(frame) = body.frame().await {
          let frame = frame.map_err(|error| {
            UpstreamError::ConnectionTerminated(error.to_string())
          })?;
          match frame.into_data() {
            Ok(data) => {
              writer.stream.send_data(data).await.map_err(|error| {
                UpstreamError::ConnectionTerminated(error.to_string())
              })?
            }
            Err(frame) => {
              if let Ok(mut trailers) = frame.into_trailers() {
                crate::hop_headers::strip_trailer_headers(
                  &mut trailers,
                );
                writer.stream.send_trailers(trailers).await.map_err(
                  |error| {
                    UpstreamError::ConnectionTerminated(
                      error.to_string(),
                    )
                  },
                )?;
                break;
              }
            }
          }
        }
        writer.stream.finish().await.map_err(|error| {
          UpstreamError::ConnectionTerminated(error.to_string())
        })?;
        writer.finished = true;
        Ok(())
      }
      .await;
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
