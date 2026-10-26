//! module: h3_response
//! responsibility: stream normalized HTTP/3 responses with cancellation
//! public operations: ResponseSink, ResponseWriter::{new, send}
//! data entities: ResponseWriter
//! tests: h3_response_tests.rs

use bytes::Bytes;
use http_body_util::BodyExt;

use crate::http_message::Response;

/// A response transport; the writer owns framing and cancellation.
pub(crate) trait ResponseSink {
  async fn headers(
    &mut self,
    response: http::Response<()>,
  ) -> anyhow::Result<()>;
  async fn data(&mut self, data: Bytes) -> anyhow::Result<()>;
  async fn trailers(
    &mut self,
    trailers: http::HeaderMap,
  ) -> anyhow::Result<()>;
  async fn finish(&mut self) -> anyhow::Result<()>;
  fn cancel(&mut self);
}

impl<S: h3::quic::SendStream<Bytes>> ResponseSink
  for h3::server::RequestStream<S, Bytes>
{
  async fn headers(
    &mut self,
    response: http::Response<()>,
  ) -> anyhow::Result<()> {
    Ok(self.send_response(response).await?)
  }

  async fn data(&mut self, data: Bytes) -> anyhow::Result<()> {
    Ok(self.send_data(data).await?)
  }

  async fn trailers(
    &mut self,
    trailers: http::HeaderMap,
  ) -> anyhow::Result<()> {
    Ok(self.send_trailers(trailers).await?)
  }

  async fn finish(&mut self) -> anyhow::Result<()> {
    Ok(self.finish().await?)
  }

  fn cancel(&mut self) {
    self.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
  }
}

/// Dropping an unfinished exchange resets it, including cancellation
/// while awaiting a body frame or QUIC flow control.
pub(crate) struct ResponseWriter<S: ResponseSink> {
  stream: S,
  finished: bool,
}

impl<S: ResponseSink> ResponseWriter<S> {
  pub(crate) fn new(stream: S) -> Self {
    Self { stream, finished: false }
  }

  pub(crate) async fn send(
    &mut self,
    response: Response,
    method: &http::Method,
  ) -> anyhow::Result<()> {
    let request_id = response
      .extensions()
      .get::<crate::context::RequestContext>()
      .and_then(crate::context::RequestContext::request_id)
      .cloned();
    let (mut parts, mut body) = response.into_parts();
    let body_allowed = method != http::Method::HEAD
      && !parts.status.is_informational()
      && !matches!(
        parts.status,
        http::StatusCode::NO_CONTENT
          | http::StatusCode::RESET_CONTENT
          | http::StatusCode::NOT_MODIFIED
      );
    if parts.status.is_informational()
      || parts.status == http::StatusCode::NO_CONTENT
    {
      parts.headers.remove(http::header::CONTENT_LENGTH);
    }
    let trailer_policy =
      crate::hop_headers::strip_connection_headers(&mut parts.headers);
    parts.version = http::Version::HTTP_3;
    self.stream.headers(http::Response::from_parts(parts, ())).await?;
    if body_allowed {
      while let Some(frame) = body.frame().await {
        match frame?.into_data() {
          Ok(data) => {
            if !data.is_empty() {
              let bytes = data.len();
              tracing::trace!(
                request_id =
                  request_id.as_ref().map(tracing::field::display),
                bytes,
                "H3 response content sending"
              );
              self.stream.data(data).await?;
              tracing::trace!(
                request_id =
                  request_id.as_ref().map(tracing::field::display),
                bytes,
                "H3 response content sent"
              );
            }
          }
          Err(frame) => {
            if let Ok(mut trailers) = frame.into_trailers() {
              trailer_policy.apply(&mut trailers);
              self.stream.trailers(trailers).await?;
              break;
            }
          }
        }
      }
    }
    drop(body);
    self.stream.finish().await?;
    self.finished = true;
    Ok(())
  }
}

impl<S: ResponseSink> Drop for ResponseWriter<S> {
  fn drop(&mut self) {
    if !self.finished {
      self.stream.cancel();
    }
  }
}
