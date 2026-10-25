//! module: h3
//! responsibilities: complete HTTP/3 CONNECT negotiation before
//! transferring its stream public operations: H3UpgradeTrigger::{pair,
//! send_success, send_error, send_error_with_body} data entities:
//! H3UpgradeTrigger tests: HTTP/3 process integration tests
use anyhow::Result;
use bytes::Bytes;

use super::{OnUpgrade, UpgradeTrigger};
use crate::h3_stream::H3ServerBidiStream;

/// H3 upgrade trigger (Listener side).
///
/// Held by the H3 listener. After service.call() returns a Response,
/// the listener calls `send_success()` or `send_error()` to:
/// 1. Send the H3 protocol response on the stream
/// 2. Transfer stream ownership to the Service via the upgrade channel
pub(crate) struct H3UpgradeTrigger<S: h3::quic::BidiStream<Bytes>> {
  trigger: Option<UpgradeTrigger>,
  stream: Option<h3::server::RequestStream<S, Bytes>>,
}

impl<S: h3::quic::BidiStream<Bytes>> std::fmt::Debug
  for H3UpgradeTrigger<S>
{
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("H3UpgradeTrigger").finish_non_exhaustive()
  }
}

impl<S> H3UpgradeTrigger<S>
where
  S: h3::quic::BidiStream<
      Bytes,
      SendStream = h3_quinn::SendStream<Bytes>,
      RecvStream = h3_quinn::RecvStream,
    >,
{
  /// Create a linked (trigger, on_upgrade) pair.
  pub(crate) fn pair(
    stream: h3::server::RequestStream<S, Bytes>,
  ) -> (Self, OnUpgrade) {
    let (trigger, on_upgrade) = OnUpgrade::pair();
    (Self { trigger: Some(trigger), stream: Some(stream) }, on_upgrade)
  }

  /// Send H3 success (200 OK) and deliver the stream to the Service.
  pub(crate) async fn send_success(
    mut self,
    resp_headers: Option<&http::HeaderMap>,
  ) -> Result<()> {
    // Send 200 OK response on the H3 stream, preserving upstream
    // headers (e.g. Proxy-Status per RFC 9209).
    let mut builder =
      http::Response::builder().status(http::StatusCode::OK);
    if let Some(headers) = resp_headers
      && let Some(hdrs) = builder.headers_mut()
    {
      *hdrs = headers.clone();
    }
    let resp = builder.body(()).unwrap();
    let mut resp = resp;
    crate::hop_headers::strip_connection_headers(resp.headers_mut());
    resp.headers_mut().remove(http::header::CONTENT_LENGTH);
    self.stream.as_mut().unwrap().send_response(resp).await?;

    // Split into send/recv halves and wrap
    let (send_stream, recv_stream) =
      self.stream.take().unwrap().split();
    let bidi = H3ServerBidiStream::new(send_stream, recv_stream);

    // Deliver to Service
    self.trigger.take().unwrap().send(Ok(Box::new(bidi)))
  }

  /// Send H3 error response and deliver error to the Service.
  pub(crate) async fn send_error(
    mut self,
    status: http::StatusCode,
  ) -> Result<()> {
    let stream = self.stream.as_mut().unwrap();

    // Send error response on the H3 stream
    let resp =
      http::Response::builder().status(status).body(()).unwrap();
    stream.send_response(resp).await?;
    stream.finish().await?;
    self.stream.take();

    // Deliver error to Service
    self
      .trigger
      .take()
      .unwrap()
      .send(Err(anyhow::anyhow!("H3 upgrade failed: {}", status)))
  }

  /// Send H3 error response with body and deliver error to the Service.
  pub(crate) async fn send_error_with_body(
    mut self,
    status: http::StatusCode,
    body: Bytes,
    resp_headers: Option<&http::HeaderMap>,
  ) -> Result<()> {
    let stream = self.stream.as_mut().unwrap();

    // Send error response on the H3 stream, preserving upstream
    // headers (e.g. Proxy-Status per RFC 9209).
    let mut builder = http::Response::builder().status(status);
    if let Some(headers) = resp_headers
      && let Some(hdrs) = builder.headers_mut()
    {
      *hdrs = headers.clone();
    }
    let resp = builder.body(()).unwrap();
    stream.send_response(resp).await?;

    // Send body if not empty
    if !body.is_empty() {
      stream.send_data(body).await?;
    }

    stream.finish().await?;
    self.stream.take();

    // Deliver error to Service
    self
      .trigger
      .take()
      .unwrap()
      .send(Err(anyhow::anyhow!("H3 upgrade failed: {}", status)))
  }
}

impl<S: h3::quic::BidiStream<Bytes>> Drop for H3UpgradeTrigger<S> {
  fn drop(&mut self) {
    // If negotiation is cancelled, signal a request-stream failure;
    // silently dropping Quinn's sender would finish a truncated reply.
    // The Options only permit moving fields out of this Drop owner.
    // Consuming methods own self and may take each field exactly once;
    // unwrap failures intentionally expose a broken internal invariant.
    if let Some(stream) = &mut self.stream {
      stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
    }
  }
}

// ============================================================================
// Socks5UpgradeTrigger - SOCKS5-specific trigger
// ============================================================================
