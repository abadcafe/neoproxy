//! module: upgrade
//! responsibilities: complete HTTP/3 CONNECT negotiation before
//! transferring its stream public operations: H3UpgradeTrigger::{pair,
//! respond} data entities:
//! H3UpgradeTrigger tests: HTTP/3 process integration tests
use anyhow::Result;
use bytes::Bytes;

use crate::h3_stream::H3ServerBidiStream;
use crate::stream::{OnUpgrade, UpgradeTrigger};

/// H3 upgrade trigger (Listener side).
///
/// Held by the H3 listener. After service.call() returns a Response,
/// the listener calls `respond()` to:
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

  /// Complete CONNECT using its actual status and a streamed failure
  /// body. Every 2xx transfers I/O; all other responses use the same
  /// framing/backpressure owner as ordinary HTTP/3 responses.
  pub(crate) async fn respond(
    mut self,
    response: crate::http_message::Response,
  ) -> Result<()> {
    let status = response.status();
    if status.is_success() {
      let (mut parts, body) = response.into_parts();
      drop(body);
      crate::hop_headers::strip_connection_headers(&mut parts.headers);
      parts.headers.remove(http::header::CONTENT_LENGTH);
      parts.version = http::Version::HTTP_3;
      self
        .stream
        .as_mut()
        .unwrap()
        .send_response(http::Response::from_parts(parts, ()))
        .await?;
      let (send, recv) = self.stream.take().unwrap().split();
      self
        .trigger
        .take()
        .unwrap()
        .send(Ok(Box::new(H3ServerBidiStream::new(send, recv))))
    } else {
      let stream = self.stream.take().unwrap();
      crate::h3_response::ResponseWriter::new(stream)
        .send(response, &http::Method::CONNECT)
        .await?;
      self
        .trigger
        .take()
        .unwrap()
        .send(Err(anyhow::anyhow!("H3 upgrade failed: {status}")))
    }
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
