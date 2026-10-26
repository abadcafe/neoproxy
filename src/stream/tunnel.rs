//! module: tunnel
//! responsibilities: copy a bidirectional tunnel under cancellation and
//! idle deadlines public operations: run_tunnel
//! data entities: ActivityStream, TaggedIo, SideError
//! tests: stream_tests.rs, stream_tunnel_tests.rs through stream's
//! public interface

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};

use super::idle::IdleTracker;
use super::transfer::{
  IoSide, TransferEnd, TransferProgress, WrittenCounter,
};
use crate::shutdown::ShutdownHandle;

/// Records actual byte progress; the tunnel owns the one idle timer.
/// Keeping the timer outside individual I/O methods also bounds pending
/// flush/shutdown after both read directions have reached EOF.
struct ActivityStream<S> {
  stream: S,
  tracker: IdleTracker,
  written: WrittenCounter,
}

impl<S> ActivityStream<S> {
  fn new(
    stream: S,
    tracker: IdleTracker,
    written: WrittenCounter,
  ) -> Self {
    Self { stream, tracker, written }
  }
}

impl<S: AsyncRead + Unpin> AsyncRead for ActivityStream<S> {
  fn poll_read(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut tokio::io::ReadBuf<'_>,
  ) -> Poll<std::io::Result<()>> {
    let this = self.get_mut();
    let before = buf.filled().len();
    match Pin::new(&mut this.stream).poll_read(cx, buf) {
      Poll::Ready(Ok(())) => {
        if buf.filled().len() > before {
          this.tracker.touch();
        }
        Poll::Ready(Ok(()))
      }
      other => other,
    }
  }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ActivityStream<S> {
  fn poll_write(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<std::io::Result<usize>> {
    let this = self.get_mut();
    match Pin::new(&mut this.stream).poll_write(cx, buf) {
      Poll::Ready(Ok(n)) => {
        if n > 0 {
          this.written.add(n);
          this.tracker.touch();
        }
        Poll::Ready(Ok(n))
      }
      other => other,
    }
  }

  fn poll_flush(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<std::io::Result<()>> {
    Pin::new(&mut self.get_mut().stream).poll_flush(cx)
  }

  fn poll_shutdown(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<std::io::Result<()>> {
    Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
  }
}

// ============================================================================
// TaggedIo - tags I/O errors with a side label
// ============================================================================

/// Wrapper that injects a side tag (e.g. "client", "upstream") into I/O
/// errors, so that `copy_bidirectional` error messages indicate which
/// side failed.
struct TaggedIo<S> {
  inner: S,
  tag: IoSide,
}

impl<S> TaggedIo<S> {
  fn new(inner: S, tag: IoSide) -> Self {
    Self { inner, tag }
  }
}

impl<S: AsyncRead + Unpin> AsyncRead for TaggedIo<S> {
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut tokio::io::ReadBuf<'_>,
  ) -> Poll<std::io::Result<()>> {
    match Pin::new(&mut self.inner).poll_read(cx, buf) {
      Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::new(
        e.kind(),
        SideError { side: self.tag, source: e },
      ))),
      other => other,
    }
  }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TaggedIo<S> {
  fn poll_write(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<std::io::Result<usize>> {
    match Pin::new(&mut self.inner).poll_write(cx, buf) {
      Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::new(
        e.kind(),
        SideError { side: self.tag, source: e },
      ))),
      other => other,
    }
  }

  fn poll_flush(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<std::io::Result<()>> {
    match Pin::new(&mut self.inner).poll_flush(cx) {
      Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::new(
        e.kind(),
        SideError { side: self.tag, source: e },
      ))),
      other => other,
    }
  }

  fn poll_shutdown(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<std::io::Result<()>> {
    match Pin::new(&mut self.inner).poll_shutdown(cx) {
      Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::new(
        e.kind(),
        SideError { side: self.tag, source: e },
      ))),
      other => other,
    }
  }
}

// ============================================================================
// Tunnel functions
// ============================================================================

#[derive(Debug)]
struct SideError {
  side: IoSide,
  source: std::io::Error,
}
impl std::fmt::Display for SideError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "[{}] {}", self.side, self.source)
  }
}
impl std::error::Error for SideError {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    Some(&self.source)
  }
}

/// Copy a tunnel without logging; the caller owns completion reporting.
pub(crate) async fn run_tunnel<C, T>(
  client: C,
  target: T,
  shutdown_handle: ShutdownHandle,
  idle_timeout: Duration,
  progress: TransferProgress,
) -> TransferEnd
where
  C: AsyncRead + AsyncWrite + Unpin,
  T: AsyncRead + AsyncWrite + Unpin,
{
  if shutdown_handle.is_shutdown() {
    return TransferEnd::Shutdown;
  }
  let tracker = IdleTracker::new(idle_timeout);
  let mut client_pinned = TaggedIo::new(
    ActivityStream::new(
      client,
      tracker.clone(),
      progress.client_written(),
    ),
    IoSide::Client,
  );
  let mut target_pinned = TaggedIo::new(
    ActivityStream::new(
      target,
      tracker.clone(),
      progress.upstream_written(),
    ),
    IoSide::Upstream,
  );
  tokio::select! {
    result = tokio::io::copy_bidirectional(&mut client_pinned, &mut target_pinned) => match result {
      Ok(_) => TransferEnd::Completed,
      Err(error) => {
        let side = error.get_ref().and_then(|inner| inner.downcast_ref::<SideError>()).map(|tagged| tagged.side);
        TransferEnd::Failed { side, error }
      }
    },
    _ = async { loop { tokio::time::sleep_until(tracker.deadline()).await; if tracker.is_idle() { break; } } } => TransferEnd::IdleTimeout,
    _ = shutdown_handle.notified() => TransferEnd::Shutdown,
  }
}
