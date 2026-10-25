//! module: tunnel
//! responsibilities: copy a bidirectional tunnel under cancellation and
//! idle deadlines public operations: run_tunnel
//! data entities: ActivityStream, TaggedIo
//! tests: stream_tests.rs, stream_tunnel_tests.rs through stream's
//! public interface

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{info, warn};

use super::idle::IdleTracker;
use crate::shutdown::ShutdownHandle;

/// Records actual byte progress; the tunnel owns the one idle timer.
/// Keeping the timer outside individual I/O methods also bounds pending
/// flush/shutdown after both read directions have reached EOF.
struct ActivityStream<S> {
  stream: S,
  tracker: IdleTracker,
}

impl<S> ActivityStream<S> {
  fn new(stream: S, tracker: IdleTracker) -> Self {
    Self { stream, tracker }
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
  tag: &'static str,
}

impl<S> TaggedIo<S> {
  fn new(inner: S, tag: &'static str) -> Self {
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
        format!("[{}] {}", self.tag, e),
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
        format!("[{}] {}", self.tag, e),
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
        format!("[{}] {}", self.tag, e),
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
        format!("[{}] {}", self.tag, e),
      ))),
      other => other,
    }
  }
}

// ============================================================================
// Tunnel functions
// ============================================================================

/// Run bidirectional copy between client and target streams.
///
/// Handles shutdown notification and idle timeout. Logs the outcome.
/// Idle timeout is shared across both directions: if data flows in
/// EITHER direction, the connection is considered active.
pub(crate) async fn run_tunnel<C, T>(
  client: C,
  target: T,
  shutdown_handle: ShutdownHandle,
  idle_timeout: Duration,
  tunnel_desc: &str,
) where
  C: AsyncRead + AsyncWrite + Unpin,
  T: AsyncRead + AsyncWrite + Unpin,
{
  if shutdown_handle.is_shutdown() {
    warn!("tunnel {tunnel_desc}: shutdown already triggered, aborting");
    return;
  }

  info!("tunnel {tunnel_desc}: bidirectional transfer started");

  let tracker = IdleTracker::new(idle_timeout);
  let mut client_pinned = TaggedIo::new(
    ActivityStream::new(client, tracker.clone()),
    "client",
  );
  let mut target_pinned = TaggedIo::new(
    ActivityStream::new(target, tracker.clone()),
    "upstream",
  );

  let result = tokio::select! {
    res = tokio::io::copy_bidirectional(
      &mut client_pinned,
      &mut target_pinned,
    ) => res,
    _ = async {
      loop {
        tokio::time::sleep_until(tracker.deadline()).await;
        // Progress in either direction can make the previous alarm
        // stale. Re-arm for the shared deadline without closing the
        // active tunnel or extending idle time merely for a poll.
        if tracker.is_idle() {
          break;
        }
      }
    } => Err(std::io::Error::new(
      std::io::ErrorKind::TimedOut, "idle timeout",
    )),
    _ = shutdown_handle.notified() => {
      warn!("tunnel {tunnel_desc}: shutdown by notification");
      return;
    }
  };

  match result {
    Ok((_sent, _received)) => {
      info!("tunnel {tunnel_desc}: transfer completed");
    }
    Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
      warn!(
        "tunnel {tunnel_desc}: idle timeout after {idle_timeout:?}, \
         closing"
      );
    }
    Err(e) => {
      warn!("tunnel {tunnel_desc}: transfer error: {e}");
    }
  }
}
