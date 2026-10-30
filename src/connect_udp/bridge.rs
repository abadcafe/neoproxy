//! module: bridge
//! responsibility: bind a capsule bridge task to its exposed I/O
//! lifetime public operations: spawn
//! data entities: BridgeIo
//! tests: CONNECT-UDP process contracts
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

use crate::shutdown::ShutdownHandle;
use crate::task_tracker::TaskTracker;

pub(super) fn spawn<F, T>(
  tracker: &TaskTracker,
  handler: F,
) -> Box<dyn crate::stream::Io>
where
  F: FnOnce(DuplexStream, ShutdownHandle) -> T,
  T: Future<Output = ()> + 'static,
{
  let (io, bridge) = tokio::io::duplex(131072);
  let shutdown = tracker.shutdown_handle().child();
  let task = handler(bridge, shutdown.clone());
  let (finished, done) = tokio::sync::oneshot::channel();
  let cancelled = shutdown.clone();
  tracker.register(async move {
    // Own cancellation around the entire handler, including writes and
    // shutdown inside a select branch. A blocked peer must never keep
    // the bridge, UDP socket or H3 registration alive after its owner.
    tokio::select! {
      biased;
      _ = cancelled.notified() => {},
      () = task => {},
    }
    let _ = finished.send(());
  });
  Box::new(BridgeIo { io, shutdown, done, finished: false })
}
struct BridgeIo {
  io: DuplexStream,
  shutdown: ShutdownHandle,
  done: tokio::sync::oneshot::Receiver<()>,
  finished: bool,
}
impl AsyncRead for BridgeIo {
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buffer: &mut ReadBuf<'_>,
  ) -> Poll<std::io::Result<()>> {
    Pin::new(&mut self.io).poll_read(cx, buffer)
  }
}
impl AsyncWrite for BridgeIo {
  fn poll_write(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    bytes: &[u8],
  ) -> Poll<std::io::Result<usize>> {
    Pin::new(&mut self.io).poll_write(cx, bytes)
  }

  fn poll_flush(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<std::io::Result<()>> {
    Pin::new(&mut self.io).poll_flush(cx)
  }

  fn poll_shutdown(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<std::io::Result<()>> {
    std::task::ready!(Pin::new(&mut self.io).poll_shutdown(cx))?;
    if !self.finished {
      let _ = std::task::ready!(Pin::new(&mut self.done).poll(cx));
      self.finished = true;
    }
    Poll::Ready(Ok(()))
  }
}
impl Drop for BridgeIo {
  fn drop(&mut self) {
    self.shutdown.shutdown();
  }
}
