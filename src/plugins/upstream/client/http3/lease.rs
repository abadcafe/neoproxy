//! module: lease
//! responsibility: keep an H3 session active for a response or tunnel
//! lifetime public operations: SessionLease::{new,attach}
//! data entities: SessionLease, LeasedIo
//! tests: H3 pool process contracts
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::super::observation::ConnectionObservation;
use super::io_progress::SendBuffer;
pub(super) struct Session {
  pub(super) connection: quinn::Connection,
  pub(super) sender:
    h3::client::SendRequest<super::read_progress::Opener, SendBuffer>,
  pub(super) observation: ConnectionObservation,
  pub(super) reads: super::read_progress::Registry,
  pub(super) hostname: Option<String>,
  pub(super) draining: AtomicBool,
  active: AtomicUsize,
  used: Mutex<tokio::time::Instant>,
  _permit: tokio::sync::OwnedSemaphorePermit,
}
impl Session {
  pub(super) fn new(
    connection: quinn::Connection,
    sender: h3::client::SendRequest<
      super::read_progress::Opener,
      SendBuffer,
    >,
    observation: ConnectionObservation,
    reads: super::read_progress::Registry,
    hostname: Option<String>,
    permit: tokio::sync::OwnedSemaphorePermit,
  ) -> Arc<Self> {
    Arc::new(Self {
      connection,
      sender,
      observation,
      reads,
      hostname,
      draining: AtomicBool::new(false),
      active: AtomicUsize::new(0),
      used: Mutex::new(tokio::time::Instant::now()),
      _permit: permit,
    })
  }

  pub(super) fn acquire(&self) {
    self.active.fetch_add(1, Ordering::AcqRel);
  }

  pub(super) fn release(&self) {
    *self.used.lock().expect("H3 activity poisoned") =
      tokio::time::Instant::now();
    self.active.fetch_sub(1, Ordering::AcqRel);
  }

  pub(super) fn expired(&self, timeout: Duration) -> bool {
    self.connection.close_reason().is_some()
      || (self.active.load(Ordering::Acquire) == 0
        && (self.draining.load(Ordering::Acquire)
          || self.used.lock().expect("H3 activity poisoned").elapsed()
            >= timeout))
  }
}

use crate::stream::Io;
pub(in crate::plugins::upstream::client) struct SessionLease {
  session: Arc<Session>,
}
impl SessionLease {
  pub(super) fn session(&self) -> &Session {
    &self.session
  }

  pub(super) fn new(session: Arc<Session>) -> Self {
    session.acquire();
    Self { session }
  }
}
impl Drop for SessionLease {
  fn drop(&mut self) {
    self.session.release();
  }
}
impl SessionLease {
  pub(in crate::plugins::upstream::client) fn attach<T: Io>(
    self,
    transport: T,
  ) -> impl Io {
    LeasedIo { inner: transport, _lease: self }
  }
}

struct LeasedIo<T> {
  inner: T,
  _lease: SessionLease,
}
impl<T: AsyncRead + Unpin> AsyncRead for LeasedIo<T> {
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buffer: &mut ReadBuf<'_>,
  ) -> Poll<std::io::Result<()>> {
    Pin::new(&mut self.inner).poll_read(cx, buffer)
  }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for LeasedIo<T> {
  fn poll_write(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buffer: &[u8],
  ) -> Poll<std::io::Result<usize>> {
    Pin::new(&mut self.inner).poll_write(cx, buffer)
  }

  fn poll_flush(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<std::io::Result<()>> {
    Pin::new(&mut self.inner).poll_flush(cx)
  }

  fn poll_shutdown(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<std::io::Result<()>> {
    Pin::new(&mut self.inner).poll_shutdown(cx)
  }
}
