//! module: transport
//! responsibility: retain physical connection observations with proxy
//! I/O public operations: ProxyTransport::{new,into_parts}, ProxyIo and
//! Hyper I/O data entities: ProxyTransport
//! tests: connector_tests.rs and HTTP proxy process tests
use std::pin::Pin;
use std::task::{Context, Poll};

use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};

use super::super::observation::ConnectionObservation;

pub(crate) struct ProxyTransport<T> {
  io: TokioIo<T>,
  observation: ConnectionObservation,
}
impl<T> ProxyTransport<T> {
  pub(super) fn new(io: T, observation: ConnectionObservation) -> Self {
    Self { io: TokioIo::new(io), observation }
  }

  pub(super) fn into_parts(self) -> (T, ConnectionObservation) {
    (self.io.into_inner(), self.observation)
  }
}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>
  super::super::transport_io::ProxyIo for ProxyTransport<T>
{
  fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> {
    self.observation.peer().ok_or_else(|| {
      std::io::Error::new(
        std::io::ErrorKind::NotConnected,
        "missing connected peer",
      )
    })
  }

  fn observation(&self) -> ConnectionObservation {
    self.observation.clone()
  }
}
impl<T: AsyncRead + Unpin> hyper::rt::Read for ProxyTransport<T> {
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buffer: hyper::rt::ReadBufCursor<'_>,
  ) -> Poll<std::io::Result<()>> {
    Pin::new(&mut self.io).poll_read(cx, buffer)
  }
}
impl<T: AsyncWrite + Unpin> hyper::rt::Write for ProxyTransport<T> {
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
    Pin::new(&mut self.io).poll_shutdown(cx)
  }

  fn is_write_vectored(&self) -> bool {
    self.io.is_write_vectored()
  }

  fn poll_write_vectored(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    bytes: &[std::io::IoSlice<'_>],
  ) -> Poll<std::io::Result<usize>> {
    Pin::new(&mut self.io).poll_write_vectored(cx, bytes)
  }
}
