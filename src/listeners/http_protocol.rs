//! module: http_protocol
//! responsibility: select HTTP framing while retaining pre-read bytes
//! public operations: detect, Protocol, PrefixedIo
//! data entities: Protocol, PrefixedIo
//! tests: http_protocol_tests.rs, test_listener_io_timeout.py
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
pub(super) enum Protocol {
  Http1,
  Http2,
}
pub(super) struct PrefixedIo<I> {
  inner: I,
  prefix: bytes::Bytes,
}
pub(super) async fn detect<I: AsyncRead + Unpin>(
  mut inner: I,
) -> std::io::Result<(Protocol, PrefixedIo<I>)> {
  let mut prefix = [0; 24];
  let mut length = 0;
  while length < PREFACE.len() {
    let read = inner.read(&mut prefix[length..]).await?;
    length += read;
    if read == 0 || prefix[..length] != PREFACE[..length] {
      break;
    }
  }
  let protocol = if prefix.as_slice() == PREFACE {
    Protocol::Http2
  } else {
    Protocol::Http1
  };
  Ok((
    protocol,
    PrefixedIo {
      inner,
      prefix: bytes::Bytes::copy_from_slice(&prefix[..length]),
    },
  ))
}
impl<I: AsyncRead + Unpin> AsyncRead for PrefixedIo<I> {
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
  ) -> Poll<std::io::Result<()>> {
    if !self.prefix.is_empty() {
      let count = self.prefix.len().min(buf.remaining());
      buf.put_slice(&self.prefix.split_to(count));
      return Poll::Ready(Ok(()));
    }
    Pin::new(&mut self.inner).poll_read(cx, buf)
  }
}
impl<I: AsyncWrite + Unpin> AsyncWrite for PrefixedIo<I> {
  fn poll_write(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    data: &[u8],
  ) -> Poll<std::io::Result<usize>> {
    Pin::new(&mut self.inner).poll_write(cx, data)
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

  fn is_write_vectored(&self) -> bool {
    self.inner.is_write_vectored()
  }

  fn poll_write_vectored(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    data: &[std::io::IoSlice<'_>],
  ) -> Poll<std::io::Result<usize>> {
    Pin::new(&mut self.inner).poll_write_vectored(cx, data)
  }
}
