//! Black-box reads over scripted H3 receive halves.

use std::collections::VecDeque;
use std::io::{Error, ErrorKind, Result};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};

use crate::h3_stream::{H3BidirectionalStream, H3Recv};

struct ScriptedRecv {
  chunks: VecDeque<Result<Option<Bytes>>>,
  polls: Arc<AtomicUsize>,
}

impl H3Recv for ScriptedRecv {
  fn poll_recv_data(
    &mut self,
    _: &mut Context<'_>,
  ) -> Poll<Result<Option<Bytes>>> {
    self.polls.fetch_add(1, Ordering::Relaxed);
    Poll::Ready(self.chunks.pop_front().unwrap_or(Ok(None)))
  }
}

#[test]
fn test_read_full_buffer_returns_without_polling_receive_half() {
  let polls = Arc::new(AtomicUsize::new(0));
  let mut stream = H3BidirectionalStream::new(
    (),
    ScriptedRecv {
      chunks: VecDeque::from([Err(Error::other("must not receive"))]),
      polls: polls.clone(),
    },
  );
  let mut memory = [0; 2];
  let mut buffer = ReadBuf::new(&mut memory);
  buffer.put_slice(b"ab");
  let mut cx = Context::from_waker(Waker::noop());
  assert!(matches!(
    Pin::new(&mut stream).poll_read(&mut cx, &mut buffer),
    Poll::Ready(Ok(()))
  ));
  assert_eq!(buffer.filled(), b"ab");
  assert_eq!(polls.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn test_read_partial_frame_and_empty_read_preserve_remaining_bytes()
 {
  let polls = Arc::new(AtomicUsize::new(0));
  let mut stream = H3BidirectionalStream::new(
    (),
    ScriptedRecv {
      chunks: VecDeque::from([Ok(Some(Bytes::from_static(
        b"abcdefgh",
      )))]),
      polls: polls.clone(),
    },
  );
  let mut prefix = [0; 3];
  stream.read_exact(&mut prefix).await.unwrap();
  assert_eq!(&prefix, b"abc");
  assert_eq!(stream.read(&mut []).await.unwrap(), 0);
  let mut suffix = [0; 5];
  stream.read_exact(&mut suffix).await.unwrap();
  assert_eq!(&suffix, b"defgh");
  assert_eq!(polls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn test_read_empty_data_frames_do_not_become_eof() {
  let mut stream = H3BidirectionalStream::new(
    (),
    ScriptedRecv {
      chunks: VecDeque::from([
        Ok(Some(Bytes::new())),
        Ok(Some(Bytes::new())),
        Ok(Some(Bytes::from_static(b"data"))),
        Ok(None),
      ]),
      polls: Arc::default(),
    },
  );
  let mut data = Vec::new();
  assert_eq!(stream.read_to_end(&mut data).await.unwrap(), 4);
  assert_eq!(data, b"data");
}

#[tokio::test]
async fn test_read_propagates_receive_error() {
  let mut stream = H3BidirectionalStream::new(
    (),
    ScriptedRecv {
      chunks: VecDeque::from([Err(Error::new(
        ErrorKind::ConnectionReset,
        "receive failed",
      ))]),
      polls: Arc::default(),
    },
  );
  let error = stream.read(&mut [0; 4]).await.unwrap_err();
  assert_eq!(error.kind(), ErrorKind::ConnectionReset);
  assert_eq!(error.to_string(), "receive failed");
}
