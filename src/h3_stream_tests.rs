use crate::h3_stream::{
  H3BidirectionalStream, H3ClientBidiStream, H3ServerBidiStream,
};

fn assert_send<T: Send>() {}

fn assert_sync<T: Sync>() {}

fn assert_unpin<T: Unpin>() {}

#[test]
fn test_h3_bidirectional_stream_new_accepts_owned_halves() {
  struct SendHalf;
  struct RecvHalf;

  let _stream = H3BidirectionalStream::new(SendHalf, RecvHalf);
}

#[test]
fn test_h3_client_bidi_stream_satisfies_runtime_bounds() {
  assert_send::<H3ClientBidiStream>();
  assert_unpin::<H3ClientBidiStream>();
}

#[test]
fn test_h3_server_bidi_stream_satisfies_extension_bounds() {
  assert_send::<H3ServerBidiStream>();
  assert_sync::<H3ServerBidiStream>();
  assert_unpin::<H3ServerBidiStream>();
}

use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::h3_stream::{H3Recv, H3Send};

struct SendHalf {
  data: Arc<Mutex<Vec<Bytes>>>,
}
impl H3Send for SendHalf {
  async fn send_data(&mut self, bytes: Bytes) -> std::io::Result<()> {
    tokio::task::yield_now().await;
    self.data.lock().unwrap().push(bytes);
    Ok(())
  }

  async fn finish(&mut self) -> std::io::Result<()> {
    Ok(())
  }
}
struct RecvHalf;
impl H3Recv for RecvHalf {
  fn poll_recv_data(
    &mut self,
    _cx: &mut Context<'_>,
  ) -> Poll<std::io::Result<Option<Bytes>>> {
    Poll::Pending
  }
}

#[tokio::test]
async fn test_write_flush_and_shutdown_preserve_buffered_data() {
  let data = Arc::new(Mutex::new(Vec::new()));
  let mut stream = H3BidirectionalStream::new(
    SendHalf { data: data.clone() },
    RecvHalf,
  );
  stream.write_all(b"first").await.unwrap();
  stream.flush().await.unwrap();
  assert_eq!(*data.lock().unwrap(), vec![Bytes::from_static(b"first")]);
  stream.write_all(b"second").await.unwrap();
  stream.shutdown().await.unwrap();
  stream.shutdown().await.unwrap();
  assert_eq!(data.lock().unwrap().len(), 2);
  assert_eq!(
    stream.write(b"late").await.unwrap_err().kind(),
    std::io::ErrorKind::BrokenPipe
  );
}

#[tokio::test]
async fn test_read_empty_buffer_completes_without_peer_data() {
  let mut stream = H3BidirectionalStream::new(
    SendHalf { data: Default::default() },
    RecvHalf,
  );
  assert_eq!(
    tokio::time::timeout(
      std::time::Duration::from_millis(50),
      stream.read(&mut [])
    )
    .await
    .unwrap()
    .unwrap(),
    0
  );
}
