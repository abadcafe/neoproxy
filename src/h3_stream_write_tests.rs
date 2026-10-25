//! Black-box AsyncWrite contracts over controllable H3 send halves.

use std::collections::VecDeque;
use std::io::{Error, ErrorKind, Result};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use tokio::io::AsyncWriteExt;
use tokio::sync::oneshot;

use crate::h3_stream::{H3BidirectionalStream, H3Send};

#[derive(Default)]
struct Observations {
  data: Vec<Bytes>,
  finishes: usize,
}

struct ControlledSend {
  sends: VecDeque<oneshot::Receiver<Result<()>>>,
  finish: Option<oneshot::Receiver<Result<()>>>,
  observations: Arc<Mutex<Observations>>,
}

impl H3Send for ControlledSend {
  async fn send_data(&mut self, data: Bytes) -> Result<()> {
    self
      .sends
      .pop_front()
      .expect("unexpected extra send")
      .await
      .unwrap()?;
    self.observations.lock().unwrap().data.push(data);
    Ok(())
  }

  async fn finish(&mut self) -> Result<()> {
    self.observations.lock().unwrap().finishes += 1;
    self.finish.take().expect("finish called twice").await.unwrap()
  }
}

struct Control {
  sends: VecDeque<oneshot::Sender<Result<()>>>,
  finish: Option<oneshot::Sender<Result<()>>>,
  observations: Arc<Mutex<Observations>>,
}

impl Control {
  fn complete_send(&mut self, result: Result<()>) {
    self.sends.pop_front().unwrap().send(result).unwrap();
  }

  fn complete_finish(&mut self, result: Result<()>) {
    self.finish.take().unwrap().send(result).unwrap();
  }

  fn data(&self) -> Vec<Bytes> {
    self.observations.lock().unwrap().data.clone()
  }

  fn finishes(&self) -> usize {
    self.observations.lock().unwrap().finishes
  }
}

fn controlled_stream(
  sends: usize,
) -> (H3BidirectionalStream<ControlledSend, ()>, Control) {
  let observations = Arc::new(Mutex::new(Observations::default()));
  let (senders, receivers) =
    (0..sends).map(|_| oneshot::channel()).unzip();
  let (finish_tx, finish_rx) = oneshot::channel();
  (
    H3BidirectionalStream::new(
      ControlledSend {
        sends: receivers,
        finish: Some(finish_rx),
        observations: observations.clone(),
      },
      (),
    ),
    Control { sends: senders, finish: Some(finish_tx), observations },
  )
}

#[tokio::test]
async fn test_write_cancelled_pending_call_never_accepts_its_buffer() {
  let (mut stream, mut control) = controlled_stream(2);
  let first = vec![b'A'; 4096];
  assert_eq!(stream.write(&first).await.unwrap(), first.len());
  {
    let mut cancelled =
      std::pin::pin!(stream.write(b"abandoned-buffer"));
    assert!(futures::poll!(&mut cancelled).is_pending());
  }
  control.complete_send(Ok(()));
  // A different caller's shorter buffer must receive its own length.
  assert_eq!(stream.write(b"B").await.unwrap(), 1);
  control.complete_send(Ok(()));
  stream.flush().await.unwrap();
  assert_eq!(
    control.data(),
    vec![Bytes::from(first), Bytes::from_static(b"B")]
  );
}

#[tokio::test]
async fn test_write_all_bounds_each_accepted_chunk_and_preserves_order()
{
  let (mut stream, mut control) = controlled_stream(4);
  let payload: Vec<u8> =
    (0..(3 * 65536 + 17)).map(|index| (index % 251) as u8).collect();
  for _ in 0..4 {
    control.complete_send(Ok(()));
  }
  stream.write_all(&payload).await.unwrap();
  stream.flush().await.unwrap();
  let data = control.data();
  assert_eq!(
    data.iter().map(Bytes::len).collect::<Vec<_>>(),
    vec![65536, 65536, 65536, 17]
  );
  assert_eq!(data.concat(), payload);
}

#[tokio::test]
async fn test_flush_waits_for_accepted_bytes_and_can_resume_after_cancellation()
 {
  let (mut stream, mut control) = controlled_stream(1);
  stream.write_all(b"accepted").await.unwrap();
  {
    let mut flush = std::pin::pin!(stream.flush());
    assert!(futures::poll!(&mut flush).is_pending());
    assert!(control.data().is_empty());
  }
  control.complete_send(Ok(()));
  stream.flush().await.unwrap();
  stream.flush().await.unwrap();
  assert_eq!(control.data(), vec![Bytes::from_static(b"accepted")]);
}

#[tokio::test]
async fn test_shutdown_waits_for_data_then_finish_and_remains_closed() {
  let (mut stream, mut control) = controlled_stream(1);
  stream.write_all(b"tail").await.unwrap();
  {
    let mut shutdown = std::pin::pin!(stream.shutdown());
    assert!(futures::poll!(&mut shutdown).is_pending());
    assert_eq!(control.finishes(), 0);
    control.complete_send(Ok(()));
    assert!(futures::poll!(&mut shutdown).is_pending());
    assert_eq!(control.data(), vec![Bytes::from_static(b"tail")]);
    assert_eq!(control.finishes(), 1);
    control.complete_finish(Ok(()));
    shutdown.await.unwrap();
  }
  stream.shutdown().await.unwrap();
  assert_eq!(control.finishes(), 1);
  assert_eq!(
    stream.write(b"late").await.unwrap_err().kind(),
    ErrorKind::BrokenPipe
  );
}

#[tokio::test]
async fn test_write_during_cancelled_shutdown_is_rejected_and_flush_completes_finish()
 {
  let (mut stream, mut control) = controlled_stream(0);
  {
    let mut shutdown = std::pin::pin!(stream.shutdown());
    assert!(futures::poll!(&mut shutdown).is_pending());
  }
  assert_eq!(
    stream.write(b"late").await.unwrap_err().kind(),
    ErrorKind::BrokenPipe
  );
  {
    let mut flush = std::pin::pin!(stream.flush());
    assert!(futures::poll!(&mut flush).is_pending());
    control.complete_finish(Ok(()));
    flush.await.unwrap();
  }
  stream.shutdown().await.unwrap();
  assert_eq!(control.finishes(), 1);
}

#[tokio::test]
async fn test_flush_propagates_send_error_and_closes_write_side() {
  let (mut stream, mut control) = controlled_stream(1);
  stream.write_all(b"buffered").await.unwrap();
  control.complete_send(Err(Error::new(
    ErrorKind::ConnectionReset,
    "send failed",
  )));
  let error = stream.flush().await.unwrap_err();
  assert_eq!(error.kind(), ErrorKind::ConnectionReset);
  assert_eq!(error.to_string(), "send failed");
  assert!(control.data().is_empty());
  assert_eq!(control.finishes(), 0);
  assert_eq!(
    stream.write(b"late").await.unwrap_err().kind(),
    ErrorKind::BrokenPipe
  );
}

#[tokio::test]
async fn test_write_propagates_previous_send_error_without_accepting_new_data()
 {
  let (mut stream, mut control) = controlled_stream(1);
  stream.write_all(b"first").await.unwrap();
  control.complete_send(Err(Error::new(
    ErrorKind::ConnectionReset,
    "previous send failed",
  )));
  let error = stream.write(b"must-not-send").await.unwrap_err();
  assert_eq!(error.kind(), ErrorKind::ConnectionReset);
  assert_eq!(error.to_string(), "previous send failed");
  assert!(control.data().is_empty());
}

#[tokio::test]
async fn test_shutdown_propagates_pending_send_error_without_calling_finish()
 {
  let (mut stream, mut control) = controlled_stream(1);
  stream.write_all(b"tail").await.unwrap();
  let mut shutdown = std::pin::pin!(stream.shutdown());
  assert!(futures::poll!(&mut shutdown).is_pending());
  control.complete_send(Err(Error::new(
    ErrorKind::ConnectionReset,
    "tail failed",
  )));
  let error = shutdown.await.unwrap_err();
  assert_eq!(error.kind(), ErrorKind::ConnectionReset);
  assert_eq!(error.to_string(), "tail failed");
  assert_eq!(control.finishes(), 0);
}

#[tokio::test]
async fn test_shutdown_propagates_finish_error_and_never_restarts_finish()
 {
  let (mut stream, mut control) = controlled_stream(0);
  {
    let mut shutdown = std::pin::pin!(stream.shutdown());
    assert!(futures::poll!(&mut shutdown).is_pending());
    control.complete_finish(Err(Error::new(
      ErrorKind::ConnectionAborted,
      "finish failed",
    )));
    let error = shutdown.await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ConnectionAborted);
    assert_eq!(error.to_string(), "finish failed");
  }
  stream.shutdown().await.unwrap();
  assert_eq!(control.finishes(), 1);
  assert_eq!(
    stream.write(b"late").await.unwrap_err().kind(),
    ErrorKind::BrokenPipe
  );
}

#[tokio::test]
async fn test_empty_write_does_not_enqueue_data_or_advance_send() {
  let (mut stream, control) = controlled_stream(1);
  assert_eq!(stream.write(b"").await.unwrap(), 0);
  stream.write_all(b"accepted").await.unwrap();
  assert_eq!(stream.write(b"").await.unwrap(), 0);
  assert!(control.data().is_empty());
  assert_eq!(control.finishes(), 0);
}
