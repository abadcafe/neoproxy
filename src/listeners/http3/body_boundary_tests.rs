//! Black-box contract for completing a length-delimited streaming body.
use bytes::Bytes;
use futures_util::{StreamExt, stream};
use http_body::Frame;
use http_body_util::{BodyExt, StreamBody};

use super::body_boundary::BodyBoundary;

#[tokio::test]
async fn test_new_streams_early_frames_but_waits_for_completion() {
  let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
  let rx = stream::poll_fn(move |cx| rx.poll_recv(cx));
  let mut body = BodyBoundary::new(StreamBody::new(rx), Some(2));
  tx.send(Ok::<_, anyhow::Error>(Frame::data(Bytes::from_static(
    b"a",
  ))))
  .unwrap();
  assert_eq!(
    body.frame().await.unwrap().unwrap().into_data().unwrap(),
    "a"
  );
  tx.send(Ok(Frame::data(Bytes::from_static(b"b")))).unwrap();
  assert!(futures_util::poll!(body.frame()).is_pending());
  drop(tx);
  assert_eq!(
    body.frame().await.unwrap().unwrap().into_data().unwrap(),
    "b"
  );
  assert!(body.frame().await.is_none());
}

#[tokio::test]
async fn test_new_rejects_short_and_excess_lengths() {
  for length in [0, 2] {
    let frames = stream::iter([Ok::<_, anyhow::Error>(Frame::data(
      Bytes::from_static(b"a"),
    ))]);
    let body = BodyBoundary::new(StreamBody::new(frames), Some(length));
    assert!(body.collect().await.is_err());
  }
}

#[tokio::test]
async fn test_new_preserves_trailers_with_known_and_unknown_length() {
  for length in [Some(1), None] {
    let mut trailers = http::HeaderMap::new();
    trailers.insert("checksum", "ok".parse().unwrap());
    let frames = stream::iter([
      Ok::<_, anyhow::Error>(Frame::data(Bytes::from_static(b"a"))),
      Ok(Frame::trailers(trailers.clone())),
    ]);
    let collected = BodyBoundary::new(StreamBody::new(frames), length)
      .collect()
      .await
      .unwrap();
    assert_eq!(collected.trailers(), Some(&trailers));
    assert_eq!(collected.to_bytes(), "a");
  }
}

#[tokio::test]
async fn test_new_propagates_error_without_releasing_final_frame() {
  let frames = stream::iter([
    Ok(Frame::data(Bytes::from_static(b"a"))),
    Err(anyhow::anyhow!("receive failed")),
  ]);
  let mut body = BodyBoundary::new(StreamBody::new(frames), Some(1));
  assert!(body.frame().await.unwrap().is_err());
  assert!(body.frame().await.is_none());
}

#[tokio::test]
async fn test_new_accepts_empty_body() {
  let frames =
    stream::empty::<Result<Frame<Bytes>, anyhow::Error>>().boxed();
  assert!(
    BodyBoundary::new(StreamBody::new(frames), Some(0))
      .collect()
      .await
      .unwrap()
      .to_bytes()
      .is_empty()
  );
}
