use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::write_deadline::{Control, TimedIo};
#[tokio::test(start_paused = true)]
async fn test_blocked_write_times_out_and_progress_resets_deadline() {
  let (io, mut peer) = tokio::io::duplex(1);
  let mut io =
    TimedIo::new(io, Duration::from_secs(1), Control::default());
  io.write_all(b"x").await.unwrap();
  assert_eq!(
    io.write_all(b"y").await.unwrap_err().kind(),
    std::io::ErrorKind::TimedOut
  );
  let mut byte = [0];
  peer.read_exact(&mut byte).await.unwrap();
  io.write_all(b"z").await.unwrap();
}
#[tokio::test(start_paused = true)]
async fn test_disabled_write_deadline_allows_tunnel_idle_time() {
  let control = Control::default();
  let (io, mut peer) = tokio::io::duplex(1);
  let mut io =
    TimedIo::new(io, Duration::from_secs(1), control.clone());
  control.disable();
  let sending = io.write_all(b"xy");
  let receiving = async {
    tokio::time::sleep(Duration::from_secs(3)).await;
    let mut data = [0; 2];
    peer.read_exact(&mut data).await.unwrap();
    assert_eq!(&data, b"xy");
  };
  let (result, ()) = tokio::join!(sending, receiving);
  result.unwrap();
}
