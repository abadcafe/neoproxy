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
