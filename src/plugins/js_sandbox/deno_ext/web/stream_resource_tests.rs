use std::cell::OnceCell;
use std::sync::OnceLock;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use deno_core::v8;

use super::stream_resource::*;

static V8_GLOBAL: OnceLock<()> = OnceLock::new();

thread_local! {
  static ISOLATE: OnceCell<std::sync::Mutex<v8::OwnedIsolate>> = const { OnceCell::new() };
}

fn with_isolate<T>(mut f: impl FnMut(&mut v8::Isolate) -> T) -> T {
  V8_GLOBAL.get_or_init(|| {
    let platform =
      v8::new_unprotected_default_platform(0, false).make_shared();
    v8::V8::initialize_platform(platform);
    v8::V8::initialize();
  });
  ISOLATE.with(|cell| {
    let mut isolate = cell
      .get_or_init(|| {
        std::sync::Mutex::new(v8::Isolate::new(Default::default()))
      })
      .try_lock()
      .unwrap();
    f(&mut isolate)
  })
}

fn create_buffer(byte_length: usize) -> V8Slice<u8> {
  with_isolate(|isolate| {
    let ptr = v8::ArrayBuffer::new_backing_store(isolate, byte_length);
    // SAFETY: we just made this
    unsafe { V8Slice::from_parts(ptr.into(), 0..byte_length) }
  })
}

#[test]
fn test_bounded_buffer_channel() {
  let channel = BoundedBufferChannel::default();

  for _ in 0..BUFFER_CHANNEL_SIZE - 1 {
    channel.write(create_buffer(1024)).unwrap();
  }
}

#[tokio::test(flavor = "current_thread")]
async fn test_multi_task() {
  let channel = BoundedBufferChannel::default();
  let channel_send = channel.clone();

  // Fast writer
  let a = deno_core::unsync::spawn(async move {
    for _ in 0..BUFFER_CHANNEL_SIZE * 2 {
      poll_fn(|cx| channel_send.poll_write_ready(cx)).await;
      channel_send
        .write(create_buffer(BUFFER_AGGREGATION_LIMIT))
        .unwrap();
    }
  });

  // Slightly slower reader
  let b = deno_core::unsync::spawn(async move {
    for _ in 0..BUFFER_CHANNEL_SIZE * 2 {
      if cfg!(windows) {
        // windows has ~15ms resolution on sleep, so just yield so
        // this test doesn't take 30 seconds to run
        tokio::task::yield_now().await;
      } else {
        tokio::time::sleep(Duration::from_millis(1)).await;
      }
      poll_fn(|cx| channel.poll_read_ready(cx)).await;
      channel.read(BUFFER_AGGREGATION_LIMIT).unwrap();
    }
  });

  a.await.unwrap();
  b.await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn test_multi_task_small_reads() {
  let channel = BoundedBufferChannel::default();
  let channel_send = channel.clone();

  let total_send = Rc::new(AtomicUsize::new(0));
  let total_send_task = total_send.clone();
  let total_recv = Rc::new(AtomicUsize::new(0));
  let total_recv_task = total_recv.clone();

  // Fast writer
  let a = deno_core::unsync::spawn(async move {
    for _ in 0..BUFFER_CHANNEL_SIZE * 2 {
      poll_fn(|cx| channel_send.poll_write_ready(cx)).await;
      channel_send.write(create_buffer(16)).unwrap();
      total_send_task.fetch_add(16, std::sync::atomic::Ordering::SeqCst);
    }
    // We need to close because we may get aggregated packets and we want a signal
    channel_send.close();
  });

  // Slightly slower reader
  let b = deno_core::unsync::spawn(async move {
    for _ in 0..BUFFER_CHANNEL_SIZE * 2 {
      poll_fn(|cx| channel.poll_read_ready(cx)).await;
      // We want to make sure we're aggregating at least some packets
      while channel.byte_size() <= 16 && !channel.closed() {
        tokio::time::sleep(Duration::from_millis(1)).await;
      }
      let len = channel
        .read(1024)
        .unwrap()
        .map(|b| b.len())
        .unwrap_or_default();
      total_recv_task.fetch_add(len, std::sync::atomic::Ordering::SeqCst);
    }
  });

  a.await.unwrap();
  b.await.unwrap();

  assert_eq!(
    total_send.load(std::sync::atomic::Ordering::SeqCst),
    total_recv.load(std::sync::atomic::Ordering::SeqCst)
  );
}
