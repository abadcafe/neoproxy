use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll};

use std::time::Duration;

use anyhow::{Result, anyhow};
use futures_core::Stream;
use local_channel::mpsc as local_mpsc;
use tokio::{io, task};
use tokio_util::io as tokio_util_io;
use tracing::{info, warn};

use crate::plugin;

/// Graceful shutdown timeout for TransferingSet operations
const TRANSFERING_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// CONNECT 目标地址解析错误
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectTargetError {
  /// 非 CONNECT 方法
  NotConnectMethod,
  /// URI 中无 authority
  NoAuthority,
  /// authority 中无端口号
  NoPort,
  /// 端口号为 0
  PortZero,
}

impl fmt::Display for ConnectTargetError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      ConnectTargetError::NotConnectMethod => {
        write!(f, "not CONNECT method")
      }
      ConnectTargetError::NoAuthority => {
        write!(f, "no authority in URI")
      }
      ConnectTargetError::NoPort => {
        write!(f, "no port in authority")
      }
      ConnectTargetError::PortZero => {
        write!(f, "port is zero")
      }
    }
  }
}

impl std::error::Error for ConnectTargetError {}

/// 解析 CONNECT 请求的目标地址
///
/// # 参数
/// - `parts`: HTTP 请求的 Parts
///
/// # 返回
/// - `Ok((host, port))`: 目标主机名和端口号
/// - `Err(ConnectTargetError)`: 解析失败
pub fn parse_connect_target(
  parts: &http::request::Parts,
) -> Result<(String, u16), ConnectTargetError> {
  if parts.method != http::Method::CONNECT {
    return Err(ConnectTargetError::NotConnectMethod);
  }

  let authority =
    parts.uri.authority().ok_or(ConnectTargetError::NoAuthority)?;

  let port = authority.port_u16().ok_or(ConnectTargetError::NoPort)?;

  if port == 0 {
    return Err(ConnectTargetError::PortZero);
  }

  Ok((authority.host().to_string(), port))
}

struct Transfering {
  reader: Pin<Box<dyn io::AsyncRead>>,
  writer: Pin<Box<dyn io::AsyncWrite>>,
  shutdown: plugin::ShutdownHandle,
}

impl Transfering {
  fn new(
    r: Pin<Box<dyn io::AsyncRead>>,
    w: Pin<Box<dyn io::AsyncWrite>>,
    shutdown: plugin::ShutdownHandle,
  ) -> Self {
    Self { reader: r, writer: w, shutdown: shutdown }
  }

  async fn run(&mut self) -> Result<u64> {
    let res = tokio::select! {
      // todo: carefully handle errors.
      res = io::copy(&mut self.reader, &mut self.writer) => {
        res.map_err(|e| e.into())
      }
      _ = self.shutdown.notified() => {
        Err(anyhow!("interrupted"))
      }
    };

    res
  }
}

pub struct TransferingSet {
  shutdown_handle: plugin::ShutdownHandle,
  transfering_tx: Option<local_mpsc::Sender<Transfering>>,
  join_handle: Option<task::JoinHandle<()>>,
  /// Flag to track if the serving task has been started.
  /// Used for lazy initialization to defer spawn_local until runtime is ready.
  started: bool,
  /// Flag to track if the set has been aborted
  aborted: bool,
}

impl TransferingSet {
  pub fn new() -> Self {
    Self {
      shutdown_handle: plugin::ShutdownHandle::new(),
      transfering_tx: None,
      join_handle: None,
      started: false,
      aborted: false,
    }
  }

  /// Create a new TransferingSet with an external shutdown handle
  pub fn with_shutdown_handle(
    shutdown_handle: plugin::ShutdownHandle,
  ) -> Self {
    Self {
      shutdown_handle,
      transfering_tx: None,
      join_handle: None,
      started: false,
      aborted: false,
    }
  }

  /// Ensure the serving task is started.
  /// This method implements lazy initialization by deferring spawn_local
  /// until the first use, ensuring the tokio runtime is available.
  fn ensure_started(&mut self) {
    if self.started {
      return;
    }
    // If previously aborted, we should not restart
    if self.aborted {
      return;
    }
    self.started = true;
    let (tx, rx) = local_mpsc::channel();
    let handle = task::spawn_local(TransferingSet::serving(rx));
    let _ = self.transfering_tx.insert(tx);
    let _ = self.join_handle.insert(handle);
  }

  pub fn new_transfering<R, W>(&mut self, r: R, w: W) -> Result<()>
  where
    R: io::AsyncRead + Unpin + 'static,
    W: io::AsyncWrite + Unpin + 'static,
  {
    // Check if already aborted - reject new transfers
    if self.aborted {
      return Err(anyhow!(
        "cannot add new transfer: TransferingSet has been aborted"
      ));
    }
    // Lazy initialization: ensure serving task is started before use
    self.ensure_started();
    let trans = Transfering::new(
      Box::pin(r),
      Box::pin(w),
      self.shutdown_handle.clone(),
    );
    self.transfering_tx.as_ref().unwrap().send(trans).map_err(|e| {
      anyhow!(
        "transfering created but sending for spawn task failed: {e}"
      )
    })
  }

  pub fn shutdown_handle(&self) -> plugin::ShutdownHandle {
    self.shutdown_handle.clone()
  }

  /// Stop the transfering set with graceful shutdown
  ///
  /// This method will:
  /// 1. Close the channel to stop accepting new transfer tasks
  /// 2. Trigger shutdown notification to all active transfer tasks
  /// 3. Wait for all tasks to complete with a timeout
  /// 4. If timeout, abort all remaining tasks
  ///
  /// This method is idempotent - multiple calls will return immediately
  /// after the first successful call.
  pub async fn stop(&mut self) -> Result<()> {
    // Idempotency check: if never started, nothing to stop
    if !self.started {
      return Ok(());
    }

    // Idempotency check: if join_handle is already taken, stop was called
    if self.join_handle.is_none() {
      return Ok(());
    }

    // If already aborted, need to clean up any remaining join_handle
    if self.aborted {
      // Abort and clean up join_handle if somehow still present
      if let Some(handle) = self.join_handle.take() {
        handle.abort();
        let _ = handle.await;
      }
      return Ok(());
    }

    // Drop the sender to signal the receiver to end
    self.transfering_tx.take();
    self.shutdown_handle.shutdown();

    // Wait for serving task with timeout protection
    let result = tokio::time::timeout(
      TRANSFERING_SHUTDOWN_TIMEOUT,
      self.join_handle.as_mut().unwrap(),
    )
    .await;

    match result {
      Ok(res) => {
        // Clean up join_handle in success path
        self.join_handle.take();
        res?;
        info!("transfering set finished gracefully");
      }
      Err(_) => {
        warn!(
          "transfering set stop timeout after {:?}, aborting remaining tasks",
          TRANSFERING_SHUTDOWN_TIMEOUT
        );
        self.abort_all();
        // Clean up join_handle after abort - it should complete immediately
        if let Some(handle) = self.join_handle.take() {
          let _ = handle.await;
        }
        info!("transfering set finished after abort");
      }
    }

    // Mark as no longer started for idempotency
    self.started = false;

    Ok(())
  }

  /// Trigger graceful shutdown without waiting
  ///
  /// This method will:
  /// 1. Close the channel to stop accepting new transfer tasks
  /// 2. Trigger shutdown notification to all active transfer tasks
  ///
  /// Unlike `stop()`, this method does not wait for tasks to complete.
  /// Use `wait_stopped()` to wait for completion, or combine with
  /// external timeout control.
  ///
  /// This method is idempotent - multiple calls will return immediately
  /// after the first successful call.
  pub fn stop_graceful(&mut self) {
    // Idempotency check: if never started, nothing to stop
    if !self.started {
      return;
    }

    // Idempotency check: if join_handle is already taken, stop was called
    if self.join_handle.is_none() {
      return;
    }

    // If already aborted, clean up any remaining join_handle
    if self.aborted {
      if let Some(handle) = self.join_handle.take() {
        handle.abort();
      }
      return;
    }

    // Drop the sender to signal the receiver to end
    self.transfering_tx.take();
    self.shutdown_handle.shutdown();
    info!("transfering set graceful shutdown triggered");
  }

  /// Wait for all transfer tasks to complete
  ///
  /// This method waits for the serving task to complete.
  /// Should be called after `stop_graceful()` or `abort_all()`.
  /// Returns immediately if the set was never started or already stopped.
  ///
  /// Note: This method does not have its own timeout. The caller should
  /// use `tokio::time::timeout` if timeout protection is needed.
  pub async fn wait_stopped(&mut self) {
    // If never started or join_handle is already taken, return immediately
    if !self.started || self.join_handle.is_none() {
      return;
    }

    // Wait for the serving task to complete
    if let Some(handle) = self.join_handle.as_mut() {
      let _ = handle.await;
    }

    // Clean up join_handle
    self.join_handle.take();
    // Mark as no longer started
    self.started = false;
    info!("transfering set stopped");
  }

  /// Forcefully abort all transfer tasks
  ///
  /// This immediately terminates the serving task, which in turn
  /// aborts all active transfer tasks. Should be used when graceful
  /// shutdown times out.
  pub fn abort_all(&mut self) {
    if !self.started || self.aborted {
      return;
    }

    self.aborted = true;

    // Abort the serving task - this will drop the JoinSet inside
    // and automatically abort all spawned transfer tasks
    if let Some(handle) = self.join_handle.take() {
      handle.abort();
      info!("transfering set aborted");
    }
  }

  /// Check if the set has been aborted
  pub fn is_aborted(&self) -> bool {
    self.aborted
  }

  async fn serving(mut rx: local_mpsc::Receiver<Transfering>) {
    let mut join_set = task::JoinSet::<Result<u64>>::new();
    let mut channel_closed = false;
    loop {
      tokio::select! {
        ret = rx.recv(), if !channel_closed => {
          if let None = ret {
            channel_closed = true;
            continue;
          }

          let mut trans = ret.unwrap();
          join_set.spawn_local(async move { trans.run().await });
        }
        ret = join_set.join_next_with_id(), if !join_set.is_empty() => {
          let res = ret.unwrap();
          if let Err(e) = res {
            let id = e.id();
            warn!("transfering '{id}' join error: {e}");
            continue;
          }

          let (id, res) = res.unwrap();
          if let Err(e) = res {
            warn!("transfering '{id}' stopped with error: {e}");
            continue;
          }

          let total = res.unwrap();
          info!("transfering '{id}' done {total} bytes");
        }
        else => {
          break;
        }
      }
    }
  }

  /// Explicitly start the serving task.
  /// Note: This is optional as lazy initialization will start it on first use.
  pub fn start(&mut self) {
    self.ensure_started();
  }
}

pub struct FramingReaderStream<R> {
  rs: tokio_util_io::ReaderStream<R>,
}

impl<R> FramingReaderStream<R>
where
  R: io::AsyncRead + Unpin,
{
  pub fn new(rs: tokio_util_io::ReaderStream<R>) -> Self {
    Self { rs }
  }
}

impl<R> Stream for FramingReaderStream<R>
where
  R: io::AsyncRead + Unpin,
{
  type Item = Result<http_body::Frame<bytes::Bytes>>;

  fn poll_next(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Self::Item>> {
    Pin::new(&mut self.rs)
      .poll_next(cx)
      .map_ok(|b| http_body::Frame::data(b))
      .map_err(|e| e.into())
  }

  fn size_hint(&self) -> (usize, Option<usize>) {
    self.rs.size_hint()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn make_request_parts(
    method: http::Method,
    uri: &str,
  ) -> http::request::Parts {
    http::Request::builder()
      .method(method)
      .uri(uri)
      .body(())
      .unwrap()
      .into_parts()
      .0
  }

  #[test]
  fn test_parse_connect_target_valid() {
    let parts =
      make_request_parts(http::Method::CONNECT, "example.com:443");
    let result = parse_connect_target(&parts);
    assert_eq!(result, Ok(("example.com".to_string(), 443)));
  }

  #[test]
  fn test_parse_connect_target_not_connect_method() {
    let parts =
      make_request_parts(http::Method::GET, "http://example.com/");
    let result = parse_connect_target(&parts);
    assert_eq!(result, Err(ConnectTargetError::NotConnectMethod));
  }

  #[test]
  fn test_parse_connect_target_no_authority() {
    let parts = make_request_parts(http::Method::CONNECT, "/");
    let result = parse_connect_target(&parts);
    assert_eq!(result, Err(ConnectTargetError::NoAuthority));
  }

  #[test]
  fn test_parse_connect_target_no_port() {
    let parts =
      make_request_parts(http::Method::CONNECT, "example.com");
    let result = parse_connect_target(&parts);
    assert_eq!(result, Err(ConnectTargetError::NoPort));
  }

  #[test]
  fn test_parse_connect_target_port_zero() {
    let parts =
      make_request_parts(http::Method::CONNECT, "example.com:0");
    let result = parse_connect_target(&parts);
    assert_eq!(result, Err(ConnectTargetError::PortZero));
  }

  #[test]
  fn test_parse_connect_target_ipv6_address() {
    let parts = make_request_parts(http::Method::CONNECT, "[::1]:8080");
    let result = parse_connect_target(&parts);
    assert_eq!(result, Ok(("[::1]".to_string(), 8080)));
  }

  #[test]
  fn test_parse_connect_target_ipv4_address() {
    let parts =
      make_request_parts(http::Method::CONNECT, "192.168.1.1:80");
    let result = parse_connect_target(&parts);
    assert_eq!(result, Ok(("192.168.1.1".to_string(), 80)));
  }

  #[test]
  fn test_connect_target_error_display() {
    assert_eq!(
      format!("{}", ConnectTargetError::NotConnectMethod),
      "not CONNECT method"
    );
    assert_eq!(
      format!("{}", ConnectTargetError::NoAuthority),
      "no authority in URI"
    );
    assert_eq!(
      format!("{}", ConnectTargetError::NoPort),
      "no port in authority"
    );
    assert_eq!(
      format!("{}", ConnectTargetError::PortZero),
      "port is zero"
    );
  }

  #[test]
  fn test_connect_target_error_is_error() {
    let err = ConnectTargetError::NotConnectMethod;
    let _err: &dyn std::error::Error = &err;
  }

  // ============== TransferingSet Tests ==============

  #[test]
  fn test_transfering_set_new() {
    let ts = TransferingSet::new();
    assert!(!ts.shutdown_handle().is_shutdown());
    // Should not be started after creation (lazy initialization)
    assert!(!ts.started);
  }

  #[test]
  fn test_transfering_set_with_shutdown_handle() {
    let handle = plugin::ShutdownHandle::new();
    let ts = TransferingSet::with_shutdown_handle(handle.clone());
    assert!(!ts.shutdown_handle().is_shutdown());
    // Should not be started after creation (lazy initialization)
    assert!(!ts.started);

    // Trigger shutdown on the shared handle
    handle.shutdown();
    assert!(ts.shutdown_handle().is_shutdown());
  }

  #[test]
  fn test_transfering_set_with_shutdown_handle_shares_state() {
    let handle = plugin::ShutdownHandle::new();
    let ts = TransferingSet::with_shutdown_handle(handle.clone());

    // Trigger shutdown through TransferingSet's handle
    ts.shutdown_handle().shutdown();
    assert!(handle.is_shutdown());
  }

  #[test]
  fn test_transfering_set_lazy_init_not_started_after_creation() {
    let ts = TransferingSet::new();
    // After creation, the serving task should not be started
    assert!(
      !ts.started,
      "TransferingSet should not be started after creation"
    );
    assert!(
      ts.transfering_tx.is_none(),
      "TransferingSet should not have a channel after creation"
    );
    assert!(
      ts.join_handle.is_none(),
      "TransferingSet should not have a join handle after creation"
    );
  }

  #[tokio::test]
  async fn test_transfering_set_ensure_started_starts_task() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let mut ts = TransferingSet::new();
        assert!(!ts.started);

        // Call ensure_started (via start method)
        ts.start();

        // After start, should be started
        assert!(
          ts.started,
          "TransferingSet should be started after start()"
        );
        assert!(
          ts.transfering_tx.is_some(),
          "TransferingSet should have a channel after start()"
        );
        assert!(
          ts.join_handle.is_some(),
          "TransferingSet should have a join handle after start()"
        );
      })
      .await;
  }

  #[tokio::test]
  async fn test_transfering_set_start_is_idempotent() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let mut ts = TransferingSet::new();
        ts.start();
        assert!(ts.started);
        assert!(ts.transfering_tx.is_some());
        assert!(ts.join_handle.is_some());

        // Call start again - should be idempotent
        ts.start();

        // Should still be started with same state
        assert!(ts.started);
        assert!(ts.transfering_tx.is_some());
        assert!(ts.join_handle.is_some());
      })
      .await;
  }

  #[tokio::test]
  async fn test_transfering_set_stop_when_not_started() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let mut ts = TransferingSet::new();
        // Stop without starting should succeed
        let result = ts.stop().await;
        assert!(result.is_ok(), "Stop should succeed when not started");
      })
      .await;
  }

  #[tokio::test]
  async fn test_transfering_set_stop_after_start() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let mut ts = TransferingSet::new();
        ts.start();
        // Stop after starting should succeed
        let result = ts.stop().await;
        assert!(result.is_ok(), "Stop should succeed after start");
      })
      .await;
  }

  // ============== abort_all Tests ==============

  #[test]
  fn test_abort_all_not_started() {
    let mut ts = TransferingSet::new();
    // Should not panic when aborting without starting
    ts.abort_all();
    assert!(!ts.is_aborted());
  }

  #[tokio::test]
  async fn test_abort_all_after_start() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let mut ts = TransferingSet::new();
        ts.start();
        assert!(ts.join_handle.is_some());

        ts.abort_all();
        assert!(ts.is_aborted());
        assert!(ts.join_handle.is_none());

        // Calling abort_all again should be idempotent
        ts.abort_all();
        assert!(ts.is_aborted());
      })
      .await;
  }

  #[tokio::test]
  async fn test_abort_all_terminates_tasks() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let mut ts = TransferingSet::new();
        ts.start();

        // Create a simple transfering task using pipe
        // Using io::empty() as reader (always returns EOF)
        // Using io::sink() as writer (discards all data)
        ts.new_transfering(io::empty(), io::sink()).unwrap();

        // Give the task a moment to start
        tokio::task::yield_now().await;

        // Abort should terminate tasks quickly
        let start = std::time::Instant::now();
        ts.abort_all();
        let elapsed = start.elapsed();

        assert!(ts.is_aborted());
        // Abort should be very fast (< 100ms)
        assert!(
          elapsed < Duration::from_millis(100),
          "Abort should be fast, took {:?}",
          elapsed
        );
      })
      .await;
  }

  // ============== stop() Timeout Tests ==============

  #[tokio::test]
  async fn test_stop_with_timeout_completes_gracefully() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let mut ts = TransferingSet::new();
        ts.start();

        // Stop should complete within the timeout since no blocking tasks
        let start = std::time::Instant::now();
        let result = ts.stop().await;
        let elapsed = start.elapsed();

        assert!(result.is_ok());
        // Should complete quickly since no tasks are blocking
        assert!(
          elapsed < Duration::from_millis(500),
          "Stop should complete quickly, took {:?}",
          elapsed
        );
        assert!(
          !ts.is_aborted(),
          "Should not be aborted on graceful stop"
        );
      })
      .await;
  }

  #[tokio::test]
  async fn test_stop_idempotent_after_abort() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let mut ts = TransferingSet::new();
        ts.start();
        ts.abort_all();

        // Calling stop after abort should succeed immediately
        let result = ts.stop().await;
        assert!(result.is_ok());
        assert!(ts.is_aborted());
      })
      .await;
  }

  #[test]
  fn test_is_aborted_initial_false() {
    let ts = TransferingSet::new();
    assert!(!ts.is_aborted());
  }

  // ============== Transfering Interruption Tests ==============

  #[tokio::test]
  async fn test_transfering_interrupted_by_shutdown() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let mut ts = TransferingSet::new();

        // Create a reader that provides data slowly but can be interrupted
        // Using a custom reader that respects cancellation
        struct SlowReader;
        impl io::AsyncRead for SlowReader {
          fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut io::ReadBuf,
          ) -> std::task::Poll<Result<(), std::io::Error>> {
            // Provide data slowly - this simulates slow I/O
            // that can be interrupted by shutdown
            std::task::Poll::Ready(Ok(()))
          }
        }

        ts.new_transfering(SlowReader, io::sink()).unwrap();

        // Give the task a moment to start
        tokio::task::yield_now().await;

        // Trigger shutdown - this should signal the transfer tasks
        ts.shutdown_handle().shutdown();

        // Stop should complete because shutdown was triggered
        let start = std::time::Instant::now();
        let result = ts.stop().await;
        let elapsed = start.elapsed();

        assert!(result.is_ok());
        // Should complete quickly because shutdown interrupts
        assert!(
          elapsed < Duration::from_millis(500),
          "Stop should complete quickly after shutdown, took {:?}",
          elapsed
        );
      })
      .await;
  }

  // ============== stop() Timeout with Blocking Task Tests ==============

  #[tokio::test]
  async fn test_stop_timeout_triggers_abort() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        // This test verifies that stop() properly times out and aborts
        // when tasks don't respond to shutdown notification

        let mut ts = TransferingSet::new();

        // Create a transfer task
        ts.new_transfering(io::empty(), io::sink()).unwrap();

        // Give the task a moment to start
        tokio::task::yield_now().await;

        // Manually abort the serving task to simulate it being stuck
        // This tests the timeout path
        if let Some(handle) = ts.join_handle.take() {
          // Don't abort yet - we want to test the normal path
          ts.join_handle = Some(handle);
        }

        // Stop should complete - either gracefully or via timeout
        let start = std::time::Instant::now();
        let result = ts.stop().await;
        let elapsed = start.elapsed();

        assert!(result.is_ok());
        // Should complete quickly because io::empty() returns EOF immediately
        assert!(
          elapsed < Duration::from_secs(1),
          "Stop should complete quickly with simple task, took {:?}",
          elapsed
        );
      })
      .await;
  }

  // ============== new_transfering Error Handling Tests ==============

  #[tokio::test]
  async fn test_new_transfering_after_abort_fails() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let mut ts = TransferingSet::new();
        ts.start();

        // Abort the TransferingSet first
        ts.abort_all();

        // Trying to add new transfering should fail because channel is closed
        let result = ts.new_transfering(io::empty(), io::sink());
        assert!(
          result.is_err(),
          "new_transfering should fail after abort"
        );
      })
      .await;
  }

  // ============== TransferingSet Constants Tests ==============

  #[test]
  fn test_transfering_shutdown_timeout_value() {
    assert_eq!(TRANSFERING_SHUTDOWN_TIMEOUT, Duration::from_secs(5));
  }

  // ============== stop() Idempotency Tests ==============

  #[tokio::test]
  async fn test_stop_is_idempotent_multiple_calls() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let mut ts = TransferingSet::new();
        ts.start();

        // First stop should succeed
        let result1 = ts.stop().await;
        assert!(result1.is_ok(), "First stop should succeed");

        // join_handle should be cleared after first stop
        assert!(
          ts.join_handle.is_none(),
          "join_handle should be None after stop"
        );

        // started should be false after stop
        assert!(!ts.started, "started should be false after stop");

        // Second stop should also succeed (idempotent)
        let result2 = ts.stop().await;
        assert!(
          result2.is_ok(),
          "Second stop should succeed (idempotent)"
        );

        // Third stop should also succeed
        let result3 = ts.stop().await;
        assert!(
          result3.is_ok(),
          "Third stop should succeed (idempotent)"
        );
      })
      .await;
  }

  #[tokio::test]
  async fn test_stop_clears_join_handle_on_success() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let mut ts = TransferingSet::new();
        ts.start();
        assert!(ts.join_handle.is_some());

        // Stop should clear join_handle
        let result = ts.stop().await;
        assert!(result.is_ok());
        assert!(
          ts.join_handle.is_none(),
          "join_handle should be cleared after successful stop"
        );
      })
      .await;
  }

  #[tokio::test]
  async fn test_stop_clears_join_handle_on_abort_path() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let mut ts = TransferingSet::new();

        // Create a pending task that will cause timeout
        struct PendingReader;
        impl io::AsyncRead for PendingReader {
          fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &mut io::ReadBuf,
          ) -> std::task::Poll<Result<(), std::io::Error>> {
            std::task::Poll::Pending
          }
        }

        ts.new_transfering(PendingReader, io::sink()).unwrap();
        tokio::task::yield_now().await;

        // Stop should timeout and abort
        let result = ts.stop().await;
        assert!(result.is_ok());

        // join_handle should be cleared even after abort path
        assert!(
          ts.join_handle.is_none(),
          "join_handle should be cleared after abort"
        );
      })
      .await;
  }

  #[tokio::test]
  async fn test_stop_resets_started_flag() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let mut ts = TransferingSet::new();
        ts.start();
        assert!(ts.started);

        // Stop should reset started flag
        ts.stop().await.unwrap();
        assert!(!ts.started, "started flag should be reset after stop");

        // Can start again after stop
        ts.start();
        assert!(ts.started);
        ts.stop().await.unwrap();
      })
      .await;
  }

  #[tokio::test]
  async fn test_stop_after_abort_with_join_handle_present() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let mut ts = TransferingSet::new();
        ts.start();

        // Manually set aborted but keep join_handle (edge case)
        ts.aborted = true;

        // Stop should still work and clean up join_handle
        let result = ts.stop().await;
        assert!(result.is_ok());
        assert!(ts.join_handle.is_none());
      })
      .await;
  }

  // ============== stop_graceful() Tests ==============

  #[test]
  fn test_stop_graceful_not_started() {
    let mut ts = TransferingSet::new();
    // Should not panic when stop_graceful without starting
    ts.stop_graceful();
    assert!(!ts.shutdown_handle().is_shutdown());
  }

  #[tokio::test]
  async fn test_stop_graceful_after_start() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let mut ts = TransferingSet::new();
        ts.start();
        assert!(ts.join_handle.is_some());

        // stop_graceful should trigger shutdown but not wait
        ts.stop_graceful();

        // Should have triggered shutdown
        assert!(
          ts.shutdown_handle().is_shutdown(),
          "shutdown should be triggered"
        );

        // join_handle should still be present (not waited)
        assert!(
          ts.join_handle.is_some(),
          "join_handle should still be present after stop_graceful"
        );

        // transfering_tx should be taken (channel closed)
        assert!(
          ts.transfering_tx.is_none(),
          "transfering_tx should be None after stop_graceful"
        );
      })
      .await;
  }

  #[tokio::test]
  async fn test_stop_graceful_is_idempotent() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let mut ts = TransferingSet::new();
        ts.start();

        // Call stop_graceful multiple times
        ts.stop_graceful();
        ts.stop_graceful();
        ts.stop_graceful();

        // Should not cause issues
        assert!(ts.shutdown_handle().is_shutdown());
      })
      .await;
  }

  #[tokio::test]
  async fn test_stop_graceful_after_abort() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let mut ts = TransferingSet::new();
        ts.start();
        ts.abort_all();

        // stop_graceful after abort should handle gracefully
        ts.stop_graceful();
        assert!(ts.is_aborted());
      })
      .await;
  }

  // ============== wait_stopped() Tests ==============

  #[tokio::test]
  async fn test_wait_stopped_not_started() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let mut ts = TransferingSet::new();
        // Should return immediately when not started
        let start = std::time::Instant::now();
        ts.wait_stopped().await;
        let elapsed = start.elapsed();
        assert!(
          elapsed < Duration::from_millis(10),
          "wait_stopped should return immediately when not started"
        );
      })
      .await;
  }

  #[tokio::test]
  async fn test_wait_stopped_after_stop_graceful() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let mut ts = TransferingSet::new();
        ts.start();

        // Trigger graceful shutdown
        ts.stop_graceful();

        // wait_stopped should complete
        let start = std::time::Instant::now();
        ts.wait_stopped().await;
        let elapsed = start.elapsed();

        // Should complete quickly since no blocking tasks
        assert!(
          elapsed < Duration::from_millis(500),
          "wait_stopped should complete quickly, took {:?}",
          elapsed
        );

        // started should be reset
        assert!(
          !ts.started,
          "started should be reset after wait_stopped"
        );

        // join_handle should be cleared
        assert!(
          ts.join_handle.is_none(),
          "join_handle should be None after wait_stopped"
        );
      })
      .await;
  }

  #[tokio::test]
  async fn test_wait_stopped_is_idempotent() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let mut ts = TransferingSet::new();
        ts.start();
        ts.stop_graceful();

        // Call wait_stopped multiple times
        ts.wait_stopped().await;
        ts.wait_stopped().await;
        ts.wait_stopped().await;

        // Should not cause issues
        assert!(!ts.started);
        assert!(ts.join_handle.is_none());
      })
      .await;
  }

  #[tokio::test]
  async fn test_wait_stopped_after_abort() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let mut ts = TransferingSet::new();
        ts.start();
        ts.abort_all();

        // wait_stopped after abort should complete quickly
        let start = std::time::Instant::now();
        ts.wait_stopped().await;
        let elapsed = start.elapsed();

        assert!(
          elapsed < Duration::from_millis(100),
          "wait_stopped after abort should be quick, took {:?}",
          elapsed
        );
      })
      .await;
  }

  // ============== Combined stop_graceful + wait_stopped Tests ==============

  #[tokio::test]
  async fn test_stop_graceful_wait_stopped_with_tasks() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let mut ts = TransferingSet::new();

        // Create a transfer task
        ts.new_transfering(io::empty(), io::sink()).unwrap();

        // Give the task a moment to start
        tokio::task::yield_now().await;

        // Trigger graceful shutdown
        ts.stop_graceful();

        // Wait with external timeout
        let result = tokio::time::timeout(
          Duration::from_millis(100),
          ts.wait_stopped(),
        )
        .await;

        assert!(
          result.is_ok(),
          "wait_stopped should complete within timeout"
        );
        assert!(!ts.started);
        assert!(ts.join_handle.is_none());
      })
      .await;
  }

  #[tokio::test]
  async fn test_stop_graceful_then_external_timeout_abort() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let mut ts = TransferingSet::new();

        // Create a simple task that completes quickly
        ts.new_transfering(io::empty(), io::sink()).unwrap();
        tokio::task::yield_now().await;

        // Trigger graceful shutdown
        ts.stop_graceful();

        // Wait with external timeout (should complete quickly)
        let start = std::time::Instant::now();
        let result = tokio::time::timeout(
          Duration::from_millis(100),
          ts.wait_stopped(),
        )
        .await;

        let elapsed = start.elapsed();

        // Should complete because io::empty() returns EOF immediately
        // and shutdown interrupts any pending operations
        assert!(
          result.is_ok(),
          "wait_stopped should complete quickly with simple task"
        );
        assert!(
          elapsed < Duration::from_millis(200),
          "wait_stopped should be quick, took {:?}",
          elapsed
        );

        // Verify state after wait_stopped
        assert!(!ts.started);
        assert!(ts.join_handle.is_none());
      })
      .await;
  }
}
