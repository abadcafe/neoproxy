use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::Notify;

use super::{
  ExitReason, LogWriterConfig, determine_exit_code,
  main_loop_with_signal,
};

#[test]
fn test_log_writer_config_default_flushes_each_line() {
  assert_eq!(LogWriterConfig::default().buffered_lines_limit, 1);
}

#[test]
fn test_determine_exit_code_prioritizes_panic_then_error() {
  assert_eq!(determine_exit_code(&[]), 0);
  assert_eq!(determine_exit_code(&[ExitReason::Normal]), 0);
  assert_eq!(determine_exit_code(&[ExitReason::Error]), 2);
  assert_eq!(
    determine_exit_code(&[ExitReason::Error, ExitReason::Panic]),
    1
  );
}

#[tokio::test]
async fn test_main_loop_without_server_threads_exits_after_signal() {
  let shutdown_notify = Arc::new(Notify::new());
  let shutdown_triggered = Arc::new(AtomicBool::new(false));

  let exit_code = main_loop_with_signal(
    vec![],
    shutdown_notify,
    shutdown_triggered.clone(),
    Box::pin(async {}),
  )
  .await;

  assert_eq!(exit_code, 0);
  assert!(!shutdown_triggered.load(Ordering::SeqCst));
}
