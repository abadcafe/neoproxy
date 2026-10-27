//! Terminal tunnel logging uses the creating request's immutable
//! identity.
use std::sync::{Arc, Mutex};

use super::tunnel_log::TunnelLog;
use crate::context::RequestContext;
use crate::stream::TransferEnd;

#[derive(Clone)]
struct Capture(Arc<Mutex<Vec<u8>>>);
impl std::io::Write for Capture {
  fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
    self.0.lock().unwrap().extend_from_slice(bytes);
    Ok(bytes.len())
  }

  fn flush(&mut self) -> std::io::Result<()> {
    Ok(())
  }
}
fn context() -> RequestContext {
  let mut headers = http::HeaderMap::new();
  headers.insert("x-request-id", "creator-id".parse().unwrap());
  RequestContext::new().with_request_id(
    crate::request_id::RequestId::read_or_generate(&headers).unwrap(),
  )
}
#[test]
fn test_finish_emits_once_after_completion_with_request_id() {
  let bytes = Arc::new(Mutex::new(Vec::new()));
  let output = Capture(bytes.clone());
  let subscriber = tracing_subscriber::fmt()
    .with_ansi(false)
    .without_time()
    .with_writer(move || output.clone())
    .finish();
  tracing::subscriber::with_default(subscriber, || {
    let log = TunnelLog::new(&context(), "origin.test:443", None);
    assert!(bytes.lock().unwrap().is_empty());
    log.finish(TransferEnd::Completed);
  });
  let output =
    String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
  assert_eq!(output.matches("tunnel_finished").count(), 1);
  assert!(output.contains("request_id=creator-id"));
  assert!(output.contains("end_reason=completed"));
}
#[test]
fn test_drop_before_task_poll_reports_cancelled_once() {
  let bytes = Arc::new(Mutex::new(Vec::new()));
  let output = Capture(bytes.clone());
  let subscriber = tracing_subscriber::fmt()
    .with_ansi(false)
    .without_time()
    .with_writer(move || output.clone())
    .finish();
  tracing::subscriber::with_default(subscriber, || {
    let _log = TunnelLog::new(&context(), "origin.test:443", None);
  });
  let output =
    String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
  assert_eq!(output.matches("tunnel_finished").count(), 1);
  assert!(output.contains("request_id=creator-id"));
  assert!(output.contains("end_reason=cancelled"));
}
