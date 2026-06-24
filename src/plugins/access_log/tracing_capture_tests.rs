use super::tracing_capture::TracingCapture;

#[test]
fn test_tracing_capture_records_warn_events() {
  let (capture, _guard) = TracingCapture::new();

  tracing::warn!("captured warning");

  assert!(capture.output().contains("captured warning"));
}
