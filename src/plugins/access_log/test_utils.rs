//! Shared test utilities for the access_log module.
//!
//! This module provides common test helpers used by both `plugin_tests`
//! (in `access_log.rs`) and `writer::tests` (in `writer.rs`), avoiding
//! DRY violations.

use std::sync::{Arc, Mutex};

/// Helper to capture tracing events in tests.
///
/// Encapsulates the RecordingLayer, StringVisitor, subscriber setup,
/// and output() method into a reusable struct. This avoids duplicating
/// ~20 lines of boilerplate per test that needs to verify tracing output.
pub struct TracingCapture {
  captured: Arc<Mutex<Vec<String>>>,
}

impl TracingCapture {
  pub fn new() -> (Self, tracing::subscriber::DefaultGuard) {
    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let captured_clone = captured.clone();

    use tracing_subscriber::layer::SubscriberExt;

    struct RecordingLayer {
      captured: Arc<Mutex<Vec<String>>>,
    }

    impl<S> tracing_subscriber::Layer<S> for RecordingLayer
    where
      S: tracing::Subscriber,
    {
      fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
      ) {
        let mut visitor = StringVisitor(String::new());
        event.record(&mut visitor);
        let mut guard = self.captured.lock().unwrap();
        guard.push(visitor.0);
      }
    }

    struct StringVisitor(String);

    impl tracing::field::Visit for StringVisitor {
      fn record_debug(
        &mut self,
        field: &tracing::field::Field,
        value: &dyn std::fmt::Debug,
      ) {
        if !self.0.is_empty() {
          self.0.push(' ');
        }
        self.0.push_str(&format!("{}={:?}", field.name(), value));
      }
    }

    let layered = tracing_subscriber::registry()
      .with(tracing_subscriber::filter::LevelFilter::WARN)
      .with(RecordingLayer {
        captured: captured_clone,
      });

    let guard = tracing::subscriber::set_default(layered);
    (Self { captured }, guard)
  }

  pub fn output(&self) -> String {
    let guard = self.captured.lock().unwrap();
    guard.join(" | ")
  }
}
