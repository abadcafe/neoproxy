use std::sync::{Arc, Mutex};

pub(crate) struct TracingCapture {
  captured: Arc<Mutex<Vec<String>>>,
}

impl TracingCapture {
  pub(crate) fn new() -> (Self, tracing::subscriber::DefaultGuard) {
    let captured: Arc<Mutex<Vec<String>>> =
      Arc::new(Mutex::new(Vec::new()));
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
      .with(RecordingLayer { captured: captured_clone });

    let guard = tracing::subscriber::set_default(layered);
    (Self { captured }, guard)
  }

  pub(crate) fn output(&self) -> String {
    let guard = self.captured.lock().unwrap();
    guard.join(" | ")
  }
}
