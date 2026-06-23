//! Black-box tests for the listener core abstractions module.

use std::future::Future;
use std::pin::Pin;

use anyhow::Result;

use crate::config::SerializedArgs;
use crate::listener::{
  BuildListener, Listener, ListenerProps, Listening, TransportLayer,
};
use crate::server::Server;

fn dummy_builder(
  _addresses: Vec<String>,
  _args: SerializedArgs,
  _server_routing_table: Vec<Server>,
) -> Result<Listener> {
  struct DummyListener;
  impl Listening for DummyListener {
    fn start(&self) -> Pin<Box<dyn Future<Output = Result<()>>>> {
      Box::pin(async { Ok(()) })
    }

    fn stop(&self) {}
  }
  Ok(Listener::new(DummyListener))
}

// ========== ListenerProps ==========

#[test]
fn test_listener_props_tcp_with_hostname_routing() {
  let props = ListenerProps::new(TransportLayer::Tcp, true);
  assert_eq!(props.transport_layer(), TransportLayer::Tcp);
  assert!(props.supports_hostname_routing());
}

#[test]
fn test_listener_props_tcp_without_hostname_routing() {
  let props = ListenerProps::new(TransportLayer::Tcp, false);
  assert_eq!(props.transport_layer(), TransportLayer::Tcp);
  assert!(!props.supports_hostname_routing());
}

#[test]
fn test_listener_props_udp_with_hostname_routing() {
  let props = ListenerProps::new(TransportLayer::Udp, true);
  assert_eq!(props.transport_layer(), TransportLayer::Udp);
  assert!(props.supports_hostname_routing());
}

// ========== Listening trait ==========

#[tokio::test]
async fn test_start_completes_after_stop() {
  use std::sync::Arc;
  use tokio::sync::Notify;

  let notify = Arc::new(Notify::new());

  struct NotifyListener {
    notify: Arc<Notify>,
  }
  impl Listening for NotifyListener {
    fn start(&self) -> Pin<Box<dyn Future<Output = Result<()>>>> {
      let notify = self.notify.clone();
      Box::pin(async move {
        notify.notified().await;
        Ok(())
      })
    }
    fn stop(&self) {
      self.notify.notify_one();
    }
  }

  let listener = Listener::new(NotifyListener { notify });

  // stop() should cause start() to complete with Ok
  listener.stop();
  let result = listener.start().await;
  assert!(result.is_ok());
}

#[tokio::test]
async fn test_start_blocks_until_stop_called() {
  use std::sync::Arc;
  use std::sync::atomic::{AtomicBool, Ordering};
  use tokio::sync::Notify;

  let notify = Arc::new(Notify::new());
  let completed = Arc::new(AtomicBool::new(false));

  struct NotifyListener {
    notify: Arc<Notify>,
    completed: Arc<AtomicBool>,
  }
  impl Listening for NotifyListener {
    fn start(&self) -> Pin<Box<dyn Future<Output = Result<()>>>> {
      let notify = self.notify.clone();
      let completed = self.completed.clone();
      Box::pin(async move {
        notify.notified().await;
        completed.store(true, Ordering::Relaxed);
        Ok(())
      })
    }
    fn stop(&self) {
      self.notify.notify_one();
    }
  }

  let listener = Listener::new(NotifyListener {
    notify,
    completed: completed.clone(),
  });

  // Before stop, start() should not complete
  // Use tokio::select! with a timeout to verify it blocks
  let timeout = std::time::Duration::from_millis(50);
  tokio::select! {
    _ = listener.start() => {
      panic!("start() should not complete before stop()");
    }
    _ = tokio::time::sleep(timeout) => {
      // Expected: start() is still waiting
    }
  }
  assert!(!completed.load(Ordering::Relaxed));

  // Now stop — start() should complete
  listener.stop();
  let result = listener.start().await;
  assert!(result.is_ok());
  assert!(completed.load(Ordering::Relaxed));
}

// ========== BuildListener trait ==========

#[test]
fn test_build_listener_callable() {
  let builder: Box<dyn BuildListener> = Box::new(dummy_builder);
  let result = builder(vec![], SerializedArgs::Null, vec![]);
  assert!(result.is_ok());
}
