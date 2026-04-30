//! Runtime listener types.
//!
//! This module provides types for building and managing network listeners:
//! - `Listener` - A wrapper type for any listener implementation
//! - `Listening` - Trait for listener lifecycle (start/stop)
//! - `BuildListener` - Factory trait for creating listeners
//! - `ListenerProps` - Metadata for listener conflict detection
//! - `TransportLayer` - Transport protocol type (TCP/UDP)

use std::future::Future;
use std::pin::Pin;

use anyhow::Result;

use crate::config::SerializedArgs;
use crate::server::Server;

/// Transport layer protocol type.
///
/// Used for address conflict detection - listeners on different
/// transport layers can share the same address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportLayer {
  /// TCP protocol
  Tcp,
  /// UDP protocol
  Udp,
}

/// Listener metadata for conflict detection.
///
/// Each listener exports its properties via `props()` function,
/// allowing the framework to detect configuration conflicts
/// without hardcoding listener-specific logic.
#[derive(Debug, Clone)]
pub struct ListenerProps {
  /// Transport layer (TCP or UDP)
  pub transport_layer: TransportLayer,
  /// Whether the listener supports hostname-based routing.
  /// If true, multiple listeners of the same kind can share
  /// an address if they have different hostnames configured.
  pub supports_hostname_routing: bool,
}

/// Trait for listener lifecycle management.
///
/// Implementations provide `start()` for beginning to accept connections
/// and `stop()` for graceful shutdown.
pub trait Listening {
  /// Start the listener.
  ///
  /// Returns a future that completes when the listener stops
  /// (either due to error or explicit stop).
  fn start(&self) -> Pin<Box<dyn Future<Output = Result<()>>>>;

  /// Stop the listener gracefully.
  fn stop(&self);
}

/// A type-erased listener wrapper.
///
/// Wraps any type implementing `Listening` trait. Created by
/// `BuildListener` functions and used by the server thread
/// for lifecycle management.
pub struct Listener(Box<dyn Listening>);

impl Listener {
  /// Create a new listener from an implementation.
  pub fn new<L>(l: L) -> Self
  where
    L: Listening + 'static,
  {
    Self(Box::new(l))
  }

  /// Start the listener.
  pub fn start(&self) -> Pin<Box<dyn Future<Output = Result<()>>>> {
    self.0.start()
  }

  /// Stop the listener gracefully.
  pub fn stop(&self) {
    self.0.stop()
  }
}

/// Factory trait for building listeners.
///
/// A `BuildListener` is a function that takes:
/// - `addresses` - Network addresses to listen on (framework field)
/// - `args` - Listener-specific configuration arguments
/// - `servers` - List of servers for routing
///
/// Returns a `Listener` instance.
///
/// Must be `Sync + Send` to allow concurrent access from multiple threads.
pub trait BuildListener:
  Fn(Vec<String>, SerializedArgs, Vec<Server>) -> Result<Listener> + Sync + Send
{
}

impl<F> BuildListener for F where
  F: Fn(Vec<String>, SerializedArgs, Vec<Server>) -> Result<Listener> + Sync + Send
{
}

#[cfg(test)]
mod tests {
  use super::*;

  fn test_listener_builder(
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

  #[test]
  fn test_build_listener_trait_with_context() {
    let builder: Box<dyn BuildListener> =
      Box::new(test_listener_builder);
    let result = builder(vec![], SerializedArgs::Null, vec![]);
    assert!(result.is_ok());
  }

  #[test]
  fn test_build_listener_with_empty_context() {
    fn builder(
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

    let builder: Box<dyn BuildListener> = Box::new(builder);
    let result = builder(vec![], SerializedArgs::Null, vec![]);
    assert!(result.is_ok());
  }

  #[tokio::test]
  async fn test_listener_start_stop() {
    struct TestListener;

    impl Listening for TestListener {
      fn start(&self) -> Pin<Box<dyn Future<Output = Result<()>>>> {
        Box::pin(async { Ok(()) })
      }
      fn stop(&self) {}
    }

    let listener = Listener::new(TestListener);
    let result = listener.start().await;
    assert!(result.is_ok());
    listener.stop();
  }
}
