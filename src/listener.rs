//! Listener core abstractions (traits, types, factory).
//!
//! This module provides types for building and managing network
//! listeners:
//! - `Listener` - A wrapper type for any listener implementation
//! - `Listening` - Trait for listener lifecycle (start/stop)
//! - `BuildListener` - Factory trait for creating listeners
//! - `ListenerProps` - Metadata for listener conflict detection
use std::future::Future;
use std::pin::Pin;

use anyhow::Result;

use crate::config::SerializedArgs;
// Re-export TransportLayer from config (single source of truth).
pub use crate::config::TransportLayer;
use crate::server::Server;

/// Listener metadata for conflict detection.
///
/// Each listener exports its properties via `props()` function,
/// allowing the framework to detect configuration conflicts
/// without hardcoding listener-specific logic.
#[derive(Debug, Clone)]
pub struct ListenerProps {
  /// Transport layer (TCP or UDP)
  transport_layer: TransportLayer,
  /// Whether the listener supports hostname-based routing.
  /// If true, multiple listeners of the same kind can share
  /// an address if they have different hostnames configured.
  supports_hostname_routing: bool,
}

impl ListenerProps {
  /// Create new listener properties.
  pub fn new(
    transport_layer: TransportLayer,
    supports_hostname_routing: bool,
  ) -> Self {
    Self { transport_layer, supports_hostname_routing }
  }

  /// Get the transport layer protocol.
  pub fn transport_layer(&self) -> TransportLayer {
    self.transport_layer
  }

  /// Get whether the listener supports hostname-based routing.
  pub fn supports_hostname_routing(&self) -> bool {
    self.supports_hostname_routing
  }
}

/// Trait for listener lifecycle management.
///
/// Implementations provide `start()` for beginning to accept
/// connections and `stop()` for graceful shutdown.
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

impl std::fmt::Debug for Listener {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("Listener").finish()
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
pub trait BuildListener:
  Fn(Vec<String>, SerializedArgs, Vec<Server>) -> Result<Listener>
{
}

impl<F> BuildListener for F where
  F: Fn(Vec<String>, SerializedArgs, Vec<Server>) -> Result<Listener>
{
}
