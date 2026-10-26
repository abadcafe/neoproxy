//! module: listener
//! responsibility: define listener construction and lifecycle
//! contracts
//! public operations: Listening, Listener, new, start, stop, finish,
//! BuildListener
//! data entities: Listener
//! tests: listener_tests.rs

//! Listener core abstractions (traits, types, factory).
//!
//! This module provides types for building and managing network
//! listeners:
//! - `Listener` - A wrapper type for any listener implementation
//! - `Listening` - Trait for listener lifecycle (start/stop)
//! - `BuildListener` - Factory trait for creating listeners
use std::future::Future;
use std::pin::Pin;

use anyhow::Result;

use crate::config::SerializedArgs;
// Re-export TransportLayer from config (single source of truth).
pub(crate) use crate::config::TransportLayer;
use crate::server::Server;

/// Trait for listener lifecycle management.
///
/// Implementations provide `start()` for beginning to accept
/// connections and `stop()` for graceful shutdown.
pub(crate) trait Listening {
  /// Start the listener.
  ///
  /// Returns a future that completes when the listener stops
  /// (either due to error or explicit stop).
  fn start(&self) -> Pin<Box<dyn Future<Output = Result<()>>>>;

  /// Stop the listener gracefully.
  fn stop(&self);

  /// Finish retained protocol drivers concurrently with plugin
  /// shutdown. TCP drivers have already completed in start();
  /// multiplexed transports can outlive request handlers and upgraded
  /// I/O.
  fn finish(&self) -> Pin<Box<dyn Future<Output = ()>>> {
    Box::pin(async {})
  }
}

/// A type-erased listener wrapper.
///
/// Wraps any type implementing `Listening` trait. Created by
/// `BuildListener` functions and used by the server thread
/// for lifecycle management.
pub(crate) struct Listener(Box<dyn Listening>);

impl Listener {
  /// Create a new listener from an implementation.
  pub(crate) fn new<L>(l: L) -> Self
  where
    L: Listening + 'static,
  {
    Self(Box::new(l))
  }

  /// Start the listener.
  pub(crate) fn start(
    &self,
  ) -> Pin<Box<dyn Future<Output = Result<()>>>> {
    self.0.start()
  }

  /// Stop the listener gracefully.
  pub(crate) fn stop(&self) {
    self.0.stop()
  }

  pub(crate) fn finish(&self) -> Pin<Box<dyn Future<Output = ()>>> {
    self.0.finish()
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
pub(crate) trait BuildListener:
  Fn(Vec<String>, SerializedArgs, Vec<Server>) -> Result<Listener>
{
}

impl<F> BuildListener for F where
  F: Fn(Vec<String>, SerializedArgs, Vec<Server>) -> Result<Listener>
{
}
