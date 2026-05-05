#![allow(clippy::borrowed_box)]
use std::collections::HashMap;

use crate::listener::{BuildListener, ListenerProps};

pub mod common;
pub mod http;
pub mod http3;
pub mod https;
pub mod socks5;

/// Registry for listener builders and their properties.
///
/// Provides access to:
/// - `BuildListener` functions for creating listener instances
/// - `ListenerProps` for conflict detection
pub struct ListenerManager {
  builders: HashMap<&'static str, Box<dyn BuildListener>>,
  props: HashMap<&'static str, ListenerProps>,
}

impl ListenerManager {
  pub fn new() -> Self {
    let builders = HashMap::from([
      (
        http::listener_name(),
        Box::new(http::create_listener_builder())
          as Box<dyn BuildListener>,
      ),
      (
        https::listener_name(),
        Box::new(https::create_listener_builder())
          as Box<dyn BuildListener>,
      ),
      (
        http3::listener_name(),
        Box::new(http3::create_listener_builder())
          as Box<dyn BuildListener>,
      ),
      (
        socks5::listener_name(),
        Box::new(socks5::create_listener_builder())
          as Box<dyn BuildListener>,
      ),
    ]);
    let props = HashMap::from([
      (http::listener_name(), http::props()),
      (https::listener_name(), https::props()),
      (http3::listener_name(), http3::props()),
      (socks5::listener_name(), socks5::props()),
    ]);
    Self { builders, props }
  }

  /// Build a listener by kind.
  pub fn build_listener(
    &self,
    kind: &str,
    addresses: Vec<String>,
    args: crate::config::SerializedArgs,
    servers: Vec<crate::server::Server>,
  ) -> Result<crate::listener::Listener, anyhow::Error> {
    let builder = self.builders.get(kind).ok_or_else(|| {
      anyhow::anyhow!("unknown listener kind '{}'", kind)
    })?;
    builder(addresses, args, servers)
  }

  /// Get listener properties by kind.
  ///
  /// Used for address conflict detection.
  pub fn props(&self, kind: &str) -> Option<&ListenerProps> {
    self.props.get(kind)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_listener_manager_registered_kinds() {
    let lm = ListenerManager::new();
    assert!(lm.props("http").is_some());
    assert!(lm.props("https").is_some());
    assert!(lm.props("http3").is_some());
    assert!(lm.props("socks5").is_some());
  }

  #[test]
  fn test_listener_manager_old_kinds_removed() {
    let lm = ListenerManager::new();
    assert!(lm.props("hyper.listener").is_none());
    assert!(lm.props("http3.listener").is_none());
    assert!(lm.props("fast_socks5.listener").is_none());
  }

  #[test]
  fn test_listener_manager_nonexistent_kind() {
    let lm = ListenerManager::new();
    assert!(lm.props("nonexistent").is_none());
  }

  #[test]
  fn test_listener_manager_new() {
    let lm = ListenerManager::new();
    assert!(lm.builders.contains_key("http"));
    assert!(lm.builders.contains_key("https"));
    assert!(lm.builders.contains_key("http3"));
    assert!(lm.builders.contains_key("socks5"));
  }
}
