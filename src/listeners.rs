#![allow(clippy::borrowed_box)]
use std::collections::HashMap;
use std::sync::LazyLock;

use crate::plugin;

pub mod common;
pub mod http;
pub mod https;
pub mod http3;
pub mod socks5;

pub struct ListenerBuilderSet {
  builders: HashMap<&'static str, Box<dyn plugin::BuildListener>>,
}

impl ListenerBuilderSet {
  fn new() -> Self {
    let mut listener_manager = Self { builders: HashMap::new() };
    let builders = &mut listener_manager.builders;

    builders.insert(
      http::listener_name(),
      Box::new(http::create_listener_builder()),
    );
    builders.insert(
      https::listener_name(),
      Box::new(https::create_listener_builder()),
    );
    builders.insert(
      http3::listener_name(),
      Box::new(http3::create_listener_builder()),
    );
    builders.insert(
      socks5::listener_name(),
      Box::new(socks5::create_listener_builder()),
    );

    listener_manager
  }

  pub fn listener_builder(
    &self,
    name: &str,
  ) -> Option<&Box<dyn plugin::BuildListener>> {
    self.builders.get(name)
  }

  pub fn global() -> &'static LazyLock<ListenerBuilderSet> {
    static LISTENER_MANAGER: LazyLock<ListenerBuilderSet> =
      LazyLock::new(ListenerBuilderSet::new);
    &LISTENER_MANAGER
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_listener_builder_set_http_kind() {
    let set = ListenerBuilderSet::new();
    assert!(
      set.listener_builder("http").is_some(),
      "http kind should be registered"
    );
  }

  #[test]
  fn test_listener_builder_set_https_kind() {
    let set = ListenerBuilderSet::new();
    assert!(
      set.listener_builder("https").is_some(),
      "https kind should be registered"
    );
  }

  #[test]
  fn test_listener_builder_set_http3_kind() {
    let set = ListenerBuilderSet::new();
    assert!(
      set.listener_builder("http3").is_some(),
      "http3 kind should be registered"
    );
  }

  #[test]
  fn test_listener_builder_set_socks5_kind() {
    let set = ListenerBuilderSet::new();
    assert!(
      set.listener_builder("socks5").is_some(),
      "socks5 kind should be registered"
    );
  }

  #[test]
  fn test_listener_builder_set_old_kinds_removed() {
    let set = ListenerBuilderSet::new();
    assert!(
      set.listener_builder("hyper.listener").is_none(),
      "old hyper.listener should be removed"
    );
    assert!(
      set.listener_builder("http3.listener").is_none(),
      "old http3.listener should be removed"
    );
    assert!(
      set.listener_builder("fast_socks5.listener").is_none(),
      "old fast_socks5.listener should be removed"
    );
  }

  #[test]
  fn test_listener_builder_set_new() {
    let set = ListenerBuilderSet::new();
    assert!(set.builders.contains_key("http"));
    assert!(set.builders.contains_key("https"));
    assert!(set.builders.contains_key("http3"));
    assert!(set.builders.contains_key("socks5"));
  }

  #[test]
  fn test_listener_builder_set_get_existing() {
    let set = ListenerBuilderSet::new();
    let builder = set.listener_builder("http");
    assert!(builder.is_some());
  }

  #[test]
  fn test_listener_builder_set_get_http3_listener() {
    let set = ListenerBuilderSet::new();
    let builder = set.listener_builder("http3");
    assert!(builder.is_some());
  }

  #[test]
  fn test_listener_builder_set_get_fast_socks5_listener() {
    let set = ListenerBuilderSet::new();
    let builder = set.listener_builder("socks5");
    assert!(builder.is_some());
  }

  #[test]
  fn test_listener_builder_set_get_nonexistent() {
    let set = ListenerBuilderSet::new();
    let builder = set.listener_builder("nonexistent");
    assert!(builder.is_none());
  }

  #[test]
  fn test_listener_builder_set_global() {
    let global_set = ListenerBuilderSet::global();
    assert!(global_set.listener_builder("http").is_some());
    assert!(global_set.listener_builder("https").is_some());
    assert!(global_set.listener_builder("http3").is_some());
    assert!(global_set.listener_builder("socks5").is_some());
  }

  #[test]
  fn test_listener_builder_set_global_is_singleton() {
    let global1 = ListenerBuilderSet::global() as *const _;
    let global2 = ListenerBuilderSet::global() as *const _;
    assert_eq!(global1, global2);
  }
}
