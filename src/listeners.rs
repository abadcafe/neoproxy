use std::collections::HashMap;
use std::sync::LazyLock;

use crate::plugin;

pub mod http3;
pub mod hyper;

pub struct ListenerBuilderSet {
  builders: HashMap<&'static str, Box<dyn plugin::BuildListener>>,
}

impl ListenerBuilderSet {
  fn new() -> Self {
    let mut listener_manager = Self { builders: HashMap::new() };
    let builders = &mut listener_manager.builders;

    builders.insert(
      hyper::listener_name(),
      Box::new(hyper::create_listener_builder()),
    );
    builders.insert(
      http3::listener_name(),
      Box::new(http3::create_listener_builder()),
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
      LazyLock::new(|| ListenerBuilderSet::new());
    &LISTENER_MANAGER
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_listener_builder_set_new() {
    let set = ListenerBuilderSet::new();
    assert!(set.builders.contains_key("hyper.listener"));
    assert!(set.builders.contains_key("http3.listener"));
  }

  #[test]
  fn test_listener_builder_set_get_existing() {
    let set = ListenerBuilderSet::new();
    let builder = set.listener_builder("hyper.listener");
    assert!(builder.is_some());
  }

  #[test]
  fn test_listener_builder_set_get_http3_listener() {
    let set = ListenerBuilderSet::new();
    let builder = set.listener_builder("http3.listener");
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
    assert!(global_set.listener_builder("hyper.listener").is_some());
    assert!(global_set.listener_builder("http3.listener").is_some());
  }

  #[test]
  fn test_listener_builder_set_global_is_singleton() {
    let global1 = ListenerBuilderSet::global() as *const _;
    let global2 = ListenerBuilderSet::global() as *const _;
    assert_eq!(global1, global2);
  }
}
