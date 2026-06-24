use std::rc::Rc;

use super::config::{self, HttpUpstreamPluginConfig};
use super::upstream::UpstreamRegistry;
use crate::tracker::StreamTracker;

#[test]
fn test_upstream_registry_new_accepts_empty_direct_registry() {
  let config: HttpUpstreamPluginConfig =
    serde_yaml::from_str("upstreams:\n  - name: direct\n").unwrap();
  let upstreams = config::merge_chain_config(&config).unwrap();

  let registry = UpstreamRegistry::new(
    upstreams,
    None,
    Rc::new(StreamTracker::new()),
  )
  .unwrap();

  assert_eq!(registry.len(), 1);
  assert!(registry.contains_upstream("direct"));
  assert!(!registry.contains_upstream("missing"));
}
