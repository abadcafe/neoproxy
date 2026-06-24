use std::time::Duration;

use super::resolver::merge_chain_config;
use super::{HttpUpstreamPluginConfig, Protocol};

#[test]
fn test_merge_chain_config_resolves_direct_upstream() {
  let config: HttpUpstreamPluginConfig =
    serde_yaml::from_str("upstreams:\n  - name: direct\n").unwrap();

  let resolved = merge_chain_config(&config).unwrap();
  let upstream = resolved.get("direct").unwrap();

  assert!(upstream.addresses.is_empty());
  assert_eq!(upstream.connect_timeout, Duration::from_secs(10));
}

#[test]
fn test_merge_chain_config_prefers_address_level_timeout() {
  let config: HttpUpstreamPluginConfig = serde_yaml::from_str(
    r#"
http:
  connect_timeout: "30s"
upstreams:
- name: chain
  http:
    connect_timeout: "20s"
  addresses:
  - address: "127.0.0.1:8080"
    http:
      connect_timeout: "5s"
"#,
  )
  .unwrap();

  let resolved = merge_chain_config(&config).unwrap();
  let address = &resolved.get("chain").unwrap().addresses[0];

  assert!(matches!(
    address.protocol,
    Protocol::Http { connect_timeout } if connect_timeout == Duration::from_secs(5)
  ));
}

#[test]
fn test_merge_chain_config_rejects_invalid_address() {
  let config: HttpUpstreamPluginConfig = serde_yaml::from_str(
    r#"
upstreams:
- name: chain
  addresses:
  - address: "missing-port"
    http: {}
"#,
  )
  .unwrap();

  assert!(merge_chain_config(&config).is_err());
}
