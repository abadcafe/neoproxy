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
tcp_connect_timeout: "30s"
upstreams:
- name: chain
  tcp_connect_timeout: "20s"
  addresses:
  - address: "127.0.0.1:8080"
    address_protocol: http
    tcp_connect_timeout: "5s"
"#,
  )
  .unwrap();

  let resolved = merge_chain_config(&config).unwrap();
  let address = &resolved.get("chain").unwrap().addresses[0];

  assert!(matches!(
    address.address_protocol,
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
    address_protocol: http
"#,
  )
  .unwrap();

  assert!(merge_chain_config(&config).is_err());
}

#[test]
fn test_merge_chain_config_partial_quic_preserves_inherited_keep_alive()
{
  let config: HttpUpstreamPluginConfig = serde_yaml::from_str(
    r#"
quic_connection_keep_alive_interval: 11s
upstreams:
- name: chain
  addresses:
  - address: localhost:443
    address_protocol: http3
    quic_connection_initial_mtu: 1400
"#,
  )
  .unwrap();
  let resolved = merge_chain_config(&config).unwrap();
  let address = &resolved["chain"].addresses[0];
  assert!(
    matches!(&address.address_protocol, Protocol::Http3 { quic, .. } if quic.keep_alive_interval == Duration::from_secs(11))
  );
}

#[test]
fn test_merge_chain_config_inherits_request_deadline() {
  let config: HttpUpstreamPluginConfig = serde_yaml::from_str(
    "upstream_request_timeout: 2s\nupstreams:\n- name: direct",
  )
  .unwrap();
  assert_eq!(
    merge_chain_config(&config).unwrap()["direct"]
      .upstream_request_timeout,
    Duration::from_secs(2)
  );
}

#[test]
fn test_merge_chain_config_resolves_direct_https_policy() {
  let config: HttpUpstreamPluginConfig = serde_yaml::from_str(
    "tcp_connect_timeout: 3s\ntls_handshake_timeout: \
     4s\nupstreams:\n- name: inherited\n- name: overridden\n  \
     tcp_connect_timeout: 1s\n  tls_handshake_timeout: 2s",
  )
  .unwrap();
  let resolved = merge_chain_config(&config).unwrap();
  assert_eq!(
    resolved["inherited"].connect_timeout,
    Duration::from_secs(3)
  );
  assert_eq!(
    resolved["inherited"].tls_handshake_timeout,
    Duration::from_secs(4)
  );
  assert_eq!(
    resolved["overridden"].connect_timeout,
    Duration::from_secs(1)
  );
  assert_eq!(
    resolved["overridden"].tls_handshake_timeout,
    Duration::from_secs(2)
  );
}

#[test]
fn test_merge_chain_config_inherits_address_request_deadlines() {
  let config: HttpUpstreamPluginConfig = serde_yaml::from_str(
    r#"
upstream_request_timeout: 9s
upstreams:
- name: overridden
  upstream_request_timeout: 4s
  addresses:
  - address: "127.0.0.1:80"
    address_protocol: http
    upstream_request_timeout: 1s
  - address: "127.0.0.1:81"
    address_protocol: http
- name: inherited
  addresses:
  - address: "127.0.0.1:82"
    address_protocol: http
- name: defaults
  addresses:
  - address: "127.0.0.1:83"
    address_protocol: http
"#,
  )
  .unwrap();
  let upstreams = merge_chain_config(&config).unwrap();
  assert_eq!(
    upstreams["overridden"].addresses[0].upstream_request_timeout,
    Duration::from_secs(1)
  );
  assert_eq!(
    upstreams["overridden"].addresses[1].upstream_request_timeout,
    Duration::from_secs(4)
  );
  assert_eq!(
    upstreams["inherited"].addresses[0].upstream_request_timeout,
    Duration::from_secs(9)
  );
}

#[test]
fn test_merge_chain_config_defaults_address_request_deadline() {
  let config: HttpUpstreamPluginConfig = serde_yaml::from_str(
    "upstreams: [{name: chain, addresses: [{address: '127.0.0.1:80', \
     address_protocol: http}]}]",
  )
  .unwrap();
  let upstreams = merge_chain_config(&config).unwrap();
  assert_eq!(
    upstreams["chain"].addresses[0].upstream_request_timeout,
    Duration::from_secs(30)
  );
}

#[test]
fn test_merge_chain_config_inherits_address_policy_and_tcp_keepalive() {
  let plugin: HttpUpstreamPluginConfig = serde_yaml::from_str(
    r#"
address_protocol: http3
address_max_fails: 3
address_fail_timeout: 20s
tcp_keep_alive_time: 60s
tcp_keep_alive_interval: 10s
tcp_keep_alive_retries: 5
upstreams:
- name: chain
  address_protocol: http
  address_max_fails: 2
  addresses:
  - address: a.test:80
  - address: b.test:443
    address_protocol: https
    address_fail_timeout: 5s
    tcp_keep_alive_retries: 7
- name: direct
"#,
  )
  .unwrap();
  let result = merge_chain_config(&plugin).unwrap();
  let addresses = &result["chain"].addresses;
  assert!(matches!(
    addresses[0].address_protocol,
    Protocol::Http { .. }
  ));
  assert!(matches!(
    addresses[1].address_protocol,
    Protocol::Https { .. }
  ));
  assert_eq!(addresses[0].address_max_fails, 2);
  assert_eq!(
    addresses[0].address_fail_timeout,
    Duration::from_secs(20)
  );
  assert_eq!(addresses[1].address_fail_timeout, Duration::from_secs(5));
  assert_eq!(
    addresses[0].tcp_keep_alive_time,
    Some(Duration::from_secs(60))
  );
  assert_eq!(
    addresses[0].tcp_keep_alive_interval,
    Some(Duration::from_secs(10))
  );
  assert_eq!(addresses[1].tcp_keep_alive_retries, Some(7));
  assert_eq!(result["direct"].address_max_fails, 3);
  assert_eq!(
    result["direct"].dns_refresh_retry_interval,
    Duration::from_secs(30)
  );
}
