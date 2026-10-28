use std::time::Duration;

use super::resolver::merge_chain_config;
use super::{Protocol, UpstreamPluginConfig};

#[test]
fn test_merge_chain_config_resolves_direct_upstream() {
  let config: UpstreamPluginConfig =
    serde_yaml::from_str("upstreams:\n  - name: direct\n").unwrap();

  let resolved = merge_chain_config(&config).unwrap();
  let upstream = resolved.get("direct").unwrap();

  assert!(upstream.addresses.is_empty());
  assert_eq!(upstream.connect_timeout, Duration::from_secs(10));
}

#[test]
fn test_merge_chain_config_uses_address_selected_connection_pool() {
  let config: UpstreamPluginConfig = serde_yaml::from_str(
    r#"
upstreams:
- name: chain
  addresses:
  - address: 127.0.0.1:8080
    address_protocol: http
    use_connection_pool: address_pool_2
  use_connection_pool: upstream_pool_1
connection_pools:
- name: default
  tcp_connect_timeout: 30s
- name: upstream_pool_1
  tcp_connect_timeout: 20s
- name: address_pool_2
  tcp_connect_timeout: 5s
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
  let config: UpstreamPluginConfig = serde_yaml::from_str(
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
fn test_merge_chain_config_reads_quic_from_selected_connection_pool() {
  let config: UpstreamPluginConfig = serde_yaml::from_str(
    r#"
upstreams:
- name: chain
  addresses:
  - address: localhost:443
    address_protocol: http3
    use_connection_pool: address_pool_1
connection_pools:
- name: default
  quic_connection_keep_alive_interval: 11s
- name: address_pool_1
  quic_connection_keep_alive_interval: 11s
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
  let config: UpstreamPluginConfig = serde_yaml::from_str(
    "upstream_read_timeout: 2s\nupstreams:\n- name: direct",
  )
  .unwrap();
  assert_eq!(
    merge_chain_config(&config).unwrap()["direct"]
      .upstream_read_timeout,
    Duration::from_secs(2)
  );
}

#[test]
fn test_merge_chain_config_resolves_direct_https_policy() {
  let config: UpstreamPluginConfig = serde_yaml::from_str(
    "upstreams:\n- name: inherited\n- name: overridden\n  \
     use_connection_pool: upstream_pool_1\nconnection_pools:\n- name: \
     default\n  tcp_connect_timeout: 3s\n  tls_handshake_timeout: \
     4s\n- name: upstream_pool_1\n  tcp_connect_timeout: 1s\n  \
     tls_handshake_timeout: 2s\n",
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
fn test_merge_chain_config_inherits_address_io_timeouts() {
  let config: UpstreamPluginConfig = serde_yaml::from_str(
    r#"
upstream_read_timeout: 9s
upstream_send_timeout: 8s
upstreams:
- name: overridden
  upstream_read_timeout: 4s
  upstream_send_timeout: 3s
  addresses:
  - address: "127.0.0.1:80"
    address_protocol: http
    upstream_read_timeout: 1s
    upstream_send_timeout: 2s
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
    upstreams["overridden"].addresses[0].upstream_send_timeout,
    Duration::from_secs(2)
  );
  assert_eq!(
    upstreams["overridden"].addresses[1].upstream_send_timeout,
    Duration::from_secs(3)
  );
  assert_eq!(
    upstreams["inherited"].addresses[0].upstream_send_timeout,
    Duration::from_secs(8)
  );
  assert_eq!(
    upstreams["overridden"].addresses[0].upstream_read_timeout,
    Duration::from_secs(1)
  );
  assert_eq!(
    upstreams["overridden"].addresses[1].upstream_read_timeout,
    Duration::from_secs(4)
  );
  assert_eq!(
    upstreams["inherited"].addresses[0].upstream_read_timeout,
    Duration::from_secs(9)
  );
}

#[test]
fn test_merge_chain_config_defaults_address_io_timeouts() {
  let config: UpstreamPluginConfig = serde_yaml::from_str(
    "upstreams: [{name: chain, addresses: [{address: '127.0.0.1:80', \
     address_protocol: http}]}]",
  )
  .unwrap();
  let upstreams = merge_chain_config(&config).unwrap();
  assert_eq!(
    upstreams["chain"].addresses[0].upstream_send_timeout,
    Duration::from_secs(10)
  );
  assert_eq!(
    upstreams["chain"].addresses[0].upstream_read_timeout,
    Duration::from_secs(10)
  );
}

#[test]
fn test_merge_chain_config_inherits_address_policy_and_tcp_keepalive() {
  let plugin: UpstreamPluginConfig = serde_yaml::from_str(
    r#"
address_protocol: http3
address_max_fails: 3
address_fail_timeout: 20s
upstreams:
- name: chain
  address_protocol: http
  address_max_fails: 2
  addresses:
  - address: a.test:80
  - address: b.test:443
    address_protocol: https
    address_fail_timeout: 5s
    use_connection_pool: address_pool_1
- name: direct
connection_pools:
- name: default
  tcp_keep_alive_time: 60s
  tcp_keep_alive_interval: 10s
  tcp_keep_alive_retries: 5
- name: address_pool_1
  tcp_keep_alive_time: 60s
  tcp_keep_alive_interval: 10s
  tcp_keep_alive_retries: 7
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
    super::connection_pool::resolve_connection_pools(&plugin).unwrap()
      ["default"]
      .dns_refresh_retry_interval
      .unwrap_or(Duration::from_secs(30)),
    Duration::from_secs(30)
  );
}

#[test]
fn test_merge_chain_config_socks5_inherits_and_validates_credentials() {
  for length in [0, 1, 255, 256] {
    let yaml = format!(
      "address_protocol: socks5\nuser: {{username: '{}', password: \
       secret}}\nconnection_pools: [{{name: default, \
       tcp_connect_timeout: 2s}}]\nupstreams: [{{name: chain, \
       addresses: [{{address: 'proxy.test:1080'}}]}}]",
      "a".repeat(length)
    );
    let config: UpstreamPluginConfig =
      serde_yaml::from_str(&yaml).unwrap();
    let result = merge_chain_config(&config);
    if length == 0 || length == 256 {
      assert!(result.is_err());
    } else {
      let upstreams = result.unwrap();
      let address = &upstreams["chain"].addresses[0];
      assert!(
        matches!(address.address_protocol, Protocol::Socks5 {connect_timeout} if connect_timeout == Duration::from_secs(2))
      );
      assert_eq!(
        address.user.as_ref().unwrap().username().len(),
        length
      );
    }
  }
}

#[test]
fn test_non_idempotent_retry_defaults_and_upstream_override() {
  let config: UpstreamPluginConfig =
    serde_yaml::from_str("upstreams: [{name: main}]").unwrap();
  assert!(
    !merge_chain_config(&config).unwrap()["main"]
      .upstream_non_idempotent_retry
  );
  let config: UpstreamPluginConfig = serde_yaml::from_str(
    "upstream_non_idempotent_retry: true\nupstreams:\n- name: \
     inherited\n- name: overridden\n  upstream_non_idempotent_retry: \
     false",
  )
  .unwrap();
  let resolved = merge_chain_config(&config).unwrap();
  assert!(resolved["inherited"].upstream_non_idempotent_retry);
  assert!(!resolved["overridden"].upstream_non_idempotent_retry);
}
