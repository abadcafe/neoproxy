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
fn test_merge_chain_config_inherits_direct_discovery_and_quic_policy() {
  let config: HttpUpstreamPluginConfig = serde_yaml::from_str(
    "dns_servers: ['127.0.0.1:5353']\nhttp3:\n  \
     tls_handshake_timeout: 2s\n  quic:\n    keep_alive_interval: \
     7s\nupstreams:\n- name: inherited\n- name: overridden\n  \
     dns_servers: ['[::1]:5454']\n  http3:\n    \
     tls_handshake_timeout: 1s\n    quic:\n      initial_mtu: 1400\n",
  )
  .unwrap();
  let upstreams = merge_chain_config(&config).unwrap();
  assert_eq!(
    upstreams["inherited"].dns_servers.as_ref().unwrap()[0],
    "127.0.0.1:5353".parse::<std::net::SocketAddr>().unwrap()
  );
  assert_eq!(
    upstreams["overridden"].dns_servers.as_ref().unwrap()[0],
    "[::1]:5454".parse::<std::net::SocketAddr>().unwrap()
  );
  assert_eq!(
    upstreams["inherited"].http3_handshake_timeout,
    Duration::from_secs(2)
  );
  assert_eq!(
    upstreams["overridden"].http3_handshake_timeout,
    Duration::from_secs(1)
  );
  assert_eq!(
    upstreams["overridden"].quic.keep_alive_interval,
    Duration::from_secs(7)
  );
  assert_eq!(upstreams["overridden"].quic.initial_mtu, Some(1400));
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

#[test]
fn test_merge_chain_config_partial_quic_preserves_inherited_keep_alive()
{
  let config: HttpUpstreamPluginConfig = serde_yaml::from_str(
    r#"
http3:
  quic:
    keep_alive_interval: 11s
upstreams:
- name: chain
  addresses:
  - address: localhost:443
    http3:
      quic:
        initial_mtu: 1400
"#,
  )
  .unwrap();
  let resolved = merge_chain_config(&config).unwrap();
  let address = &resolved["chain"].addresses[0];
  assert!(
    matches!(&address.protocol, Protocol::Http3 { quic, .. } if quic.keep_alive_interval == Duration::from_secs(11))
  );
}

#[test]
fn test_merge_chain_config_inherits_request_deadline() {
  let config: HttpUpstreamPluginConfig = serde_yaml::from_str(
    "request_timeout: 2s\nupstreams:\n- name: direct",
  )
  .unwrap();
  assert_eq!(
    merge_chain_config(&config).unwrap()["direct"].request_timeout,
    Duration::from_secs(2)
  );
}

#[test]
fn test_merge_chain_config_resolves_direct_https_policy() {
  let config: HttpUpstreamPluginConfig = serde_yaml::from_str(
    "https:\n  connect_timeout: 3s\n  tls_handshake_timeout: \
     4s\nupstreams:\n- name: inherited\n- name: overridden\n  \
     https:\n    connect_timeout: 1s\n    tls_handshake_timeout: 2s",
  )
  .unwrap();
  let resolved = merge_chain_config(&config).unwrap();
  assert_eq!(
    resolved["inherited"].https_connect_timeout,
    Duration::from_secs(3)
  );
  assert_eq!(
    resolved["inherited"].tls_handshake_timeout,
    Duration::from_secs(4)
  );
  assert_eq!(
    resolved["overridden"].https_connect_timeout,
    Duration::from_secs(1)
  );
  assert_eq!(
    resolved["overridden"].tls_handshake_timeout,
    Duration::from_secs(2)
  );
}
