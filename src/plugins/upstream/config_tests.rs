use std::time::Duration;

use super::config::protocol::ProtocolKind;
use super::config::raw::UpstreamAddressConfig;
use super::config::*;

#[test]
fn test_validate_address_format_valid() {
  assert!(validate_address_format("example.com:8080").is_ok());
  assert!(validate_address_format("127.0.0.1:443").is_ok());
}

#[test]
fn test_validate_address_format_missing_port() {
  assert!(validate_address_format("example.com").is_err());
}

#[test]
fn test_validate_address_format_invalid_port() {
  assert!(validate_address_format("example.com:abc").is_err());
}

#[test]
fn test_validate_address_format_missing_host() {
  assert!(validate_address_format(":8080").is_err());
}

#[test]
fn test_address_protocol_detection() {
  let addr: UpstreamAddressConfig = serde_yaml::from_str(
    "address: example.com:443\naddress_protocol: http3",
  )
  .unwrap();
  assert_eq!(addr.address_protocol().unwrap(), ProtocolKind::Http3);
}

#[test]
fn test_address_defaults_to_https() {
  let addr: UpstreamAddressConfig =
    serde_yaml::from_str("address: example.com:443").unwrap();
  assert_eq!(addr.address_protocol().unwrap(), ProtocolKind::Https);
}

#[test]
fn test_address_invalid_protocol_is_error() {
  assert!(
    serde_yaml::from_str::<UpstreamAddressConfig>(
      "address: example.com:443\naddress_protocol: invalid",
    )
    .is_err()
  );
}

#[test]
fn test_merge_chain_config_basic() {
  let config: UpstreamPluginConfig = serde_yaml::from_str(
    r#"
    upstreams:
      - name: test
        addresses:
          - address: proxy.example.com:443
            tunnel_idle_timeout: 120s
            address_protocol: http3
    "#,
  )
  .unwrap();
  let resolved = merge_chain_config(&config).unwrap();
  let upstream = resolved.get("test").unwrap();
  assert_eq!(upstream.addresses.len(), 1);
  assert_eq!(upstream.addresses[0].address, "proxy.example.com:443");
  assert!(matches!(
    upstream.addresses[0].address_protocol,
    Protocol::Http3 { .. }
  ));
  assert_eq!(
    upstream.addresses[0].tunnel_idle_timeout,
    Duration::from_secs(120)
  );
}

#[test]
fn test_merge_chain_config_pool_config() {
  let config: UpstreamPluginConfig = serde_yaml::from_str(
    r#"
upstreams:
- name: test
  addresses:
  - address: proxy.example.com:8080
    address_protocol: http
connection_pools:
- name: default
  http_pool_max_idle_connections: 16
  http_pool_idle_timeout: 30s
"#,
  )
  .unwrap();
  let resolved = merge_chain_config(&config).unwrap();
  assert!(resolved.contains_key("test"));
  assert_eq!(crate::plugins::upstream::config::connection_pool::resolve_connection_pools(&config).unwrap()["default"].limits().http.max_idle_per_host, 16);
}

#[test]
fn test_merge_chain_config_three_level_inheritance() {
  let config: UpstreamPluginConfig = serde_yaml::from_str(
    r#"
tunnel_idle_timeout: 90s
upstreams:
- name: test
  addresses:
  - address: proxy.example.com:8080
    address_protocol: http
    use_connection_pool: address_pool_2
  - address: proxy2.example.com:8080
    address_protocol: http
  use_connection_pool: upstream_pool_1
connection_pools:
- name: default
  tcp_connect_timeout: 5s
- name: upstream_pool_1
  tcp_connect_timeout: 3s
- name: address_pool_2
  tcp_connect_timeout: 1s
"#,
  )
  .unwrap();
  let resolved = merge_chain_config(&config).unwrap();
  let upstream = resolved.get("test").unwrap();

  // Address-level overrides upstream-level overrides plugin-level
  match &upstream.addresses[0].address_protocol {
    Protocol::Http { connect_timeout, .. } => {
      assert_eq!(*connect_timeout, Duration::from_secs(1));
    }
    _ => panic!("expected Http protocol"),
  }
  assert_eq!(
    upstream.addresses[0].tunnel_idle_timeout,
    Duration::from_secs(90)
  );

  // Falls back to upstream-level connect_timeout, plugin-level
  // tunnel_idle_timeout
  match &upstream.addresses[1].address_protocol {
    Protocol::Http { connect_timeout, .. } => {
      assert_eq!(*connect_timeout, Duration::from_secs(3));
    }
    _ => panic!("expected Http protocol"),
  }
  assert_eq!(
    upstream.addresses[1].tunnel_idle_timeout,
    Duration::from_secs(90)
  );
}

#[test]
fn test_upstream_service_args_requires_upstream() {
  let result = serde_yaml::from_str::<UpstreamServiceArgs>("{}");
  assert!(result.is_err(), "upstream field should be required");
}

#[test]
fn test_upstream_service_args_with_upstream() {
  let args: UpstreamServiceArgs =
    serde_yaml::from_str("upstream: test_upstream").unwrap();
  assert_eq!(args.upstream, "test_upstream");
}

#[test]
fn test_upstream_service_args_deny_unknown_fields() {
  let result = serde_yaml::from_str::<UpstreamServiceArgs>(
    "upstream: test\nconnect_timeout: 5s",
  );
  assert!(
    result.is_err(),
    "connect_timeout should be rejected in service args"
  );
}

#[test]
fn test_resolve_direct_upstream() {
  let config: UpstreamPluginConfig = serde_yaml::from_str(
    r#"
upstreams:
- name: direct
  tunnel_idle_timeout: 45s
  use_connection_pool: upstream_pool_1
connection_pools:
- name: upstream_pool_1
  tcp_connect_timeout: 3s
"#,
  )
  .unwrap();
  let resolved = merge_chain_config(&config).unwrap();
  let upstream = resolved.get("direct").unwrap();
  assert!(upstream.addresses.is_empty());
  assert_eq!(upstream.connect_timeout, Duration::from_secs(3));
  assert_eq!(upstream.tunnel_idle_timeout, Duration::from_secs(45));
}

#[test]
fn test_resolve_direct_upstream_inherits_plugin_defaults() {
  let config: UpstreamPluginConfig = serde_yaml::from_str(
    r#"
upstreams:
- name: direct
connection_pools:
- name: default
  tcp_connect_timeout: 7s
"#,
  )
  .unwrap();
  let resolved = merge_chain_config(&config).unwrap();
  let upstream = resolved.get("direct").unwrap();
  assert!(upstream.addresses.is_empty());
  assert_eq!(upstream.connect_timeout, Duration::from_secs(7));
  assert_eq!(upstream.tunnel_idle_timeout, Duration::from_secs(60));
}

#[test]
fn test_plugin_config_deny_unknown_fields() {
  let result = serde_yaml::from_str::<UpstreamPluginConfig>(
    "direct:\n  connect_timeout: 10s\n",
  );
  assert!(result.is_err(), "old 'direct:' field should be rejected");
}

#[test]
fn test_pool_config_defaults() {
  let config: UpstreamPluginConfig = serde_yaml::from_str(
    r#"
    upstreams:
      - name: test
        addresses:
          - address: proxy.example.com:8080
            address_protocol: http
    "#,
  )
  .unwrap();

  let resolved = merge_chain_config(&config).unwrap();
  assert!(resolved.contains_key("test"));
  assert_eq!(crate::plugins::upstream::config::connection_pool::resolve_connection_pools(&config).unwrap()["default"].limits().http.max_idle_per_host, 32);
  assert_eq!(
    crate::plugins::upstream::config::connection_pool::resolve_connection_pools(&config).unwrap()["default"].limits().http.idle_timeout,
    Duration::from_secs(3600)
  );
}

#[test]
fn test_merge_chain_config_stream_window_uses_selected_connection_pool()
{
  let config: UpstreamPluginConfig =
    serde_yaml::from_str(
      "upstreams:\n- name: inherited\n  addresses:\n  - address: \
       127.0.0.1:443\n    address_protocol: http3\n- name: \
       overridden\n  addresses:\n  - address: 127.0.0.1:443\n    \
       address_protocol: http3\n  - address: 127.0.0.1:444\n    \
       address_protocol: http3\n    use_connection_pool: \
       address_pool_2\n  use_connection_pool: \
       upstream_pool_1\nconnection_pools:\n- name: default\n  \
       quic_stream_receive_window: 1024\n- name: upstream_pool_1\n  \
       quic_stream_receive_window: 2048\n- name: address_pool_2\n  \
       quic_stream_receive_window: 4096\n",
    )
    .unwrap();
  let resolved = merge_chain_config(&config).unwrap();
  for (name, index, expected) in [
    ("inherited", 0, 1024),
    ("overridden", 0, 2048),
    ("overridden", 1, 4096),
  ] {
    let Protocol::Http3 { quic, .. } =
      &resolved[name].addresses[index].address_protocol
    else {
      panic!("expected HTTP3");
    };
    assert_eq!(quic.stream_receive_window, Some(expected));
  }
}

#[test]
fn test_merge_chain_config_validates_quic_stream_and_count_bounds() {
  for (fields, valid) in [
    (
      "connection_pools:\n- name: default\n  \
       quic_connection_max_concurrent_bidi_streams: 10001\n",
      true,
    ),
    (
      "connection_pools:\n- name: default\n  \
       quic_connection_max_concurrent_bidi_streams: \
       1152921504606846976\n",
      true,
    ),
    (
      "connection_pools:\n- name: default\n  \
       quic_connection_max_concurrent_bidi_streams: \
       1152921504606846977\n",
      false,
    ),
    (
      "connection_pools:\n- name: default\n  \
       quic_stream_receive_window: 0\n",
      false,
    ),
    (
      "connection_pools:\n- name: default\n  \
       quic_stream_receive_window: 4611686018427387904\n",
      false,
    ),
    (
      "connection_pools:\n- name: default\n  \
       quic_stream_receive_window: 4096\n",
      true,
    ),
  ] {
    let config = serde_yaml::from_str(fields).unwrap();
    assert_eq!(merge_chain_config(&config).is_ok(), valid, "{fields}");
  }
}

#[test]
fn test_merge_chain_config_window_units_and_integer_bytes() {
  for field in [
    "quic_connection_send_window",
    "quic_connection_receive_window",
    "quic_stream_receive_window",
  ] {
    for (value, expected) in [
      ("10MiB", 10 * 1024 * 1024),
      ("10MB", 10_000_000),
      ("4096", 4096),
    ] {
      let config: UpstreamPluginConfig =
        serde_yaml::from_str(&format!(
          "connection_pools:\n- name: default\n  {field}: {value}\n- \
           name: override\n  {field}: 2MiB\n- name: small\n  {field}: \
           4KiB\nupstreams:\n- name: inherited\n  addresses:\n  - \
           address: '127.0.0.1:443'\n    address_protocol: http3\n- \
           name: override\n  use_connection_pool: override\n  \
           addresses:\n  - address: '127.0.0.1:443'\n    \
           address_protocol: http3\n  - address: '127.0.0.1:444'\n    \
           address_protocol: http3\n    use_connection_pool: small"
        ))
        .unwrap();
      let resolved = merge_chain_config(&config).unwrap();
      for (name, index, expected) in [
        ("inherited", 0, expected),
        ("override", 0, 2 * 1024 * 1024),
        ("override", 1, 4096),
      ] {
        let Protocol::Http3 { quic, .. } =
          &resolved[name].addresses[index].address_protocol
        else {
          panic!("expected HTTP3");
        };
        let actual = match field {
          "quic_connection_send_window" => quic.send_window,
          "quic_connection_receive_window" => quic.receive_window,
          _ => quic.stream_receive_window,
        };
        assert_eq!(
          actual,
          Some(expected),
          "{field}: {value}, {name}/{index}"
        );
      }
    }
  }
}

#[test]
fn test_merge_chain_config_window_units_reject_invalid_sizes() {
  for field in [
    "quic_connection_send_window",
    "quic_connection_receive_window",
    "quic_stream_receive_window",
  ] {
    for value in ["0MiB", "-1MiB", "garbage", "18446744073709551616B"] {
      let parsed =
        serde_yaml::from_str::<UpstreamPluginConfig>(&format!(
          "connection_pools:\n- name: default\n  {field}: \
           {value}\nupstreams: [{{name: direct}}]"
        ));
      assert!(
        parsed
          .and_then(|config| merge_chain_config(&config)
            .map_err(serde::de::Error::custom))
          .is_err(),
        "{field}: {value}"
      );
    }
  }
  for field in
    ["quic_connection_receive_window", "quic_stream_receive_window"]
  {
    let parsed: UpstreamPluginConfig = serde_yaml::from_str(&format!(
      "connection_pools:\n- name: default\n  {field}: \
       4EiB\nupstreams: [{{name: direct}}]"
    ))
    .unwrap();
    assert!(merge_chain_config(&parsed).is_err());
  }
}

#[test]
fn test_connection_pool_selection_inherits_and_creates_default() {
  let config = serde_yaml::from_str(
    "use_connection_pool: a\nconnection_pools: [{name: a, \
     tcp_connect_timeout: 2s}, {name: b, tcp_connect_timeout: \
     4s}]\nupstreams:\n- name: inherited\n- name: overridden\n  \
     use_connection_pool: b\n  addresses:\n  - address: \
     example.test:80\n    address_protocol: http\n  - address: \
     example.test:81\n    address_protocol: http\n    \
     use_connection_pool: default\n",
  )
  .unwrap();
  let upstreams = merge_chain_config(&config).unwrap();
  assert_eq!(upstreams["inherited"].use_connection_pool, "a");
  assert_eq!(
    upstreams["inherited"].connect_timeout,
    Duration::from_secs(2)
  );
  assert_eq!(
    upstreams["overridden"].addresses[0].use_connection_pool,
    "b"
  );
  assert_eq!(
    upstreams["overridden"].addresses[1].use_connection_pool,
    "default"
  );
}

#[test]
fn test_connection_pool_selection_rejects_missing_and_duplicate_names()
{
  for yaml in [
    "use_connection_pool: missing",
    "connection_pools: [{name: a}, {name: a}]",
    "connection_pools: [{name: ''}]",
    "upstreams: [{name: direct, use_connection_pool: missing}]",
  ] {
    let config = serde_yaml::from_str(yaml).unwrap();
    assert!(merge_chain_config(&config).is_err(), "accepted {yaml}");
  }
}
