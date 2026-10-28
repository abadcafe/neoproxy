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
        pool:
          max_idle_per_host: 16
          idle_timeout: 30s
        addresses:
          - address: proxy.example.com:8080
            address_protocol: http
    "#,
  )
  .unwrap();
  let resolved = merge_chain_config(&config).unwrap();
  let upstream = resolved.get("test").unwrap();
  assert_eq!(upstream.pool_config.max_idle_per_host, 16);
}

#[test]
fn test_merge_chain_config_three_level_inheritance() {
  let config: UpstreamPluginConfig = serde_yaml::from_str(
    r#"
    tunnel_idle_timeout: 90s
    tcp_connect_timeout: 5s
    upstreams:
      - name: test
        tcp_connect_timeout: 3s
        addresses:
          - address: proxy.example.com:8080
            address_protocol: http
            tcp_connect_timeout: 1s
          - address: proxy2.example.com:8080
            address_protocol: http
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
        tcp_connect_timeout: 3s
        tunnel_idle_timeout: 45s
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
    tcp_connect_timeout: 7s
    upstreams:
      - name: direct
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
  let upstream = resolved.get("test").unwrap();
  assert_eq!(upstream.pool_config.max_idle_per_host, 32);
  assert_eq!(
    upstream.pool_config.idle_timeout,
    Duration::from_secs(90)
  );
}

#[test]
fn test_merge_chain_config_stream_window_inherits_three_levels() {
  let config: UpstreamPluginConfig = serde_yaml::from_str(
    "quic_stream_receive_window: 1024\nupstreams:\n- name: \
     inherited\n  addresses:\n  - address: '127.0.0.1:443'\n    \
     address_protocol: http3\n- name: overridden\n  \
     quic_stream_receive_window: 2048\n  addresses:\n  - address: \
     '127.0.0.1:443'\n    address_protocol: http3\n  - address: \
     '127.0.0.1:444'\n    address_protocol: http3\n    \
     quic_stream_receive_window: 4096",
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
    ("quic_connection_max_concurrent_bidi_streams: 10001", true),
    (
      "quic_connection_max_concurrent_bidi_streams: \
       1152921504606846976",
      true,
    ),
    (
      "quic_connection_max_concurrent_bidi_streams: \
       1152921504606846977",
      false,
    ),
    ("quic_stream_receive_window: 0", false),
    ("quic_stream_receive_window: 4611686018427387904", false),
    ("quic_stream_receive_window: 4096", true),
  ] {
    for yaml in [
      format!("{fields}\nupstreams: [{{name: direct}}]"),
      format!("upstreams:\n- name: direct\n  {fields}"),
      format!(
        "upstreams:\n- name: chain\n  addresses:\n  - address: \
         '127.0.0.1:443'\n    address_protocol: http3\n    {fields}"
      ),
    ] {
      let config: UpstreamPluginConfig =
        serde_yaml::from_str(&yaml).unwrap();
      assert_eq!(merge_chain_config(&config).is_ok(), valid, "{yaml}");
    }
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
          "{field}: {value}\nupstreams:\n- name: inherited\n  \
           addresses:\n  - address: '127.0.0.1:443'\n    \
           address_protocol: http3\n- name: override\n  {field}: \
           2MiB\n  addresses:\n  - address: '127.0.0.1:443'\n    \
           address_protocol: http3\n  - address: '127.0.0.1:444'\n    \
           address_protocol: http3\n    {field}: 4KiB"
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
      let parsed = serde_yaml::from_str::<UpstreamPluginConfig>(
        &format!("{field}: {value}\nupstreams: [{{name: direct}}]"),
      );
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
      "{field}: 4EiB\nupstreams: [{{name: direct}}]"
    ))
    .unwrap();
    assert!(merge_chain_config(&parsed).is_err());
  }
}
