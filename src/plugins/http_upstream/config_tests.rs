use std::time::Duration;

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
  let addr: UpstreamAddressConfig =
    serde_yaml::from_str("address: example.com:443\nhttp3: {}")
      .unwrap();
  assert_eq!(addr.protocol().unwrap(), ProtocolKind::Http3);
}

#[test]
fn test_address_no_protocol_is_error() {
  let addr: UpstreamAddressConfig =
    serde_yaml::from_str("address: example.com:443").unwrap();
  assert!(addr.protocol().is_err());
}

#[test]
fn test_address_multiple_protocols_is_error() {
  let addr: UpstreamAddressConfig = serde_yaml::from_str(
    "address: example.com:443\nhttp: {}\nhttps: {}",
  )
  .unwrap();
  assert!(addr.protocol().is_err());
}

#[test]
fn test_merge_chain_config_basic() {
  let config: HttpUpstreamPluginConfig = serde_yaml::from_str(
    r#"
    upstreams:
      - name: test
        addresses:
          - address: proxy.example.com:443
            tunnel_idle_timeout: 120s
            http3: {}
    "#,
  )
  .unwrap();
  let resolved = merge_chain_config(&config).unwrap();
  let upstream = resolved.get("test").unwrap();
  assert_eq!(upstream.addresses.len(), 1);
  assert_eq!(upstream.addresses[0].address, "proxy.example.com:443");
  assert!(matches!(
    upstream.addresses[0].protocol,
    Protocol::Http3 { .. }
  ));
  assert_eq!(
    upstream.addresses[0].tunnel_idle_timeout,
    Duration::from_secs(120)
  );
}

#[test]
fn test_merge_chain_config_pool_config() {
  let config: HttpUpstreamPluginConfig = serde_yaml::from_str(
    r#"
    upstreams:
      - name: test
        pool:
          max_idle_per_host: 16
          idle_timeout: 30s
        addresses:
          - address: proxy.example.com:8080
            http: {}
    "#,
  )
  .unwrap();
  let resolved = merge_chain_config(&config).unwrap();
  let upstream = resolved.get("test").unwrap();
  assert_eq!(upstream.pool_config.max_idle_per_host, 16);
}

#[test]
fn test_merge_chain_config_three_level_inheritance() {
  let config: HttpUpstreamPluginConfig = serde_yaml::from_str(
    r#"
    tunnel_idle_timeout: 90s
    http:
      connect_timeout: 5s
    upstreams:
      - name: test
        http:
          connect_timeout: 3s
        addresses:
          - address: proxy.example.com:8080
            http:
              connect_timeout: 1s
          - address: proxy2.example.com:8080
            http: {}
    "#,
  )
  .unwrap();
  let resolved = merge_chain_config(&config).unwrap();
  let upstream = resolved.get("test").unwrap();

  // Address-level overrides upstream-level overrides plugin-level
  match &upstream.addresses[0].protocol {
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
  match &upstream.addresses[1].protocol {
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
  let config: HttpUpstreamPluginConfig = serde_yaml::from_str(
    r#"
    upstreams:
      - name: direct
        http:
          connect_timeout: 3s
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
  let config: HttpUpstreamPluginConfig = serde_yaml::from_str(
    r#"
    http:
      connect_timeout: 7s
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
  let result = serde_yaml::from_str::<HttpUpstreamPluginConfig>(
    "direct:\n  connect_timeout: 10s\n",
  );
  assert!(result.is_err(), "old 'direct:' field should be rejected");
}

#[test]
fn test_pool_config_defaults() {
  let config: HttpUpstreamPluginConfig = serde_yaml::from_str(
    r#"
    upstreams:
      - name: test
        addresses:
          - address: proxy.example.com:8080
            http: {}
    "#,
  )
  .unwrap();

  let resolved = merge_chain_config(&config).unwrap();
  let upstream = resolved.get("test").unwrap();
  assert_eq!(upstream.pool_config.max_idle_per_host, 32);
  assert_eq!(upstream.pool_config.idle_timeout, Duration::from_secs(90));
}
