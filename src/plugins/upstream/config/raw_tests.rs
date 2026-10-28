use super::protocol::{PoolConfig, ProtocolKind};
use super::raw::{
  CertificateConfig, UpstreamAddressConfig, UpstreamServiceArgs,
};

#[test]
fn test_certificate_config_validate_accepts_empty_identity() {
  let config = CertificateConfig::default();

  assert!(config.validate().is_ok());
}

#[test]
fn test_certificate_config_validate_rejects_partial_identity() {
  let config = CertificateConfig {
    client_cert_path: Some("client.pem".to_string()),
    client_key_path: None,
    server_ca_path: None,
  };

  assert!(config.validate().is_err());
}

#[test]
fn test_upstream_address_config_protocol_detects_http3() {
  let addr: UpstreamAddressConfig = serde_yaml::from_str(
    r#"
address: example.com:443
address_protocol: http3
"#,
  )
  .unwrap();

  assert_eq!(addr.address_protocol().unwrap(), ProtocolKind::Http3);
}

#[test]
fn test_upstream_address_config_protocol_defaults_to_https() {
  let addr: UpstreamAddressConfig =
    serde_yaml::from_str("address: example.com:443").unwrap();

  assert_eq!(addr.address_protocol().unwrap(), ProtocolKind::Https);
}

#[test]
fn test_pool_config_default_uses_pool_defaults() {
  let pool = PoolConfig::default();

  assert_eq!(pool.max_idle_per_host, 100);
  assert_eq!(pool.idle_timeout, std::time::Duration::from_secs(60));
}

#[test]
fn test_upstream_service_args_requires_upstream_name() {
  let args: UpstreamServiceArgs =
    serde_yaml::from_str("upstream: chain").unwrap();

  assert_eq!(args.upstream, "chain");
  assert!(serde_yaml::from_str::<UpstreamServiceArgs>("{}").is_err());
}

#[test]
fn test_plugin_pool_configuration_defaults_and_overrides() {
  let config: super::raw::UpstreamPluginConfig =
    serde_yaml::from_str("{}").unwrap();
  let pools = crate::plugins::upstream::config::connection_pool::resolve_connection_pools(&config).unwrap()["default"].limits();
  assert_eq!(pools.http.max_idle_per_host, 100);
  assert_eq!(
    pools.https.idle_timeout,
    std::time::Duration::from_secs(60)
  );
  assert_eq!(pools.h3_connections, 1);
  assert_eq!(pools.h3_threads, 1);
  let config: super::raw::UpstreamPluginConfig = serde_yaml::from_str(
    "connection_pools:\n- name: default\n  http_max_idle_connections: \
     0\n  http3_pool_io_threads: 3\n  http3_connection_idle_timeout: \
     60m\n",
  )
  .unwrap();
  assert_eq!(crate::plugins::upstream::config::connection_pool::resolve_connection_pools(&config).unwrap()["default"].limits().http.max_idle_per_host, 0);
  assert_eq!(crate::plugins::upstream::config::connection_pool::resolve_connection_pools(&config).unwrap()["default"].limits().h3_threads, 3);
}

#[test]
fn test_plugin_pool_rejects_zero_h3_capacity_and_threads() {
  for field in
    ["http3_pool_io_threads", "http3_pool_max_connections_per_host"]
  {
    let config = serde_yaml::from_str(&format!(
      "connection_pools:\n- name: default\n  {field}: 0"
    ))
    .unwrap();
    assert!(super::merge_chain_config(&config).is_err());
  }
}

#[test]
fn test_connection_pool_shared_http_policy_and_h3_defaults() {
  let config = serde_yaml::from_str(
    "connection_pools: [{name: default, http_max_idle_connections: 7, \
     http_connection_idle_timeout: 9s}]",
  )
  .unwrap();
  let pools =
    super::connection_pool::resolve_connection_pools(&config).unwrap();
  let limits = pools["default"].limits();
  assert_eq!(limits.http.max_idle_per_host, 7);
  assert_eq!(limits.https.max_idle_per_host, 7);
  assert_eq!(
    limits.http.idle_timeout,
    std::time::Duration::from_secs(9)
  );
  assert_eq!(
    limits.https.idle_timeout,
    std::time::Duration::from_secs(9)
  );
  assert_eq!(limits.h3_connections, 1);
  assert_eq!(
    limits.h3_idle_timeout,
    std::time::Duration::from_secs(60)
  );
}
