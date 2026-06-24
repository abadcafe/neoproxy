use super::raw::{
  CertificateConfig, PoolConfig, UpstreamAddressConfig,
  UpstreamServiceArgs,
};
use super::resolved::ProtocolKind;

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
http3: {}
"#,
  )
  .unwrap();

  assert_eq!(addr.protocol().unwrap(), ProtocolKind::Http3);
}

#[test]
fn test_upstream_address_config_protocol_rejects_missing_protocol() {
  let addr: UpstreamAddressConfig =
    serde_yaml::from_str("address: example.com:443").unwrap();

  assert!(addr.protocol().is_err());
}

#[test]
fn test_pool_config_default_uses_pool_defaults() {
  let pool = PoolConfig::default();

  assert_eq!(pool.max_idle_per_host, 32);
  assert_eq!(pool.idle_timeout, std::time::Duration::from_secs(90));
}

#[test]
fn test_upstream_service_args_requires_upstream_name() {
  let args: UpstreamServiceArgs =
    serde_yaml::from_str("upstream: chain").unwrap();

  assert_eq!(args.upstream, "chain");
  assert!(serde_yaml::from_str::<UpstreamServiceArgs>("{}").is_err());
}
