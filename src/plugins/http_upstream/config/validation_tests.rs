use super::raw::HttpUpstreamPluginConfig;
use super::validation::{
  validate_address_format, validate_plugin_config,
};

#[test]
fn test_validate_address_format_accepts_host_port() {
  assert!(validate_address_format("example.com:8080").is_ok());
  assert!(validate_address_format("127.0.0.1:443").is_ok());
  assert!(validate_address_format("[::1]:443").is_ok());
}

#[test]
fn test_validate_address_format_rejects_missing_port() {
  assert!(validate_address_format("example.com").is_err());
}

#[test]
fn test_validate_address_format_rejects_invalid_port() {
  assert!(validate_address_format("example.com:http").is_err());
  assert!(validate_address_format("example.com:0").is_err());
}

#[test]
fn test_validate_address_format_rejects_missing_host() {
  assert!(validate_address_format(":8080").is_err());
}

#[test]
fn test_validate_address_format_rejects_userinfo() {
  assert!(validate_address_format("user@example.com:8080").is_err());
}

#[test]
fn test_validate_plugin_config_rejects_duplicate_upstream_name() {
  let config: HttpUpstreamPluginConfig = serde_yaml::from_str(
    r#"
upstreams:
  - name: duplicate
  - name: duplicate
"#,
  )
  .unwrap();

  assert!(validate_plugin_config(&config).is_err());
}

#[test]
fn test_validate_plugin_config_rejects_empty_upstream_name() {
  let config: HttpUpstreamPluginConfig = serde_yaml::from_str(
    r#"
upstreams:
  - name: ""
"#,
  )
  .unwrap();

  assert!(validate_plugin_config(&config).is_err());
}

#[test]
fn test_validate_plugin_config_rejects_zero_weight() {
  let config: HttpUpstreamPluginConfig = serde_yaml::from_str(
    r#"
upstreams:
  - name: chain
    addresses:
      - address: "127.0.0.1:8080"
        weight: 0
        http: {}
"#,
  )
  .unwrap();

  assert!(validate_plugin_config(&config).is_err());
}

#[test]
fn test_validate_plugin_config_rejects_direct_http3_config() {
  let config: HttpUpstreamPluginConfig = serde_yaml::from_str(
    r#"
upstreams:
  - name: direct
    http3: {}
"#,
  )
  .unwrap();

  assert!(validate_plugin_config(&config).is_err());
}

#[test]
fn test_validate_plugin_config_rejects_invalid_quic_ranges() {
  let config: HttpUpstreamPluginConfig = serde_yaml::from_str(
    r#"
upstreams:
  - name: chain
    addresses:
      - address: "127.0.0.1:8443"
        http3:
          quic:
            initial_mtu: 1000
"#,
  )
  .unwrap();

  assert!(validate_plugin_config(&config).is_err());
}
