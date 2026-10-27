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
        address_protocol: http
"#,
  )
  .unwrap();

  assert!(validate_plugin_config(&config).is_err());
}

#[test]
fn test_validate_plugin_config_accepts_direct_http3_config() {
  let config: HttpUpstreamPluginConfig = serde_yaml::from_str(
    r#"
upstreams:
  - name: direct
"#,
  )
  .unwrap();

  assert!(validate_plugin_config(&config).is_ok());
}

#[test]
fn test_validate_plugin_config_rejects_empty_or_zero_port_dns_servers()
{
  for value in [
    "dns_servers: []\nupstreams: [{name: direct}]",
    "dns_servers: ['127.0.0.1:0']",
  ] {
    let config: HttpUpstreamPluginConfig =
      serde_yaml::from_str(value).unwrap();
    assert!(validate_plugin_config(&config).is_err());
  }
}

#[test]
fn test_validate_plugin_config_rejects_invalid_quic_ranges() {
  let config: HttpUpstreamPluginConfig = serde_yaml::from_str(
    r#"
upstreams:
  - name: chain
    addresses:
      - address: "127.0.0.1:8443"
        address_protocol: http3
        quic_connection_initial_mtu: 1000
"#,
  )
  .unwrap();

  assert!(validate_plugin_config(&config).is_err());
}

#[test]
fn test_validate_plugin_config_rejects_unrepresentable_quic_values() {
  for field in [
    "quic_connection_idle_timeout: 100us",
    "quic_connection_idle_timeout: 18446744073709552s",
    "quic_connection_receive_window: 4611686018427387904",
  ] {
    let config: HttpUpstreamPluginConfig =
      serde_yaml::from_str(&format!(
        "upstreams:\n  - name: chain\n    addresses:\n      - \
         address: 127.0.0.1:443\n        address_protocol: http3\n        \
         {field}"
      ))
      .unwrap();
    assert!(
      validate_plugin_config(&config).is_err(),
      "accepted {field}"
    );
  }
}

#[test]
fn test_validate_plugin_config_bounds_every_idle_deadline() {
  for duration in ["0s", "18446744073709551615s"] {
    for yaml in [
      format!("tunnel_idle_timeout: {duration}"),
      format!(
        "upstreams: [{{name: direct, tunnel_idle_timeout: \
         {duration}}}]"
      ),
      format!(
        "upstreams: [{{name: chain, addresses: [{{address: \
         'localhost:80', address_protocol: http, tunnel_idle_timeout: \
         {duration}}}]}}]"
      ),
      format!(
        "upstreams: [{{name: direct, pool: {{idle_timeout: \
         {duration}}}}}]"
      ),
    ] {
      let config: HttpUpstreamPluginConfig =
        serde_yaml::from_str(&yaml).unwrap();
      assert!(
        validate_plugin_config(&config).is_err(),
        "accepted {yaml}"
      );
    }
  }
}

#[test]
fn test_validate_plugin_config_accepts_finite_idle_deadlines() {
  let config: HttpUpstreamPluginConfig = serde_yaml::from_str(
    "tunnel_idle_timeout: 1ms\nupstreams: [{name: direct, pool: \
     {idle_timeout: 1ms, max_idle_per_host: 0}}]",
  )
  .unwrap();
  assert!(validate_plugin_config(&config).is_ok());
}

#[test]
fn test_validate_plugin_config_accepts_tcp_keepalive() {
  for field in [
    "tcp_keep_alive_time: 10s",
    "tcp_keep_alive_interval: 5s",
    "tcp_keep_alive_retries: 3",
  ] {
    let config: HttpUpstreamPluginConfig =
      serde_yaml::from_str(field).unwrap();
    assert!(validate_plugin_config(&config).is_ok());
  }
}

#[test]
fn test_validate_plugin_config_rejects_invalid_address_request_timeout()
{
  let config: HttpUpstreamPluginConfig = serde_yaml::from_str(
    "upstreams: [{name: chain, addresses: [{address: '127.0.0.1:80', \
     address_protocol: http, upstream_request_timeout: 0s}]}]",
  )
  .unwrap();
  assert!(validate_plugin_config(&config).is_err());
}

#[test]
fn test_dns_configuration_is_plugin_scoped() {
  for field in
    ["dns_servers: ['127.0.0.1:53']", "dns_resolve_timeout: 5s"]
  {
    let upstream = format!("upstreams:\n  - name: direct\n    {field}");
    let address = format!(
      "upstreams:\n  - name: chain\n    addresses:\n      - address: \
       '127.0.0.1:80'\n        address_protocol: http\n        {field}"
    );
    assert!(
      serde_yaml::from_str::<HttpUpstreamPluginConfig>(&upstream)
        .is_err()
    );
    assert!(
      serde_yaml::from_str::<HttpUpstreamPluginConfig>(&address)
        .is_err()
    );
  }
}
