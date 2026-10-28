use super::raw::UpstreamPluginConfig;
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
  let config: UpstreamPluginConfig = serde_yaml::from_str(
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
  let config: UpstreamPluginConfig = serde_yaml::from_str(
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
  let config: UpstreamPluginConfig = serde_yaml::from_str(
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
  let config: UpstreamPluginConfig = serde_yaml::from_str(
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
  for value in
    [
      "upstreams:\n- name: direct\nconnection_pools:\n- name: \
       default\n  dns_servers: []\n",
      "connection_pools:\n- name: default\n  dns_servers:\n  - \
       127.0.0.1:0\n",
    ]
  {
    let config: UpstreamPluginConfig =
      serde_yaml::from_str(value).unwrap();
    assert!(validate_plugin_config(&config).is_err());
  }
}

#[test]
fn test_validate_plugin_config_rejects_invalid_quic_ranges() {
  let config: UpstreamPluginConfig = serde_yaml::from_str(
    r#"
upstreams:
- name: chain
  addresses:
  - address: 127.0.0.1:8443
    address_protocol: http3
    use_connection_pool: address_pool_1
connection_pools:
- name: address_pool_1
  quic_connection_initial_mtu: 1000
"#,
  )
  .unwrap();

  assert!(validate_plugin_config(&config).is_err());
}

#[test]
fn test_validate_plugin_config_rejects_unrepresentable_quic_values() {
  for field in [
    "connection_pools:\n- name: default\n  \
     quic_connection_max_idle_timeout: 100us\n",
    "connection_pools:\n- name: default\n  \
     quic_connection_max_idle_timeout: 18446744073709552s\n",
    "connection_pools:\n- name: default\n  \
     quic_connection_receive_window: 4611686018427387904\n",
  ] {
    let config: UpstreamPluginConfig =
      serde_yaml::from_str(field).unwrap();
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
        "connection_pools: [{{name: default, \
         http_connection_idle_timeout: {duration}}}]\nupstreams: \
         [{{name: direct}}]"
      ),
    ] {
      let config: UpstreamPluginConfig =
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
  let config: UpstreamPluginConfig = serde_yaml::from_str(
    "tunnel_idle_timeout: 1ms\nupstreams:\n- name: \
     direct\nconnection_pools:\n- name: default\n  \
     http_connection_idle_timeout: 1ms\n  http_max_idle_connections: \
     0\n",
  )
  .unwrap();
  assert!(validate_plugin_config(&config).is_ok());
}

#[test]
fn test_validate_plugin_config_accepts_tcp_keepalive() {
  for field in [
    "connection_pools:\n- name: default\n  tcp_keep_alive_time: 10s\n",
    "connection_pools:\n- name: default\n  tcp_keep_alive_interval: \
     5s\n",
    "connection_pools:\n- name: default\n  tcp_keep_alive_retries: 3\n",
  ] {
    let config: UpstreamPluginConfig =
      serde_yaml::from_str(field).unwrap();
    assert!(validate_plugin_config(&config).is_ok());
  }
}

#[test]
fn test_validate_plugin_config_rejects_invalid_address_request_timeout()
{
  let config: UpstreamPluginConfig = serde_yaml::from_str(
    "upstreams: [{name: chain, addresses: [{address: '127.0.0.1:80', \
     address_protocol: http, upstream_read_timeout: 0s}]}]",
  )
  .unwrap();
  assert!(validate_plugin_config(&config).is_err());
}

#[test]
fn test_dns_configuration_is_independent_for_each_connection_pool() {
  let config = serde_yaml::from_str(
    "connection_pools: [{name: a, dns_servers: ['127.0.0.1:53']}, \
     {name: b, dns_resolve_timeout: 2s}]",
  )
  .unwrap();
  let pools =
    super::connection_pool::resolve_connection_pools(&config).unwrap();
  assert_eq!(pools["a"].dns_servers.as_ref().unwrap().len(), 1);
  assert!(pools["b"].dns_servers.is_none());
  assert_eq!(
    pools["b"].dns_resolve_timeout,
    Some(std::time::Duration::from_secs(2))
  );
}
