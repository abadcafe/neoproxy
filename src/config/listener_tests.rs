use super::listener::*;

#[test]
fn test_transport_layer_equality() {
  assert_eq!(TransportLayer::Tcp, TransportLayer::Tcp);
  assert_eq!(TransportLayer::Udp, TransportLayer::Udp);
  assert_ne!(TransportLayer::Tcp, TransportLayer::Udp);
}

#[test]
fn test_transport_layer_clone() {
  let tcp = TransportLayer::Tcp;
  let cloned = tcp;
  assert_eq!(tcp, cloned);
}

#[test]
fn test_listener_config_default() {
  let lc = ListenerConfig::default();
  assert!(lc.name().is_empty());
  assert!(lc.kind().is_empty());
  assert!(lc.addresses().is_empty());
}

#[test]
fn test_listener_config_deserialize() {
  let yaml = r#"
name: http_main
kind: http
addresses:
- "0.0.0.0:8080"
"#;
  let lc: ListenerConfig = serde_yaml::from_str(yaml).unwrap();
  assert_eq!(lc.name(), "http_main");
  assert_eq!(lc.kind(), "http");
  assert_eq!(lc.addresses(), ["0.0.0.0:8080"]);
}

#[test]
fn test_listener_config_clone() {
  let lc: ListenerConfig = serde_yaml::from_str(
    r#"
name: test
kind: http
addresses:
- "127.0.0.1:8080"
"#,
  )
  .unwrap();
  let cloned = lc.clone();
  assert_eq!(cloned.name(), "test");
  assert_eq!(cloned.kind(), "http");
}

#[test]
fn test_listener_property_values_construction() {
  let props =
    ListenerPropertyValues::new(TransportLayer::Tcp, true, false);
  assert_eq!(props.transport_layer(), TransportLayer::Tcp);
  assert!(!props.requires_server_certificate());
  assert!(props.supports_hostname_routing());
}

// ========== ListenerPropertyValues ==========

#[test]
fn test_listener_property_values_tcp_with_hostname_routing() {
  let props =
    ListenerPropertyValues::new(TransportLayer::Tcp, true, false);
  assert_eq!(props.transport_layer(), TransportLayer::Tcp);
  assert!(!props.requires_server_certificate());
  assert!(props.supports_hostname_routing());
}

#[test]
fn test_listener_property_values_tcp_without_hostname_routing() {
  let props =
    ListenerPropertyValues::new(TransportLayer::Tcp, false, false);
  assert_eq!(props.transport_layer(), TransportLayer::Tcp);
  assert!(!props.requires_server_certificate());
  assert!(!props.supports_hostname_routing());
}

#[test]
fn test_listener_property_values_udp_with_hostname_routing() {
  let props =
    ListenerPropertyValues::new(TransportLayer::Udp, true, true);
  assert_eq!(props.transport_layer(), TransportLayer::Udp);
  assert!(props.requires_server_certificate());
  assert!(props.supports_hostname_routing());
}

#[test]
fn test_listener_config_collects_flat_protocol_fields() {
  let config: ListenerConfig = serde_yaml::from_str(
    "name: main\nkind: https\naddresses: \
     ['127.0.0.1:8443']\ntls_handshake_timeout: \
     7s\ntcp_keep_alive_time: 60s",
  )
  .unwrap();
  assert_eq!(
    config.args()["tls_handshake_timeout"].as_str(),
    Some("7s")
  );
  assert_eq!(
    config.args()["tcp_keep_alive_time"].as_str(),
    Some("60s")
  );
  assert!(config.args().get("name").is_none());
}
