use super::SerializedArgs;
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
  assert!(lc.name.is_empty());
  assert!(lc.kind.is_empty());
  assert!(lc.addresses.is_empty());
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
  assert_eq!(lc.name, "http_main");
  assert_eq!(lc.kind, "http");
  assert_eq!(lc.addresses, vec!["0.0.0.0:8080"]);
}

#[test]
fn test_listener_config_clone() {
  let lc = ListenerConfig {
    name: "test".to_string(),
    kind: "http".to_string(),
    addresses: vec!["127.0.0.1:8080".to_string()],
    args: SerializedArgs::Null,
  };
  let cloned = lc.clone();
  assert_eq!(cloned.name, "test");
  assert_eq!(cloned.kind, "http");
}

#[test]
fn test_listener_property_values_construction() {
  let props = ListenerPropertyValues {
    transport_layer: TransportLayer::Tcp,
    supports_hostname_routing: true,
  };
  assert_eq!(props.transport_layer, TransportLayer::Tcp);
  assert!(props.supports_hostname_routing);
}

#[test]
fn test_address_usage_construction() {
  let usage = AddressUsage {
    server_name: "server1".to_string(),
    listener_kind: "http".to_string(),
    hostnames: vec!["api.example.com".to_string()],
  };
  assert_eq!(usage.server_name, "server1");
  assert_eq!(usage.listener_kind, "http");
  assert_eq!(usage.hostnames.len(), 1);
}
