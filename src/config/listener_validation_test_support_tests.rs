use super::listener_validation_test_support::MockListenerProps;
use super::{ListenerPropertiesProvider, TransportLayer};

#[test]
fn test_mock_listener_props_matches_listener_validation_contract() {
  let provider = MockListenerProps;

  let http = provider.listener_props("http").unwrap();
  assert_eq!(http.transport_layer(), TransportLayer::Tcp);
  assert!(http.supports_hostname_routing());

  let socks5 = provider.listener_props("socks5").unwrap();
  assert_eq!(socks5.transport_layer(), TransportLayer::Tcp);
  assert!(!socks5.supports_hostname_routing());

  assert!(provider.listener_props("missing").is_none());
}
