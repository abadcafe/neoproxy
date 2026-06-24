use super::ListenerPropertiesProvider;
use super::listener::{ListenerPropertyValues, TransportLayer};

pub(super) struct MockListenerProps;

impl ListenerPropertiesProvider for MockListenerProps {
  fn listener_props(
    &self,
    kind: &str,
  ) -> Option<ListenerPropertyValues> {
    match kind {
      "http" | "https" | "http3" => Some(ListenerPropertyValues {
        transport_layer: TransportLayer::Tcp,
        supports_hostname_routing: true,
      }),
      "socks5" => Some(ListenerPropertyValues {
        transport_layer: TransportLayer::Tcp,
        supports_hostname_routing: false,
      }),
      _ => None,
    }
  }
}
