use super::ListenerPropertiesProvider;
use super::listener::{ListenerPropertyValues, TransportLayer};

pub(super) struct MockListenerProps;

impl ListenerPropertiesProvider for MockListenerProps {
  fn listener_props(
    &self,
    kind: &str,
  ) -> Option<ListenerPropertyValues> {
    match kind {
      "http" | "https" | "http3" => {
        Some(ListenerPropertyValues::new(TransportLayer::Tcp, true))
      }
      "socks5" => {
        Some(ListenerPropertyValues::new(TransportLayer::Tcp, false))
      }
      _ => None,
    }
  }
}
