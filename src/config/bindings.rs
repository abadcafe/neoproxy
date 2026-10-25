//! module: bindings
//! responsibilities: validate that listening sockets have unambiguous
//! owners public operations: validate
//! data entities: none
//! tests: bindings_tests.rs through Config::validate
use std::net::SocketAddr;

use super::document::Config;
use super::error::{ConfigError, ConfigErrorCollector};
use super::listener::ListenerPropertiesProvider;

pub(super) fn validate(
  config: &Config,
  errors: &mut ConfigErrorCollector,
  properties: &dyn ListenerPropertiesProvider,
) {
  let mut bindings = Vec::new();
  for listener in config.listeners() {
    let Some(properties) = properties.listener_props(listener.kind())
    else {
      errors.add(ConfigError::InvalidFormat {
        location: format!("listener '{}'", listener.name()),
        message: format!("unknown listener kind '{}'", listener.kind()),
      });
      continue;
    };
    for address in listener.addresses() {
      let Ok(address) = address.parse::<SocketAddr>() else {
        continue;
      };
      if address.port() == 0 {
        continue;
      }
      for (previous, transport, name) in &bindings {
        if properties.transport_layer() == *transport
          && overlaps(address, *previous)
        {
          errors.add(ConfigError::AddressConflict {
            location: format!("listener '{}'", listener.name()),
            message: format!(
              "socket {address} overlaps listener '{name}'; share one \
               listener between servers instead"
            ),
          });
        }
      }
      bindings.push((
        address,
        properties.transport_layer(),
        listener.name(),
      ));
    }
  }
}

fn overlaps(left: SocketAddr, right: SocketAddr) -> bool {
  left.port() == right.port()
    && (left.ip() == right.ip()
      || (left.is_ipv4() == right.is_ipv4()
        && (left.ip().is_unspecified() || right.ip().is_unspecified()))
      || (left.is_ipv6() && left.ip().is_unspecified())
      || (right.is_ipv6() && right.ip().is_unspecified()))
}
