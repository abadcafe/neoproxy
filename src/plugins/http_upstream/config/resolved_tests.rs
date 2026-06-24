use std::time::Duration;

use super::raw::PoolConfig;
use super::resolved::{
  Address, ClientCertCredential, Protocol, ProtocolKind, QuicResolved,
  Upstream,
};

#[test]
fn test_protocol_kind_equality_distinguishes_protocols() {
  assert_eq!(ProtocolKind::Http, ProtocolKind::Http);
  assert_ne!(ProtocolKind::Http, ProtocolKind::Https);
}

#[test]
fn test_resolved_address_preserves_runtime_fields() {
  let address = Address {
    address: "127.0.0.1:8080".to_string(),
    hostname: Some("proxy.local".to_string()),
    weight: 3,
    protocol: Protocol::Http {
      connect_timeout: Duration::from_secs(2),
    },
    tunnel_idle_timeout: Duration::from_secs(30),
    user: None,
  };

  assert_eq!(address.address, "127.0.0.1:8080");
  assert_eq!(address.hostname.as_deref(), Some("proxy.local"));
  assert_eq!(address.weight, 3);
  assert!(matches!(address.protocol, Protocol::Http { .. }));
}

#[test]
fn test_quic_resolved_preserves_optional_transport_fields() {
  let quic = QuicResolved {
    max_idle_timeout: Some(Duration::from_secs(20)),
    keep_alive_interval: Duration::from_secs(3),
    max_concurrent_bidi_streams: Some(64),
    initial_mtu: Some(1200),
    send_window: Some(1024),
    receive_window: Some(2048),
  };

  assert_eq!(quic.max_idle_timeout, Some(Duration::from_secs(20)));
  assert_eq!(quic.max_concurrent_bidi_streams, Some(64));
}

#[test]
fn test_upstream_preserves_direct_mode_defaults() {
  let upstream = Upstream {
    addresses: vec![],
    pool_config: PoolConfig::default(),
    connect_timeout: Duration::from_secs(10),
    tunnel_idle_timeout: Duration::from_secs(60),
    dns_resolve_timeout: Duration::from_secs(5),
  };

  assert!(upstream.addresses.is_empty());
  assert_eq!(upstream.pool_config.max_idle_per_host, 32);
  assert_eq!(upstream.connect_timeout, Duration::from_secs(10));
}

#[test]
fn test_client_cert_credential_allows_absent_identity() {
  let credential =
    ClientCertCredential { cert_path: None, key_path: None };

  assert!(credential.cert_path.is_none());
  assert!(credential.key_path.is_none());
}
