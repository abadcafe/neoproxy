//! Public configuration contracts for connection-scoped QUIC datagrams.
use super::quic_datagram::Config;

#[test]
fn test_defaults_enable_h3_datagrams_with_one_mib_buffers() {
  let config: Config = serde_yaml::from_str("{}").unwrap();
  assert!(config.http3_enable_datagram);
  assert_eq!(
    config.quic_connection_datagram_receive_buffer_size.as_u64(),
    1048576
  );
  assert_eq!(
    config.quic_connection_datagram_send_buffer_size.as_u64(),
    1048576
  );
  config.validate().unwrap();
}
#[test]
fn test_custom_sizes_and_disabled_h3_datagrams() {
  let config: Config = serde_yaml::from_str(
    "http3_enable_datagram: \
     false\nquic_connection_datagram_receive_buffer_size: \
     2MiB\nquic_connection_datagram_send_buffer_size: 3MiB",
  )
  .unwrap();
  assert!(!config.http3_enable_datagram);
  assert_eq!(
    config.quic_connection_datagram_receive_buffer_size.as_u64(),
    2097152
  );
  assert_eq!(
    config.quic_connection_datagram_send_buffer_size.as_u64(),
    3145728
  );
  config.validate().unwrap();
}
#[test]
fn test_zero_buffer_sizes_are_invalid() {
  for field in [
    "quic_connection_datagram_receive_buffer_size",
    "quic_connection_datagram_send_buffer_size",
  ] {
    let config: Config =
      serde_yaml::from_str(&format!("{field}: 0")).unwrap();
    assert!(config.validate().is_err());
  }
}
