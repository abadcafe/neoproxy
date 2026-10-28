//! Tests for QUIC configuration validation.

use super::quic_config::Http3ListenerArgs;

fn parse_args(yaml: &str) -> Http3ListenerArgs {
  let args: crate::config::SerializedArgs =
    serde_yaml::from_str(yaml).unwrap();
  let parsed: super::quic_config::Http3ListenerArgs =
    serde_yaml::from_value(args).unwrap();
  parsed
}

// ========== Valid configurations ==========

#[test]
fn test_quic_config_default_values_succeeds() {
  let args = parse_args(r#"{}"#);
  let config = args.validate_and_apply_defaults().unwrap();
  assert_eq!(config.max_concurrent_bidi_streams, 100);
  assert_eq!(config.max_idle_timeout_ms, None);
  assert_eq!(config.initial_mtu, 1200);
  assert_eq!(config.send_window, None);
  assert_eq!(config.receive_window, None);
}

#[test]
fn test_quic_config_custom_values_succeeds() {
  let args = parse_args(
    r#"
quic_connection_max_concurrent_bidi_streams: 200
quic_connection_max_idle_timeout: "60s"
quic_connection_initial_mtu: 1400
quic_connection_send_window: "20MiB"
quic_connection_receive_window: "20MiB"
"#,
  );
  let config = args.validate_and_apply_defaults().unwrap();
  assert_eq!(config.max_concurrent_bidi_streams, 200);
  assert_eq!(config.max_idle_timeout_ms, Some(60000));
  assert_eq!(config.initial_mtu, 1400);
  assert_eq!(config.send_window, Some(20 * 1024 * 1024));
  assert_eq!(config.receive_window, Some(20 * 1024 * 1024));
}

// ========== Boundary values (valid) ==========

#[test]
fn test_quic_config_bidi_streams_lower_bound_succeeds() {
  let args =
    parse_args(r#"quic_connection_max_concurrent_bidi_streams: 1"#);
  assert!(args.validate_and_apply_defaults().is_ok());
}

#[test]
fn test_quic_config_bidi_streams_upper_bound_succeeds() {
  let args = parse_args(
    r#"quic_connection_max_concurrent_bidi_streams: 1152921504606846976"#,
  );
  assert!(args.validate_and_apply_defaults().is_ok());
}

#[test]
fn test_quic_config_initial_mtu_lower_bound_succeeds() {
  let args = parse_args(r#"quic_connection_initial_mtu: 1200"#);
  assert!(args.validate_and_apply_defaults().is_ok());
}

#[test]
fn test_quic_config_initial_mtu_upper_bound_succeeds() {
  let args = parse_args(r#"quic_connection_initial_mtu: 9000"#);
  assert!(args.validate_and_apply_defaults().is_ok());
}

// ========== Invalid values ==========

#[test]
fn test_quic_config_bidi_streams_zero_rejected() {
  let args =
    parse_args(r#"quic_connection_max_concurrent_bidi_streams: 0"#);
  let err = args.validate_and_apply_defaults().unwrap_err();
  assert!(
    err
      .to_string()
      .contains("quic_connection_max_concurrent_bidi_streams")
  );
}

#[test]
fn test_quic_config_bidi_streams_too_high_rejected() {
  let args = parse_args(
    r#"quic_connection_max_concurrent_bidi_streams: 1152921504606846977"#,
  );
  let err = args.validate_and_apply_defaults().unwrap_err();
  assert!(
    err
      .to_string()
      .contains("quic_connection_max_concurrent_bidi_streams")
  );
}

#[test]
fn test_quic_config_idle_timeout_zero_rejected() {
  let args = parse_args(r#"quic_connection_max_idle_timeout: "0ms""#);
  let err = args.validate_and_apply_defaults().unwrap_err();
  assert!(err.to_string().contains("quic_connection_max_idle_timeout"));
}

#[test]
fn test_quic_config_initial_mtu_too_low_rejected() {
  let args = parse_args(r#"quic_connection_initial_mtu: 100"#);
  let err = args.validate_and_apply_defaults().unwrap_err();
  assert!(err.to_string().contains("quic_connection_initial_mtu"));
}

#[test]
fn test_quic_config_initial_mtu_too_high_rejected() {
  let args = parse_args(r#"quic_connection_initial_mtu: 10000"#);
  let err = args.validate_and_apply_defaults().unwrap_err();
  assert!(err.to_string().contains("quic_connection_initial_mtu"));
}

#[test]
fn test_quic_config_send_window_zero_rejected() {
  let args = parse_args(r#"quic_connection_send_window: "0""#);
  let err = args.validate_and_apply_defaults().unwrap_err();
  assert!(err.to_string().contains("quic_connection_send_window"));
}

#[test]
fn test_quic_config_receive_window_zero_rejected() {
  let args = parse_args(r#"quic_connection_receive_window: "0""#);
  let err = args.validate_and_apply_defaults().unwrap_err();
  assert!(err.to_string().contains("quic_connection_receive_window"));
}

// ========== Default impl ==========

#[test]
fn test_quic_config_default_trait_matches_constants() {
  use super::quic_config::*;
  let config = QuicConfig::default();
  assert_eq!(
    config.max_concurrent_bidi_streams,
    DEFAULT_MAX_CONCURRENT_BIDI_STREAMS
  );
  assert_eq!(config.max_idle_timeout_ms, None);
  assert_eq!(config.initial_mtu, DEFAULT_INITIAL_MTU);
  assert_eq!(config.send_window, None);
  assert_eq!(config.receive_window, None);
}

#[test]
fn test_quic_config_rejects_unrepresentable_values() {
  for yaml in [
    "quic_connection_max_idle_timeout: 18446744073709552s",
    "quic_connection_max_idle_timeout: 4611686018427388s",
    "quic_connection_receive_window: 4611686018427387904B",
  ] {
    assert!(
      parse_args(yaml).validate_and_apply_defaults().is_err(),
      "accepted unrepresentable QUIC config {yaml}"
    );
  }
}

#[test]
fn test_quic_config_flat_fields_and_new_transport_settings() {
  let args: super::quic_config::Http3ListenerArgs =
    serde_yaml::from_str(
      "quic_connection_max_concurrent_bidi_streams: \
       10001\nquic_connection_handshake_timeout: \
       7s\nquic_connection_keep_alive_interval: \
       1s\nquic_stream_receive_window: 1MiB",
    )
    .unwrap();
  let config = args.validate_and_apply_defaults().unwrap();
  assert_eq!(config.max_concurrent_bidi_streams, 10001);
  assert_eq!(
    config.handshake_timeout,
    std::time::Duration::from_secs(7)
  );
  assert_eq!(
    config.keep_alive_interval,
    Some(std::time::Duration::from_secs(1))
  );
  assert_eq!(config.stream_receive_window, Some(1048576));
}
