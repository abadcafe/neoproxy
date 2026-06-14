//! Tests for QUIC configuration validation.

use super::quic_config::QuicConfigArgs;

fn parse_args(yaml: &str) -> QuicConfigArgs {
  let args: crate::config::SerializedArgs =
    serde_yaml::from_str(yaml).unwrap();
  let parsed: super::quic_config::Http3ListenerArgs =
    serde_yaml::from_value(args).unwrap();
  parsed.quic.unwrap()
}

// ========== Valid configurations ==========

#[test]
fn test_quic_config_default_values_succeeds() {
  let args = parse_args(r#"quic: {}"#);
  let config = args.validate_and_apply_defaults().unwrap();
  assert_eq!(config.max_concurrent_bidi_streams, 100);
  assert_eq!(config.max_idle_timeout_ms, 5000);
  assert_eq!(config.initial_mtu, 1200);
  assert_eq!(config.send_window, 10 * 1024 * 1024);
  assert_eq!(config.receive_window, 10 * 1024 * 1024);
}

#[test]
fn test_quic_config_custom_values_succeeds() {
  let args = parse_args(
    r#"
quic:
  max_concurrent_bidi_streams: 200
  max_idle_timeout: "60s"
  initial_mtu: 1400
  send_window: "20MiB"
  receive_window: "20MiB"
"#,
  );
  let config = args.validate_and_apply_defaults().unwrap();
  assert_eq!(config.max_concurrent_bidi_streams, 200);
  assert_eq!(config.max_idle_timeout_ms, 60000);
  assert_eq!(config.initial_mtu, 1400);
  assert_eq!(config.send_window, 20 * 1024 * 1024);
  assert_eq!(config.receive_window, 20 * 1024 * 1024);
}

// ========== Boundary values (valid) ==========

#[test]
fn test_quic_config_bidi_streams_lower_bound_succeeds() {
  let args = parse_args(r#"quic: { max_concurrent_bidi_streams: 1 }"#);
  assert!(args.validate_and_apply_defaults().is_ok());
}

#[test]
fn test_quic_config_bidi_streams_upper_bound_succeeds() {
  let args =
    parse_args(r#"quic: { max_concurrent_bidi_streams: 10000 }"#);
  assert!(args.validate_and_apply_defaults().is_ok());
}

#[test]
fn test_quic_config_initial_mtu_lower_bound_succeeds() {
  let args = parse_args(r#"quic: { initial_mtu: 1200 }"#);
  assert!(args.validate_and_apply_defaults().is_ok());
}

#[test]
fn test_quic_config_initial_mtu_upper_bound_succeeds() {
  let args = parse_args(r#"quic: { initial_mtu: 9000 }"#);
  assert!(args.validate_and_apply_defaults().is_ok());
}

// ========== Invalid values ==========

#[test]
fn test_quic_config_bidi_streams_zero_rejected() {
  let args = parse_args(r#"quic: { max_concurrent_bidi_streams: 0 }"#);
  let err = args.validate_and_apply_defaults().unwrap_err();
  assert!(err.to_string().contains("max_concurrent_bidi_streams"));
}

#[test]
fn test_quic_config_bidi_streams_too_high_rejected() {
  let args =
    parse_args(r#"quic: { max_concurrent_bidi_streams: 10001 }"#);
  let err = args.validate_and_apply_defaults().unwrap_err();
  assert!(err.to_string().contains("max_concurrent_bidi_streams"));
}

#[test]
fn test_quic_config_idle_timeout_zero_rejected() {
  let args = parse_args(r#"quic: { max_idle_timeout: "0ms" }"#);
  let err = args.validate_and_apply_defaults().unwrap_err();
  assert!(err.to_string().contains("max_idle_timeout"));
}

#[test]
fn test_quic_config_initial_mtu_too_low_rejected() {
  let args = parse_args(r#"quic: { initial_mtu: 100 }"#);
  let err = args.validate_and_apply_defaults().unwrap_err();
  assert!(err.to_string().contains("initial_mtu"));
}

#[test]
fn test_quic_config_initial_mtu_too_high_rejected() {
  let args = parse_args(r#"quic: { initial_mtu: 10000 }"#);
  let err = args.validate_and_apply_defaults().unwrap_err();
  assert!(err.to_string().contains("initial_mtu"));
}

#[test]
fn test_quic_config_send_window_zero_rejected() {
  let args = parse_args(r#"quic: { send_window: "0" }"#);
  let err = args.validate_and_apply_defaults().unwrap_err();
  assert!(err.to_string().contains("send_window"));
}

#[test]
fn test_quic_config_receive_window_zero_rejected() {
  let args = parse_args(r#"quic: { receive_window: "0" }"#);
  let err = args.validate_and_apply_defaults().unwrap_err();
  assert!(err.to_string().contains("receive_window"));
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
  assert_eq!(
    config.max_idle_timeout_ms,
    DEFAULT_MAX_IDLE_TIMEOUT.as_millis() as u64
  );
  assert_eq!(config.initial_mtu, DEFAULT_INITIAL_MTU);
  assert_eq!(config.send_window, DEFAULT_SEND_WINDOW.as_u64());
  assert_eq!(config.receive_window, DEFAULT_RECEIVE_WINDOW.as_u64());
}
