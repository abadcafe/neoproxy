//! module: listeners::http3::quic_config
//! responsibility: validate listener QUIC transport parameters
//! public operations: DEFAULT_MAX_CONCURRENT_BIDI_STREAMS,
//! DEFAULT_MAX_IDLE_TIMEOUT, DEFAULT_INITIAL_MTU,
//! DEFAULT_SEND_WINDOW, DEFAULT_RECEIVE_WINDOW, H3_NO_ERROR_CODE,
//! Http3ListenerArgs, validate_and_apply_defaults,
//! QuicConfig
//! data entities: Http3ListenerArgs, QuicConfig
//! tests: quic_config_tests.rs

use std::time::Duration;

use anyhow::{Context, Result, bail};
use byte_unit::Byte;
use serde::Deserialize;

/// Default maximum concurrent bidirectional streams
pub(super) const DEFAULT_MAX_CONCURRENT_BIDI_STREAMS: u64 = 100;

/// Default maximum idle timeout
pub(super) const DEFAULT_MAX_IDLE_TIMEOUT: Duration =
  Duration::from_secs(5);

/// Default initial MTU
pub(super) const DEFAULT_INITIAL_MTU: u16 = 1200;

/// Default send window size (10MiB)
pub(super) const DEFAULT_SEND_WINDOW: Byte = Byte::from_u64(10485760);

/// Default receive window size (10MiB)
pub(super) const DEFAULT_RECEIVE_WINDOW: Byte =
  Byte::from_u64(10485760);

/// H3_NO_ERROR error code for CONNECTION_CLOSE frame
/// See: https://www.rfc-editor.org/rfc/rfc9114.html#errors
/// Value 0x100 = 256, which fits in u32
pub(super) const H3_NO_ERROR_CODE: u32 = 0x100;

// ============================================================================
// Configuration Structures
// ============================================================================

/// HTTP/3 Listener configuration arguments
#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub(super) struct Http3ListenerArgs {
  #[serde(default)]
  pub(super) header_read_timeout:
    crate::listeners::header_deadline::HeaderDeadline,
  #[serde(
    with = "humantime_serde",
    default = "default_handshake_timeout"
  )]
  quic_connection_handshake_timeout: Duration,
  #[serde(with = "humantime_serde", default)]
  quic_connection_keep_alive_interval: Option<Duration>,
  #[serde(default)]
  quic_stream_receive_window: Option<Byte>,
  /// Maximum concurrent bidirectional streams (default: 100, range:
  /// 1..=2^60)
  #[serde(default = "default_max_concurrent_bidi_streams")]
  quic_connection_max_concurrent_bidi_streams: u64,
  /// Maximum idle timeout (default: 5s)
  #[serde(
    with = "humantime_serde",
    default = "default_max_idle_timeout"
  )]
  quic_connection_idle_timeout: Duration,
  /// Initial MTU (default: 1200, range: 1200-9000)
  #[serde(default = "default_initial_mtu")]
  quic_connection_initial_mtu: u16,
  /// Send window size (default: 10MiB)
  #[serde(default = "default_send_window")]
  quic_connection_send_window: Byte,
  /// Receive window size (default: 10MiB)
  #[serde(default = "default_receive_window")]
  quic_connection_receive_window: Byte,
}

fn default_handshake_timeout() -> Duration {
  Duration::from_secs(5)
}

fn default_max_concurrent_bidi_streams() -> u64 {
  DEFAULT_MAX_CONCURRENT_BIDI_STREAMS
}

fn default_max_idle_timeout() -> Duration {
  DEFAULT_MAX_IDLE_TIMEOUT
}

fn default_initial_mtu() -> u16 {
  DEFAULT_INITIAL_MTU
}

fn default_send_window() -> Byte {
  DEFAULT_SEND_WINDOW
}

fn default_receive_window() -> Byte {
  DEFAULT_RECEIVE_WINDOW
}

impl Http3ListenerArgs {
  /// Validate and apply defaults to QUIC configuration
  ///
  /// Returns validated configuration with defaults applied where
  /// needed. Invalid values return an error, rejecting startup.
  pub(super) fn validate_and_apply_defaults(
    &self,
  ) -> Result<QuicConfig> {
    if !(1..=1u64 << 60)
      .contains(&self.quic_connection_max_concurrent_bidi_streams)
    {
      bail!(
        "Invalid quic_connection_max_concurrent_bidi_streams: {}, \
         expected range 1..=2^60",
        self.quic_connection_max_concurrent_bidi_streams
      );
    }

    for (name, value) in [
      (
        "quic_connection_handshake_timeout",
        Some(self.quic_connection_handshake_timeout),
      ),
      (
        "quic_connection_keep_alive_interval",
        self.quic_connection_keep_alive_interval,
      ),
    ] {
      if let Some(value) = value {
        anyhow::ensure!(
          !value.is_zero()
            && std::time::Instant::now().checked_add(value).is_some(),
          "{name} must be positive and representable"
        );
      }
    }
    if let Some(value) = self.quic_connection_keep_alive_interval {
      anyhow::ensure!(
        value < self.quic_connection_idle_timeout,
        "quic_connection_keep_alive_interval must be less than \
         quic_connection_idle_timeout"
      );
    }
    let stream_receive_window =
      self.quic_stream_receive_window.map(|value| value.as_u64());
    if let Some(value) = stream_receive_window {
      anyhow::ensure!(
        value > 0 && quinn::VarInt::from_u64(value).is_ok(),
        "quic_stream_receive_window must fit a positive QUIC variable \
         integer"
      );
    }
    let max_idle_timeout_ms =
      u64::try_from(self.quic_connection_idle_timeout.as_millis())
        .context(
          "Invalid quic_connection_idle_timeout: milliseconds overflow",
        )?;
    quinn::VarInt::try_from(max_idle_timeout_ms).context(
      "Invalid quic_connection_idle_timeout: exceeds QUIC range",
    )?;
    if max_idle_timeout_ms == 0 {
      bail!("Invalid quic_connection_idle_timeout: must be > 0ms");
    }

    if !(1200..=9000).contains(&self.quic_connection_initial_mtu) {
      bail!(
        "Invalid quic_connection_initial_mtu: {}, expected range \
         1200-9000",
        self.quic_connection_initial_mtu
      );
    }

    let send_window = self.quic_connection_send_window.as_u64();
    if send_window == 0 {
      bail!("Invalid quic_connection_send_window: must be > 0");
    }

    let receive_window = self.quic_connection_receive_window.as_u64();
    if receive_window == 0 {
      bail!("Invalid quic_connection_receive_window: must be > 0");
    }

    quinn::VarInt::try_from(receive_window).context(
      "Invalid quic_connection_receive_window: exceeds QUIC range",
    )?;

    Ok(QuicConfig {
      handshake_timeout: self.quic_connection_handshake_timeout,
      keep_alive_interval: self.quic_connection_keep_alive_interval,
      stream_receive_window,
      max_concurrent_bidi_streams: self
        .quic_connection_max_concurrent_bidi_streams,
      max_idle_timeout_ms,
      initial_mtu: self.quic_connection_initial_mtu,
      send_window,
      receive_window,
    })
  }
}

/// Validated QUIC configuration with applied defaults
#[derive(Clone, Debug)]
pub(super) struct QuicConfig {
  pub(super) handshake_timeout: Duration,
  pub(super) keep_alive_interval: Option<Duration>,
  pub(super) stream_receive_window: Option<u64>,
  pub(super) max_concurrent_bidi_streams: u64,
  pub(super) max_idle_timeout_ms: u64,
  pub(super) initial_mtu: u16,
  pub(super) send_window: u64,
  pub(super) receive_window: u64,
}

impl Default for QuicConfig {
  fn default() -> Self {
    Self {
      handshake_timeout: default_handshake_timeout(),
      keep_alive_interval: None,
      stream_receive_window: None,
      max_concurrent_bidi_streams: DEFAULT_MAX_CONCURRENT_BIDI_STREAMS,
      max_idle_timeout_ms: DEFAULT_MAX_IDLE_TIMEOUT.as_millis() as u64,
      initial_mtu: DEFAULT_INITIAL_MTU,
      send_window: DEFAULT_SEND_WINDOW.as_u64(),
      receive_window: DEFAULT_RECEIVE_WINDOW.as_u64(),
    }
  }
}
