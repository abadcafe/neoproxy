use std::time::Duration;

use anyhow::{Result, bail};
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
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub(super) struct Http3ListenerArgs {
  /// QUIC protocol parameters (optional)
  #[serde(default)]
  pub(super) quic: Option<QuicConfigArgs>,
}

/// QUIC protocol configuration arguments
#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub(super) struct QuicConfigArgs {
  /// Maximum concurrent bidirectional streams (default: 100, range:
  /// 1-10000)
  #[serde(default = "default_max_concurrent_bidi_streams")]
  max_concurrent_bidi_streams: u64,
  /// Maximum idle timeout (default: 5s)
  #[serde(
    with = "humantime_serde",
    default = "default_max_idle_timeout"
  )]
  max_idle_timeout: Duration,
  /// Initial MTU (default: 1200, range: 1200-9000)
  #[serde(default = "default_initial_mtu")]
  initial_mtu: u16,
  /// Send window size (default: 10MiB)
  #[serde(default = "default_send_window")]
  send_window: Byte,
  /// Receive window size (default: 10MiB)
  #[serde(default = "default_receive_window")]
  receive_window: Byte,
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

impl QuicConfigArgs {
  /// Validate and apply defaults to QUIC configuration
  ///
  /// Returns validated configuration with defaults applied where
  /// needed. Invalid values return an error, rejecting startup.
  pub(super) fn validate_and_apply_defaults(
    &self,
  ) -> Result<QuicConfig> {
    if !(1..=10000).contains(&self.max_concurrent_bidi_streams) {
      bail!(
        "Invalid max_concurrent_bidi_streams: {}, expected range \
         1-10000",
        self.max_concurrent_bidi_streams
      );
    }

    let max_idle_timeout_ms = self.max_idle_timeout.as_millis() as u64;
    if max_idle_timeout_ms == 0 {
      bail!("Invalid max_idle_timeout: must be > 0ms");
    }

    if !(1200..=9000).contains(&self.initial_mtu) {
      bail!(
        "Invalid initial_mtu: {}, expected range 1200-9000",
        self.initial_mtu
      );
    }

    let send_window = self.send_window.as_u64();
    if send_window == 0 {
      bail!("Invalid send_window: must be > 0");
    }

    let receive_window = self.receive_window.as_u64();
    if receive_window == 0 {
      bail!("Invalid receive_window: must be > 0");
    }

    Ok(QuicConfig {
      max_concurrent_bidi_streams: self.max_concurrent_bidi_streams,
      max_idle_timeout_ms,
      initial_mtu: self.initial_mtu,
      send_window,
      receive_window,
    })
  }
}

/// Validated QUIC configuration with applied defaults
#[derive(Clone, Debug)]
pub(super) struct QuicConfig {
  pub(super) max_concurrent_bidi_streams: u64,
  pub(super) max_idle_timeout_ms: u64,
  pub(super) initial_mtu: u16,
  pub(super) send_window: u64,
  pub(super) receive_window: u64,
}

impl Default for QuicConfig {
  fn default() -> Self {
    Self {
      max_concurrent_bidi_streams: DEFAULT_MAX_CONCURRENT_BIDI_STREAMS,
      max_idle_timeout_ms: DEFAULT_MAX_IDLE_TIMEOUT.as_millis() as u64,
      initial_mtu: DEFAULT_INITIAL_MTU,
      send_window: DEFAULT_SEND_WINDOW.as_u64(),
      receive_window: DEFAULT_RECEIVE_WINDOW.as_u64(),
    }
  }
}
