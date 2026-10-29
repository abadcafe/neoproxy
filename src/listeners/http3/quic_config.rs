//! module: listeners::http3::quic_config
//! responsibility: validate listener QUIC transport parameters
//! public operations: DEFAULT_MAX_CONCURRENT_BIDI_STREAMS,
//! DEFAULT_INITIAL_MTU, H3_NO_ERROR_CODE,
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

/// Default initial MTU
pub(super) const DEFAULT_INITIAL_MTU: u16 = 1200;

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
  #[serde(flatten)]
  datagram: crate::quic_datagram::Config,
  #[serde(flatten)]
  pub(super) request_limits: crate::header_limits::RequestLimits,
  #[serde(default)]
  pub(super) body_read_timeout:
    crate::listeners::http_policy::IdleTimeout,
  #[serde(default)]
  pub(super) write_timeout: crate::listeners::http_policy::IdleTimeout,
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
  /// Omission preserves Quinn's default transport idle timeout.
  #[serde(with = "humantime_serde", default)]
  quic_connection_max_idle_timeout: Option<Duration>,
  /// Initial MTU (default: 1200, range: 1200-9000)
  #[serde(default = "default_initial_mtu")]
  quic_connection_initial_mtu: u16,
  /// Omission preserves Quinn's default connection windows.
  #[serde(default)]
  quic_connection_send_window: Option<Byte>,
  #[serde(default)]
  quic_connection_receive_window: Option<Byte>,
}

fn default_handshake_timeout() -> Duration {
  Duration::from_secs(5)
}

fn default_max_concurrent_bidi_streams() -> u64 {
  DEFAULT_MAX_CONCURRENT_BIDI_STREAMS
}

fn default_initial_mtu() -> u16 {
  DEFAULT_INITIAL_MTU
}

impl Http3ListenerArgs {
  /// Validate and apply defaults to QUIC configuration
  ///
  /// Returns validated configuration with defaults applied where
  /// needed. Invalid values return an error, rejecting startup.
  pub(super) fn validate_and_apply_defaults(
    &self,
  ) -> Result<QuicConfig> {
    self.datagram.validate()?;
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
    if let (Some(value), Some(idle)) = (
      self.quic_connection_keep_alive_interval,
      self.quic_connection_max_idle_timeout,
    ) {
      anyhow::ensure!(
        value < idle,
        "quic_connection_keep_alive_interval must be less than \
         quic_connection_max_idle_timeout"
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
    let max_idle_timeout_ms = self
      .quic_connection_max_idle_timeout
      .map(|value| -> Result<u64> {
        let milliseconds = u64::try_from(value.as_millis()).context(
          "Invalid quic_connection_max_idle_timeout: milliseconds \
           overflow",
        )?;
        quinn::VarInt::try_from(milliseconds).context(
          "Invalid quic_connection_max_idle_timeout: exceeds QUIC \
           range",
        )?;
        anyhow::ensure!(
          milliseconds > 0,
          "Invalid quic_connection_max_idle_timeout: must be > 0ms"
        );
        Ok(milliseconds)
      })
      .transpose()?;

    if !(1200..=9000).contains(&self.quic_connection_initial_mtu) {
      bail!(
        "Invalid quic_connection_initial_mtu: {}, expected range \
         1200-9000",
        self.quic_connection_initial_mtu
      );
    }

    let send_window =
      self.quic_connection_send_window.map(|v| v.as_u64());
    let receive_window =
      self.quic_connection_receive_window.map(|v| v.as_u64());
    if send_window == Some(0) {
      bail!("Invalid quic_connection_send_window: must be > 0");
    }
    if let Some(value) = receive_window {
      anyhow::ensure!(
        value > 0,
        "Invalid quic_connection_receive_window: must be > 0"
      );
      quinn::VarInt::try_from(value).context(
        "Invalid quic_connection_receive_window: exceeds QUIC range",
      )?;
    }

    Ok(QuicConfig {
      datagram: self.datagram.clone(),
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
  pub(super) datagram: crate::quic_datagram::Config,
  pub(super) handshake_timeout: Duration,
  pub(super) keep_alive_interval: Option<Duration>,
  pub(super) stream_receive_window: Option<u64>,
  pub(super) max_concurrent_bidi_streams: u64,
  pub(super) max_idle_timeout_ms: Option<u64>,
  pub(super) initial_mtu: u16,
  pub(super) send_window: Option<u64>,
  pub(super) receive_window: Option<u64>,
}

impl Default for QuicConfig {
  fn default() -> Self {
    Self {
      datagram: Default::default(),
      handshake_timeout: default_handshake_timeout(),
      keep_alive_interval: None,
      stream_receive_window: None,
      max_concurrent_bidi_streams: DEFAULT_MAX_CONCURRENT_BIDI_STREAMS,
      max_idle_timeout_ms: None,
      initial_mtu: DEFAULT_INITIAL_MTU,
      send_window: None,
      receive_window: None,
    }
  }
}
