//! module: http_policy
//! responsibility: validate listener HTTP exchange policy
//! public operations: HttpPolicy, IdleTimeout::duration, Deserialize
//! data entities: HttpPolicy, IdleTimeout, DurationValue
//! tests: http_policy_tests.rs
use std::time::Duration;

use serde::Deserialize;

#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(default)]
pub(crate) struct HttpPolicy {
  #[serde(flatten)]
  pub(crate) request_limits: crate::header_limits::RequestLimits,
  pub(crate) body_read_timeout: IdleTimeout,
  pub(crate) write_timeout: IdleTimeout,
}
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(try_from = "DurationValue")]
pub(crate) struct IdleTimeout(Duration);
#[derive(Deserialize)]
struct DurationValue(#[serde(with = "humantime_serde")] Duration);
impl TryFrom<DurationValue> for IdleTimeout {
  type Error = &'static str;

  fn try_from(value: DurationValue) -> Result<Self, Self::Error> {
    if value.0.is_zero()
      || std::time::Instant::now().checked_add(value.0).is_none()
    {
      return Err(
        "HTTP inactivity timeout must be positive and representable",
      );
    }
    Ok(Self(value.0))
  }
}
impl Default for IdleTimeout {
  fn default() -> Self {
    Self(Duration::from_secs(60))
  }
}
impl IdleTimeout {
  pub(crate) fn duration(self) -> Duration {
    self.0
  }
}
