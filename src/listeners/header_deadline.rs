//! module: header_deadline
//! responsibility: validate finite request-header read deadlines
//! public operations: HeaderDeadline::{default, duration}, Deserialize
//! data entities: HeaderDeadline, DurationValue
//! tests: header_deadline_tests.rs

use std::time::Duration;

use anyhow::{Result, ensure};
use serde::Deserialize;

const DEFAULT_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(75);

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(try_from = "DurationValue")]
pub(crate) struct HeaderDeadline(Duration);
#[derive(Deserialize)]
struct DurationValue(#[serde(with = "humantime_serde")] Duration);
impl TryFrom<DurationValue> for HeaderDeadline {
  type Error = anyhow::Error;

  fn try_from(value: DurationValue) -> Result<Self> {
    ensure!(
      !value.0.is_zero()
        && std::time::Instant::now().checked_add(value.0).is_some(),
      "header_read_timeout must be positive and representable"
    );
    Ok(Self(value.0))
  }
}
impl Default for HeaderDeadline {
  fn default() -> Self {
    Self(DEFAULT_HEADER_READ_TIMEOUT)
  }
}

impl HeaderDeadline {
  pub(crate) fn duration(self) -> Duration {
    self.0
  }
}
