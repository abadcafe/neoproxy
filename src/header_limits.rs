//! module: header_limits
//! responsibility: represent validated incoming HTTP header budgets
//! public operations: RequestLimits::limits, ResponseLimits::limits,
//! Limits::{count,bytes,accepts}, Deserialize
//! data entities: HeaderSize, RequestLimits, ResponseLimits, Limits
//! tests: header_limits_tests.rs
use std::num::NonZeroUsize;

use serde::Deserialize;

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(try_from = "byte_unit::Byte")]
struct HeaderSize(u32);
impl TryFrom<byte_unit::Byte> for HeaderSize {
  type Error = &'static str;

  fn try_from(value: byte_unit::Byte) -> Result<Self, Self::Error> {
    let value = u32::try_from(value.as_u64())
      .map_err(|_| "header size exceeds u32::MAX")?;
    if value == 0 {
      return Err("header size must be positive");
    }
    Ok(Self(value))
  }
}
impl Default for HeaderSize {
  fn default() -> Self {
    Self(32 * 1024)
  }
}
fn default_count() -> NonZeroUsize {
  NonZeroUsize::new(100).unwrap()
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(default)]
pub(crate) struct RequestLimits {
  max_request_headers: NonZeroUsize,
  max_request_header_size: HeaderSize,
}
impl Default for RequestLimits {
  fn default() -> Self {
    Self {
      max_request_headers: default_count(),
      max_request_header_size: HeaderSize::default(),
    }
  }
}
impl RequestLimits {
  pub(crate) fn limits(self) -> Limits {
    Limits {
      count: self.max_request_headers,
      size: self.max_request_header_size,
    }
  }
}
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(default)]
pub(crate) struct ResponseLimits {
  max_response_headers: NonZeroUsize,
  max_response_header_size: HeaderSize,
}
impl Default for ResponseLimits {
  fn default() -> Self {
    Self {
      max_response_headers: default_count(),
      max_response_header_size: HeaderSize::default(),
    }
  }
}
impl ResponseLimits {
  pub(crate) fn limits(self) -> Limits {
    Limits {
      count: self.max_response_headers,
      size: self.max_response_header_size,
    }
  }
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
  count: NonZeroUsize,
  size: HeaderSize,
}
impl Limits {
  pub(crate) fn count(self) -> usize {
    self.count.get()
  }

  pub(crate) fn bytes(self) -> u32 {
    self.size.0
  }

  /// Size is enforced by each protocol's decoder, before allocation.
  pub(crate) fn accepts(self, headers: &http::HeaderMap) -> bool {
    headers.len() <= self.count()
  }
}
