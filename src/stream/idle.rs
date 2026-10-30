//! module: idle
//! responsibility: calculate a tunnel's shared idle deadline
//! public operations: IdleDeadline::{new, record_activity,
//! deadline, is_expired} data entities: IdleDeadline
//! tests: idle_tests.rs

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Shared idle deadline for a bidirectional tunnel.
///
/// Both sides share one deadline. Any successful read or write on
/// either side resets the idle deadline.
#[derive(Clone)]
pub(crate) struct IdleDeadline {
  last_active_ns: Arc<AtomicU64>,
  idle_timeout: Duration,
  epoch: tokio::time::Instant,
}

impl IdleDeadline {
  pub(crate) fn new(idle_timeout: Duration) -> Self {
    Self {
      last_active_ns: Arc::new(AtomicU64::new(0)),
      idle_timeout,
      epoch: tokio::time::Instant::now(),
    }
  }

  /// Record activity (called on successful read/write).
  pub(crate) fn record_activity(&self) {
    let nanoseconds =
      self.epoch.elapsed().as_nanos().min(u64::MAX as u128) as u64;
    self.last_active_ns.fetch_max(nanoseconds, Ordering::Relaxed);
  }

  /// Return the instant at which the idle deadline expires based on
  /// the last recorded activity.
  pub(crate) fn deadline(&self) -> tokio::time::Instant {
    let last_ns = self.last_active_ns.load(Ordering::Relaxed);
    let last_instant = self.epoch + Duration::from_nanos(last_ns);
    last_instant + self.idle_timeout
  }

  /// Check whether the idle deadline has expired.
  pub(crate) fn is_expired(&self) -> bool {
    let now_ns =
      self.epoch.elapsed().as_nanos().min(u64::MAX as u128) as u64;
    let last = self.last_active_ns.load(Ordering::Relaxed);
    now_ns.saturating_sub(last)
      >= self.idle_timeout.as_nanos().min(u64::MAX as u128) as u64
  }
}
