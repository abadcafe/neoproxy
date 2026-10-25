//! module: idle
//! responsibilities: track a tunnel's last activity with a shared
//! precise deadline public operations: IdleTracker::{new, touch,
//! deadline, is_idle} data entities: IdleTracker
//! tests: idle_tests.rs

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Shared activity tracker for idle timeout across a bidirectional
/// tunnel.
///
/// Both sides share one tracker. Any successful read or write on either
/// side resets the idle deadline.
#[derive(Clone)]
pub(crate) struct IdleTracker {
  last_active_ns: Arc<AtomicU64>,
  idle_timeout: Duration,
  epoch: tokio::time::Instant,
}

impl IdleTracker {
  pub(crate) fn new(idle_timeout: Duration) -> Self {
    Self {
      last_active_ns: Arc::new(AtomicU64::new(0)),
      idle_timeout,
      epoch: tokio::time::Instant::now(),
    }
  }

  /// Record activity (called on successful read/write).
  pub(crate) fn touch(&self) {
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

  /// Check whether the connection is genuinely idle right now.
  pub(crate) fn is_idle(&self) -> bool {
    let now_ns =
      self.epoch.elapsed().as_nanos().min(u64::MAX as u128) as u64;
    let last = self.last_active_ns.load(Ordering::Relaxed);
    now_ns.saturating_sub(last)
      >= self.idle_timeout.as_nanos().min(u64::MAX as u128) as u64
  }
}
