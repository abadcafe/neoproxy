//! module: worker_shutdown
//! responsibility: coordinate worker transport release after business
//! drain public operations: participants,
//! WorkerShutdown::{shutdown_handle, finish} data entities:
//! WorkerShutdown, Group tests: worker_shutdown_tests.rs

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::shutdown::ShutdownHandle;

struct Group {
  remaining: AtomicUsize,
  released: ShutdownHandle,
  shutdown: ShutdownHandle,
}

pub(crate) struct WorkerShutdown {
  group: Arc<Group>,
  arrived: bool,
}

/// Register all workers before spawning, including workers whose
/// threads may fail to start. Dropping their guard releases their slot.
pub(crate) fn participants(
  count: usize,
  shutdown: ShutdownHandle,
) -> Vec<WorkerShutdown> {
  let group = Arc::new(Group {
    remaining: AtomicUsize::new(count),
    released: ShutdownHandle::new(),
    shutdown,
  });
  (0..count)
    .map(|_| WorkerShutdown { group: group.clone(), arrived: false })
    .collect()
}

impl WorkerShutdown {
  pub(crate) fn shutdown_handle(&self) -> ShutdownHandle {
    self.group.shutdown.clone()
  }

  /// Peers are already using the existing request/plugin drain
  /// budgets. This rendezvous adds no third grace period. Keep polling
  /// the worker runtime while waiting so UDP drivers remain alive.
  pub(crate) async fn finish(&mut self) {
    self.group.shutdown.shutdown();
    self.arrive();
    self.group.released.notified().await;
  }

  fn arrive(&mut self) {
    if !self.arrived {
      self.arrived = true;
      if self.group.remaining.fetch_sub(1, Ordering::AcqRel) == 1 {
        self.group.released.shutdown();
      }
    }
  }
}

impl Drop for WorkerShutdown {
  fn drop(&mut self) {
    // Do not catch programming panics. During unwinding release this
    // participant and notify peers, so shutdown cannot deadlock on a
    // worker which panicked or whose thread failed to start.
    self.group.shutdown.shutdown();
    self.arrive();
  }
}
