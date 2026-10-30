//! module: sessions
//! responsibility: enforce per-endpoint H3 capacity and session
//! rotation public operations: Store::{new,bucket,close},
//! Bucket::{reserve,wait_capacity,insert,select,retire}, Session data
//! entities: Store, Bucket, Sessions tests: sessions_tests.rs; H3 pool
//! process contracts
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::lease::{Session, SessionLease};
use crate::retained_cache::RetainedCache;
#[derive(Default)]
struct Sessions {
  entries: Vec<Arc<Session>>,
  sequence: usize,
}
pub(super) struct Bucket {
  sessions: Mutex<Sessions>,
  capacity: Arc<tokio::sync::Semaphore>,
  pub(super) changed: tokio::sync::Notify,
  timeout: Duration,
}
impl Bucket {
  pub(super) fn is_closed(&self) -> bool {
    self.capacity.is_closed()
  }

  pub(super) fn reserve(
    &self,
  ) -> Option<tokio::sync::OwnedSemaphorePermit> {
    self.capacity.clone().try_acquire_owned().ok()
  }

  pub(super) async fn wait_capacity(
    &self,
  ) -> Option<tokio::sync::OwnedSemaphorePermit> {
    self.capacity.clone().acquire_owned().await.ok()
  }

  pub(super) fn insert(&self, session: Arc<Session>) {
    let mut sessions =
      self.sessions.lock().expect("H3 sessions poisoned");
    if self.is_closed() {
      drop(sessions);
      session.connection.close(0x100u32.into(), b"pool shutdown");
      return;
    }
    sessions.entries.push(session);
    drop(sessions);
    self.changed.notify_waiters();
  }

  pub(super) fn select(
    &self,
    hostname: &Option<String>,
  ) -> Option<SessionLease> {
    let mut sessions =
      self.sessions.lock().expect("H3 sessions poisoned");
    let eligible = |s: &&Arc<Session>| {
      &s.hostname == hostname
        && !s.draining.load(Ordering::Acquire)
        && s.connection.close_reason().is_none()
    };
    let count = sessions.entries.iter().filter(eligible).count();
    if count == 0 {
      return None;
    }
    let index = sessions.sequence % count;
    sessions.sequence = sessions.sequence.wrapping_add(1);
    // Closure/draining can change concurrently even under the bucket
    // lock. Recheck eligibility and tolerate a shrinking candidate set.
    let session = sessions
      .entries
      .iter()
      .filter(eligible)
      .nth(index)
      .or_else(|| sessions.entries.iter().find(eligible))?
      .clone();
    Some(SessionLease::new(session))
  }

  pub(super) fn retire(&self) {
    let retired = {
      let mut sessions =
        self.sessions.lock().expect("H3 sessions poisoned");
      sessions
        .entries
        .extract_if(.., |session| session.expired(self.timeout))
        .collect::<Vec<_>>()
    };
    if !retired.is_empty() {
      for session in retired {
        session.connection.close(0x100u32.into(), b"pool retirement");
      }
      self.changed.notify_waiters();
    }
  }

  fn close(&self) {
    self.capacity.close();
    let retired = std::mem::take(
      &mut self.sessions.lock().expect("H3 sessions poisoned").entries,
    );
    self.changed.notify_waiters();
    for session in retired {
      session.connection.close(0x100u32.into(), b"pool shutdown");
    }
  }
}
pub(in crate::plugins::upstream::client) struct Store {
  pub(in crate::plugins::upstream::client) limits:
    crate::header_limits::Limits,
  buckets: Mutex<RetainedCache<std::net::SocketAddr, Arc<Bucket>>>,
  maximum: usize,
  timeout: Duration,
  pub(super) tasks: Arc<crate::task_tracker::background::TaskTracker>,
}
impl Store {
  pub(in crate::plugins::upstream::client) fn new(
    maximum: usize,
    timeout: Duration,
    limits: crate::header_limits::Limits,
    tasks: Arc<crate::task_tracker::background::TaskTracker>,
  ) -> Arc<Self> {
    Arc::new(Self {
      limits,
      buckets: Mutex::new(RetainedCache::new(128)),
      maximum,
      timeout,
      tasks,
    })
  }

  pub(super) fn bucket(
    &self,
    address: std::net::SocketAddr,
    runtime: &tokio::runtime::Handle,
  ) -> Arc<Bucket> {
    self
      .buckets
      .lock()
      .expect("H3 registry poisoned")
      .get_or_insert_with(
        address,
        || {
          let bucket = Arc::new(Bucket {
            sessions: Mutex::new(Sessions::default()),
            capacity: Arc::new(tokio::sync::Semaphore::new(
              self.maximum,
            )),
            changed: tokio::sync::Notify::new(),
            timeout: self.timeout,
          });
          let weak = Arc::downgrade(&bucket);
          let interval = self.timeout.min(Duration::from_millis(100));
          let shutdown = self.tasks.shutdown_handle();
          self.tasks.register_on(runtime, async move {
            loop {
              tokio::select! {
                _ = shutdown.notified() => return,
                _ = tokio::time::sleep(interval) => {},
              }
              let Some(bucket) = weak.upgrade() else {
                return;
              };
              bucket.retire();
            }
          });
          bucket
        },
        |bucket| {
          Arc::strong_count(bucket) == 1
            && bucket.capacity.available_permits() == self.maximum
        },
      )
      .clone()
  }

  pub(in crate::plugins::upstream::client) fn close(&self) {
    self.tasks.shutdown();
    for bucket in
      self.buckets.lock().expect("H3 registry poisoned").values()
    {
      bucket.close();
    }
  }
}
impl Drop for Store {
  fn drop(&mut self) {
    self.close();
  }
}
