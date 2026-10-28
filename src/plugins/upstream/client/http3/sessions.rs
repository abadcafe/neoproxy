//! module: sessions
//! responsibility: enforce per-endpoint H3 capacity and session
//! rotation public operations: Store::{new,bucket,close},
//! Bucket::{reserve,insert,select,retire}, Session data entities:
//! Store, Bucket, Session tests: H3 pool process contracts
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::lease::{Session, SessionLease};
pub(super) struct Bucket {
  sessions: Mutex<Vec<Arc<Session>>>,
  capacity: Arc<tokio::sync::Semaphore>,
  pub(super) changed: tokio::sync::Notify,
  sequence: AtomicUsize,
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

  pub(super) fn insert(&self, session: Arc<Session>) {
    let mut sessions =
      self.sessions.lock().expect("H3 sessions poisoned");
    if self.is_closed() {
      session.connection.close(0x100u32.into(), b"pool shutdown");
      return;
    }
    sessions.push(session);
    self.changed.notify_waiters();
  }

  pub(super) fn select(
    &self,
    hostname: &Option<String>,
  ) -> Option<SessionLease> {
    let sessions = self.sessions.lock().expect("H3 sessions poisoned");
    let candidates: Vec<_> = sessions
      .iter()
      .filter(|s| {
        &s.hostname == hostname
          && !s.draining.load(Ordering::Acquire)
          && s.connection.close_reason().is_none()
      })
      .collect();
    if candidates.is_empty() {
      return None;
    }
    let session =
      candidates[self.sequence.fetch_add(1, Ordering::Relaxed)
        % candidates.len()]
      .clone();
    // Reserve activity under the same lock as maintenance.
    Some(SessionLease::new(session))
  }

  pub(super) fn retire(&self) {
    self.sessions.lock().expect("H3 sessions poisoned").retain(|s| {
      if s.expired(self.timeout) {
        s.connection.close(0x100u32.into(), b"pool retirement");
        false
      } else {
        true
      }
    });
    self.changed.notify_waiters();
  }

  fn close(&self) {
    self.capacity.close();
    self.changed.notify_waiters();
    for session in
      self.sessions.lock().expect("H3 sessions poisoned").drain(..)
    {
      session.connection.close(0x100u32.into(), b"pool shutdown");
    }
  }
}
pub(in crate::plugins::upstream::client) struct Store {
  pub(in crate::plugins::upstream::client) limits:
    crate::header_limits::Limits,
  buckets: Mutex<HashMap<std::net::SocketAddr, Arc<Bucket>>>,
  maximum: usize,
  timeout: Duration,
}
impl Store {
  pub(in crate::plugins::upstream::client) fn new(
    maximum: usize,
    timeout: Duration,
    limits: crate::header_limits::Limits,
  ) -> Arc<Self> {
    Arc::new(Self {
      limits,
      buckets: Mutex::new(HashMap::new()),
      maximum,
      timeout,
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
      .entry(address)
      .or_insert_with(|| {
        let bucket = Arc::new(Bucket {
          sessions: Mutex::new(Vec::new()),
          capacity: Arc::new(tokio::sync::Semaphore::new(self.maximum)),
          changed: tokio::sync::Notify::new(),
          sequence: AtomicUsize::new(0),
          timeout: self.timeout,
        });
        let weak = Arc::downgrade(&bucket);
        let interval = self.timeout.min(Duration::from_millis(100));
        runtime.spawn(async move {
          loop {
            tokio::time::sleep(interval).await;
            let Some(bucket) = weak.upgrade() else {
              return;
            };
            bucket.retire();
          }
        });
        bucket
      })
      .clone()
  }

  pub(in crate::plugins::upstream::client) fn close(&self) {
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
