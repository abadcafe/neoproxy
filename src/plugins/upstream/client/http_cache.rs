//! module: http_cache
//! responsibility: cache exclusively owned HTTP/1 connections
//! process-wide public operations: Cache::{new,take,put,close}, Key,
//! Connection data entities: Cache, Key, Connection, Entry, Entries
//! tests: HTTP pool process contracts
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hyper::client::conn::http1::SendRequest;

use super::observation::ConnectionObservation;
use crate::http_message::RequestBody;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct Key {
  pub(super) endpoint: std::net::SocketAddr,
  pub(super) server_name: Option<String>,
  pub(super) origin: Option<String>,
}
pub(super) struct Connection {
  pub(super) timeout: super::exchange_timeout::Control,
  pub(super) sender: SendRequest<RequestBody>,
  pub(super) driver:
    Pin<Box<dyn Future<Output = Result<(), hyper::Error>> + Send>>,
  pub(super) observation: ConnectionObservation,
}
struct Entry {
  connection: Connection,
  expires: tokio::time::Instant,
}
#[derive(Default)]
struct Entries {
  by_key: HashMap<Key, Vec<Entry>>,
  count: usize,
  next_expiry: Option<tokio::time::Instant>,
}
impl Entries {
  fn prune(&mut self, closed: bool) -> Vec<Connection> {
    let now = tokio::time::Instant::now();
    if !closed && self.next_expiry.is_none_or(|deadline| deadline > now)
    {
      return Vec::new();
    }
    let mut retired = Vec::new();
    let mut next_expiry = None;
    self.by_key.retain(|_, entries| {
      let mut index = 0;
      while index < entries.len() {
        let entry = &entries[index];
        if entry.expires <= now
          || (closed && entry.connection.sender.is_closed())
        {
          retired.push(entries.swap_remove(index).connection);
        } else {
          next_expiry = Some(
            next_expiry
              .map_or(entry.expires, |next: tokio::time::Instant| {
                next.min(entry.expires)
              }),
          );
          index += 1;
        }
      }
      !entries.is_empty()
    });
    self.count -= retired.len();
    self.next_expiry = next_expiry;
    retired
  }
}
pub(super) struct Cache {
  pub(super) limits: crate::header_limits::Limits,
  entries: Mutex<Entries>,
  reaper: std::sync::atomic::AtomicBool,
  changed: Arc<tokio::sync::Notify>,
  max_idle: usize,
  idle_timeout: Duration,
  tasks: Arc<crate::task_tracker::background::TaskTracker>,
  runtime: tokio::runtime::Handle,
}
impl Cache {
  pub(super) fn new(
    max_idle: usize,
    idle_timeout: Duration,
    limits: crate::header_limits::Limits,
    tasks: Arc<crate::task_tracker::background::TaskTracker>,
    runtime: tokio::runtime::Handle,
  ) -> Arc<Self> {
    Arc::new(Self {
      limits,
      entries: Mutex::new(Entries::default()),
      reaper: std::sync::atomic::AtomicBool::new(false),
      changed: Arc::new(tokio::sync::Notify::new()),
      max_idle,
      idle_timeout,
      tasks,
      runtime,
    })
  }

  pub(super) fn take(&self, key: &Key) -> Option<Connection> {
    let mut entries = self.entries.lock().expect("HTTP cache poisoned");
    let mut retired = entries.prune(false);
    let mut selected = None;
    while let Some(entry) =
      entries.by_key.get_mut(key).and_then(Vec::pop)
    {
      entries.count -= 1;
      if entry.connection.sender.is_closed() {
        retired.push(entry.connection);
      } else {
        selected = Some(entry.connection);
        break;
      }
    }
    if entries.by_key.get(key).is_some_and(Vec::is_empty) {
      entries.by_key.remove(key);
    }
    drop(entries);
    drop(retired);
    selected
  }

  pub(super) fn put(
    self: &Arc<Self>,
    key: Key,
    connection: Connection,
  ) {
    if self.max_idle == 0 {
      return;
    }
    let expires = tokio::time::Instant::now() + self.idle_timeout;
    let mut entries = self.entries.lock().expect("HTTP cache poisoned");
    let full = entries.count >= self.max_idle;
    let retired = entries.prune(full);
    if entries.count >= self.max_idle {
      drop(entries);
      drop(retired);
      return;
    }
    entries
      .by_key
      .entry(key)
      .or_default()
      .push(Entry { connection, expires });
    entries.count += 1;
    entries.next_expiry = Some(
      entries.next_expiry.map_or(expires, |next| next.min(expires)),
    );
    drop(entries);
    drop(retired);
    self.changed.notify_one();
    if self.reaper.swap(true, std::sync::atomic::Ordering::AcqRel) {
      return;
    }
    let weak = Arc::downgrade(self);
    let changed = self.changed.clone();
    let shutdown = self.tasks.shutdown_handle();
    self.tasks.register_on(&self.runtime, async move {
      let maintenance = async {
      loop {
        let (deadline, retired) = {
          let Some(cache) = weak.upgrade() else { return; };
          let mut entries = cache.entries.lock().expect("HTTP cache poisoned");
          let retired = entries.prune(false);
          (entries.next_expiry, retired)
        };
        drop(retired);
        if let Some(deadline) = deadline {
          tokio::select! { _ = tokio::time::sleep_until(deadline) => {}, _ = changed.notified() => {} }
        } else {
          changed.notified().await;
        }
      }
      };
      tokio::select! {
        _ = shutdown.notified() => {},
        _ = maintenance => {},
      }
    });
  }

  pub(super) fn close(&self) {
    let retired = std::mem::take(
      &mut *self.entries.lock().expect("HTTP cache poisoned"),
    );
    drop(retired);
  }
}
