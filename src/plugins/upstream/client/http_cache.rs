//! module: http_cache
//! responsibility: cache exclusively owned HTTP/1 connections
//! process-wide public operations: Cache::{new,take,put,close}, Key,
//! Connection data entities: Cache, Key, Connection, Entry
//! tests: HTTP pool process contracts
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hyper::client::conn::http1::SendRequest;

use super::observation::ConnectionObservation;
use crate::http_message::RequestBody;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Key {
  pub(super) endpoint: std::net::SocketAddr,
  pub(super) server_name: Option<String>,
  pub(super) origin: Option<String>,
}
pub(super) struct Connection {
  pub(super) sender: SendRequest<RequestBody>,
  pub(super) driver:
    Pin<Box<dyn Future<Output = Result<(), hyper::Error>> + Send>>,
  pub(super) observation: ConnectionObservation,
}
struct Entry {
  key: Key,
  connection: Connection,
  expires: tokio::time::Instant,
}
pub(super) struct Cache {
  entries: Mutex<Vec<Entry>>,
  reaper: std::sync::atomic::AtomicBool,
  changed: Arc<tokio::sync::Notify>,
  max_idle: usize,
  idle_timeout: Duration,
}
impl Cache {
  pub(super) fn new(
    max_idle: usize,
    idle_timeout: Duration,
  ) -> Arc<Self> {
    Arc::new(Self {
      entries: Mutex::new(Vec::new()),
      reaper: std::sync::atomic::AtomicBool::new(false),
      changed: Arc::new(tokio::sync::Notify::new()),
      max_idle,
      idle_timeout,
    })
  }

  pub(super) fn take(&self, key: &Key) -> Option<Connection> {
    let mut entries = self.entries.lock().expect("HTTP cache poisoned");
    entries.retain(|entry| {
      entry.expires > tokio::time::Instant::now()
        && !entry.connection.sender.is_closed()
    });
    let index = entries.iter().rposition(|entry| &entry.key == key)?;
    Some(entries.swap_remove(index).connection)
  }

  pub(super) fn put(
    self: &Arc<Self>,
    key: Key,
    connection: Connection,
  ) {
    let expires = tokio::time::Instant::now() + self.idle_timeout;
    {
      let mut entries =
        self.entries.lock().expect("HTTP cache poisoned");
      entries.retain(|entry| {
        entry.expires > tokio::time::Instant::now()
          && !entry.connection.sender.is_closed()
      });
      if entries.len() >= self.max_idle {
        return;
      }
      entries.push(Entry { key, connection, expires });
    }
    self.changed.notify_one();
    if self.reaper.swap(true, std::sync::atomic::Ordering::AcqRel) {
      return;
    }
    let weak = Arc::downgrade(self);
    let changed = self.changed.clone();
    tokio::spawn(async move {
      loop {
        let deadline = {
          let Some(cache) = weak.upgrade() else {
            return;
          };
          let mut entries =
            cache.entries.lock().expect("HTTP cache poisoned");
          entries.retain(|entry| {
            entry.expires > tokio::time::Instant::now()
          });
          entries.iter().map(|entry| entry.expires).min()
        };
        if let Some(deadline) = deadline {
          tokio::select! { _ = tokio::time::sleep_until(deadline) => {}, _ = changed.notified() => {} }
        } else {
          changed.notified().await;
        }
      }
    });
  }

  pub(super) fn close(&self) {
    self.entries.lock().expect("HTTP cache poisoned").clear();
  }
}
