//! module: cache
//! responsibility: synchronously refresh process-shared sandbox policy
//! snapshots public operations: Cache::{new,get}, Source::fetch,
//! Update, Snapshot data entities: Cache, Entry, Slot, Update,
//! Snapshot, CapacityExceeded, Source tests: cache_tests.rs
use std::collections::HashMap;
use std::future::Future;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::{Arc, Mutex as MapMutex, RwLock};
use std::time::Duration;

use tokio::sync::Mutex;
use tokio::time::Instant;

use super::policy::Policy;

pub(super) enum Update {
  Modified { version: u64, ttl: Duration, policy: Arc<Policy> },
  Unmodified { version: u64, ttl: Duration },
}
pub(super) trait Source: Send + Sync {
  fn fetch<'a>(
    &'a self,
    sandbox_id: &'a str,
    version: Option<u64>,
  ) -> Pin<Box<dyn Future<Output = anyhow::Result<Update>> + Send + 'a>>;
}
#[derive(Clone)]
pub(super) struct Snapshot {
  pub(super) policy: Arc<Policy>,
  pub(super) version: Option<u64>,
}
struct Entry {
  snapshot: Snapshot,
  expires: Instant,
}
#[derive(Default)]
struct Slot {
  entry: RwLock<Option<Arc<Entry>>>,
  refresh: Mutex<()>,
}
impl Slot {
  fn snapshot(&self) -> Option<Arc<Entry>> {
    self.entry.read().expect("policy snapshot poisoned").clone()
  }
}
#[derive(Debug)]
pub(super) struct CapacityExceeded;
pub(super) struct Cache {
  source: Arc<dyn Source>,
  default: Arc<Policy>,
  fallback: Duration,
  entries: MapMutex<HashMap<String, Arc<Slot>>>,
  capacity: NonZeroUsize,
}
impl Cache {
  pub(super) fn new(
    source: Arc<dyn Source>,
    default: Arc<Policy>,
    fallback: Duration,
    capacity: NonZeroUsize,
  ) -> Self {
    Self {
      source,
      default,
      fallback,
      entries: MapMutex::new(HashMap::new()),
      capacity,
    }
  }

  pub(super) async fn get(
    &self,
    sandbox_id: &str,
  ) -> Result<Snapshot, CapacityExceeded> {
    let slot = {
      let mut entries =
        self.entries.lock().expect("policy cache poisoned");
      if let Some(slot) = entries.get(sandbox_id) {
        slot.clone()
      } else {
        if entries.len() >= self.capacity.get() {
          // Remote policy history cannot be evicted: an outage must
          // never replace a previous denial with a permissive default.
          // Only abandoned fetches or expired default-only entries are
          // disposable; in-flight fetches and their waiters pin slots.
          entries.retain(|_, slot| {
            Arc::strong_count(slot) > 1
              || slot.entry.try_read().map_or(true, |entry| {
                entry.as_ref().is_some_and(|entry| {
                  entry.snapshot.version.is_some()
                    || Instant::now() < entry.expires
                })
              })
          });
          if entries.len() >= self.capacity.get() {
            return Err(CapacityExceeded);
          }
        }
        entries
          .entry(sandbox_id.to_owned())
          .or_insert_with(|| Arc::new(Slot::default()))
          .clone()
      }
    };
    let current = slot.snapshot();
    if let Some(current) = current
      && Instant::now() < current.expires
    {
      return Ok(current.snapshot.clone());
    }
    // Product contract: hold this sandbox's asynchronous mutex
    // throughout the fetch. Waiters recheck freshness after acquiring
    // it. Expired snapshots are retained ONLY for fallback after a
    // confirmed fetch failure. Other sandboxes never wait on this
    // network request.
    let _refresh = slot.refresh.lock().await;
    let entry = slot.snapshot();
    if let Some(current) = entry.as_ref()
      && Instant::now() < current.expires
    {
      return Ok(current.snapshot.clone());
    }
    let version = entry.as_ref().and_then(|e| e.snapshot.version);
    let update =
      self.source.fetch(sandbox_id, version).await.and_then(|update| {
        let (received, ttl) = match &update {
          Update::Modified { version, ttl, .. }
          | Update::Unmodified { version, ttl } => (*version, *ttl),
        };
        anyhow::ensure!(
          received > 0 && version.is_none_or(|old| received >= old),
          "policy version rollback"
        );
        anyhow::ensure!(
          !ttl.is_zero() && Instant::now().checked_add(ttl).is_some(),
          "invalid policy TTL"
        );
        if matches!(update, Update::Unmodified { .. }) {
          anyhow::ensure!(
            version == Some(received),
            "304 requires a matching cached version"
          );
        }
        Ok(update)
      });
    let now = Instant::now();
    let next = match update {
      Ok(Update::Modified { version: received, ttl, policy })
        if version != Some(received) =>
      {
        Entry {
          snapshot: Snapshot { policy, version: Some(received) },
          expires: now + ttl,
        }
      }
      Ok(
        Update::Modified { ttl, .. } | Update::Unmodified { ttl, .. },
      ) => {
        let current =
          entry.as_ref().expect("validated matching cached version");
        Entry {
          snapshot: current.snapshot.clone(),
          expires: current
            .expires
            .max(now)
            .checked_add(ttl)
            .expect("validated TTL"),
        }
      }
      Err(error) => {
        tracing::warn!(sandbox_id, error=%error, "policy refresh failed; using fallback");
        Entry {
          snapshot: entry
            .as_ref()
            .map(|e| e.snapshot.clone())
            .unwrap_or_else(|| Snapshot {
              policy: self.default.clone(),
              version: None,
            }),
          expires: now + self.fallback,
        }
      }
    };
    let snapshot = next.snapshot.clone();
    *slot.entry.write().expect("policy snapshot poisoned") =
      Some(Arc::new(next));
    Ok(snapshot)
  }
}
