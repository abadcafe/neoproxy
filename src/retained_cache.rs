//! module: retained_cache
//! responsibility: bound idle keyed state while preserving in-use
//! identity public operations:
//! RetainedCache::{new,get_or_insert_with,values} data entities:
//! RetainedCache, Entry tests: retained_cache_tests.rs
use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;
use std::ops::Bound::{Excluded, Unbounded};

const MAX_EVICTION_SCAN: usize = 64;

struct Entry<V> {
  value: V,
  sequence: u128,
}

/// LRU retention with an explicit ownership predicate. Busy entries can
/// exceed capacity; later accesses reclaim them once their owners
/// leave. Eviction never invalidates a value retained by an outstanding
/// operation.
pub(crate) struct RetainedCache<K, V> {
  entries: HashMap<K, Entry<V>>,
  order: BTreeMap<u128, K>,
  sequence: u128,
  capacity: usize,
  scan_after: u128,
}

impl<K: Clone + Eq + Hash, V> RetainedCache<K, V> {
  pub(crate) fn new(capacity: usize) -> Self {
    assert!(capacity > 0, "retained cache requires positive capacity");
    Self {
      entries: HashMap::new(),
      order: BTreeMap::new(),
      sequence: 0,
      capacity,
      scan_after: 0,
    }
  }

  pub(crate) fn get_or_insert_with(
    &mut self,
    key: K,
    create: impl FnOnce() -> V,
    evictable: impl Fn(&V) -> bool,
  ) -> &V {
    self.sequence += 1;
    let entry = self.entries.entry(key.clone()).or_insert_with(|| {
      Entry { value: create(), sequence: self.sequence }
    });
    self.order.remove(&entry.sequence);
    entry.sequence = self.sequence;
    self.order.insert(self.sequence, key.clone());
    // Bound maintenance even when all entries are pinned. Resume after
    // the last inspected entry so busy old targets cannot keep idle
    // history alive, or cause a quadratic scan during an active burst.
    for _ in 0..MAX_EVICTION_SCAN.min(self.entries.len()) {
      if self.entries.len() <= self.capacity {
        break;
      }
      let (&sequence, candidate) = self
        .order
        .range((Excluded(self.scan_after), Unbounded))
        .next()
        .or_else(|| self.order.first_key_value())
        .expect("cache is nonempty");
      self.scan_after = sequence;
      if candidate != &key && evictable(&self.entries[candidate].value)
      {
        let candidate = candidate.clone();
        self.order.remove(&sequence);
        self.entries.remove(&candidate);
      }
    }
    &self.entries[&key].value
  }

  pub(crate) fn values(&self) -> impl Iterator<Item = &V> {
    self.entries.values().map(|entry| &entry.value)
  }
}
