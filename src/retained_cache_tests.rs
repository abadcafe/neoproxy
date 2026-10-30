//! Observable ownership and eviction contracts for retained_cache.
use std::sync::Arc;

use crate::retained_cache::RetainedCache;

#[test]
fn test_get_or_insert_reclaims_idle_history_after_large_pinned_burst() {
  let mut cache = RetainedCache::new(2);
  let busy: Vec<_> = (0..200)
    .map(|key| {
      cache
        .get_or_insert_with(
          key,
          || Arc::new(key),
          |value| Arc::strong_count(value) == 1,
        )
        .clone()
    })
    .collect();
  let history: Vec<_> = busy.iter().map(Arc::downgrade).collect();
  drop(busy);
  for key in 200..400 {
    cache.get_or_insert_with(
      key,
      || Arc::new(key),
      |value| Arc::strong_count(value) == 1,
    );
  }
  assert!(history.iter().all(|value| value.upgrade().is_none()));
  assert_eq!(cache.values().count(), 2);
}

#[test]
fn test_get_or_insert_reuses_value_and_evicts_least_recent_idle_entry()
{
  let mut cache = RetainedCache::new(2);
  let first = Arc::downgrade(cache.get_or_insert_with(
    "first",
    || Arc::new(1),
    |v| Arc::strong_count(v) == 1,
  ));
  let second = Arc::downgrade(cache.get_or_insert_with(
    "second",
    || Arc::new(2),
    |v| Arc::strong_count(v) == 1,
  ));
  assert_eq!(
    **cache.get_or_insert_with(
      "first",
      || panic!("existing value must be reused"),
      |v| Arc::strong_count(v) == 1,
    ),
    1
  );
  cache.get_or_insert_with(
    "third",
    || Arc::new(3),
    |v| Arc::strong_count(v) == 1,
  );
  assert!(first.upgrade().is_some());
  assert!(second.upgrade().is_none());
}

#[test]
fn test_get_or_insert_preserves_busy_entries_and_reclaims_after_release()
 {
  let mut cache = RetainedCache::new(1);
  let busy = cache
    .get_or_insert_with(
      "busy",
      || Arc::new(1),
      |v| Arc::strong_count(v) == 1,
    )
    .clone();
  cache.get_or_insert_with(
    "other",
    || Arc::new(2),
    |v| Arc::strong_count(v) == 1,
  );
  assert_eq!(cache.values().count(), 2);
  assert!(Arc::ptr_eq(
    &busy,
    cache.get_or_insert_with(
      "busy",
      || panic!("in-use identity must be preserved"),
      |v| Arc::strong_count(v) == 1,
    )
  ));
  drop(busy);
  cache.get_or_insert_with(
    "last",
    || Arc::new(3),
    |v| Arc::strong_count(v) == 1,
  );
  assert_eq!(cache.values().count(), 1);
}
