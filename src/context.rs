//! Request-scoped context for loose coupling between layers and
//! services.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// A string-keyed context for request-scoped data.
///
/// Uses `Arc<Mutex>` so that `.cloned()` creates a new handle to
/// the shared data, rather than a deep copy.
#[derive(Clone)]
pub struct RequestContext {
  inner: Arc<Mutex<HashMap<String, String>>>,
}

impl RequestContext {
  pub fn new() -> Self {
    Self { inner: Arc::new(Mutex::new(HashMap::new())) }
  }

  pub fn insert(&self, key: impl Into<String>, value: impl ToString) {
    self
      .inner
      .lock()
      .unwrap_or_else(|e| e.into_inner())
      .insert(key.into(), value.to_string());
  }

  pub fn get(&self, key: &str) -> Option<String> {
    self
      .inner
      .lock()
      .unwrap_or_else(|e| e.into_inner())
      .get(key)
      .cloned()
  }
}

impl Default for RequestContext {
  fn default() -> Self {
    Self::new()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_new_is_empty() {
    let ctx = RequestContext::new();
    assert!(ctx.get("key").is_none());
  }

  #[test]
  fn test_insert_and_get() {
    let ctx = RequestContext::new();
    ctx.insert("user", "admin");
    assert_eq!(ctx.get("user"), Some("admin".to_string()));
  }

  #[test]
  fn test_insert_overwrites() {
    let ctx = RequestContext::new();
    ctx.insert("key", "v1");
    ctx.insert("key", "v2");
    assert_eq!(ctx.get("key"), Some("v2".to_string()));
  }

  #[test]
  fn test_clone_shares_data() {
    let ctx1 = RequestContext::new();
    ctx1.insert("key", "value");
    let ctx2 = ctx1.clone();
    // Both see the same data
    assert_eq!(ctx2.get("key"), Some("value".to_string()));
    // Mutation through one is visible through the other
    ctx2.insert("key", "new_value");
    assert_eq!(ctx1.get("key"), Some("new_value".to_string()));
  }

  #[test]
  fn test_default() {
    let ctx = RequestContext::default();
    assert!(ctx.get("any").is_none());
  }

  #[test]
  fn test_insert_different_value_types() {
    let ctx = RequestContext::new();
    ctx.insert("port", 8080u16);
    ctx.insert("duration", 42u64);
    assert_eq!(ctx.get("port"), Some("8080".to_string()));
    assert_eq!(ctx.get("duration"), Some("42".to_string()));
  }

  #[test]
  fn test_handles_poisoned_mutex_get() {
    let ctx = RequestContext::new();
    ctx.insert("key", "value");

    // Poison the mutex by panicking while holding the lock
    let ctx_clone = ctx.clone();
    let _ = std::thread::spawn(move || {
      let _guard = ctx_clone.inner.lock().unwrap();
      panic!("poison the mutex");
    })
    .join();

    // After poison, get should still work (recover from poison)
    assert_eq!(ctx.get("key"), Some("value".to_string()));
  }

  #[test]
  fn test_handles_poisoned_mutex_insert() {
    let ctx = RequestContext::new();
    ctx.insert("before", "poison");

    // Poison the mutex
    let ctx_clone = ctx.clone();
    let _ = std::thread::spawn(move || {
      let _guard = ctx_clone.inner.lock().unwrap();
      panic!("poison the mutex");
    })
    .join();

    // After poison, insert should still work
    ctx.insert("after", "recovery");
    assert_eq!(ctx.get("after"), Some("recovery".to_string()));
  }
}
