use std::future::Future;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::Semaphore;

use super::cache::{Cache, Source, Update};
use super::policy::Policy;

struct SourceStub {
  calls: AtomicUsize,
  gate: Semaphore,
}
impl Source for SourceStub {
  fn fetch<'a>(
    &'a self,
    id: &'a str,
    version: Option<u64>,
  ) -> Pin<Box<dyn Future<Output = anyhow::Result<Update>> + Send + 'a>>
  {
    Box::pin(async move {
      self.calls.fetch_add(1, Ordering::SeqCst);
      self.gate.acquire().await.unwrap().forget();
      if id == "fail" {
        anyhow::bail!("offline");
      }
      match version {
        None => Ok(Update::Modified {
          version: 2,
          ttl: Duration::from_secs(10),
          policy: Arc::new(Policy::parse(
            serde_json::json!({"denyOut":["0.0.0.0/0"]}),
          )?),
        }),
        Some(_) => Ok(Update::Unmodified {
          version: 2,
          ttl: Duration::from_secs(10),
        }),
      }
    })
  }
}
fn make_cache(source: Arc<SourceStub>) -> Arc<Cache> {
  Arc::new(Cache::new(
    source,
    Arc::new(Policy::parse(serde_json::json!({})).unwrap()),
    Duration::from_secs(60),
    NonZeroUsize::new(1024).unwrap(),
  ))
}

#[tokio::test]
async fn test_get_concurrent_same_sandbox_fetches_once() {
  let source = Arc::new(SourceStub {
    calls: AtomicUsize::new(0),
    gate: Semaphore::new(0),
  });
  let cache = make_cache(source.clone());
  let mut tasks = Vec::new();
  for _ in 0..16 {
    let cache = cache.clone();
    tasks.push(tokio::spawn(async move { cache.get("sandbox").await }));
  }
  source.gate.add_permits(1);
  for task in tasks {
    assert_eq!(task.await.unwrap().unwrap().version, Some(2));
  }
  assert_eq!(source.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn test_get_expiry_revalidates_and_failure_caches_default() {
  let source = Arc::new(SourceStub {
    calls: AtomicUsize::new(0),
    gate: Semaphore::new(20),
  });
  let cache = make_cache(source.clone());
  assert_eq!(cache.get("sandbox").await.unwrap().version, Some(2));
  tokio::time::advance(Duration::from_secs(11)).await;
  assert_eq!(cache.get("sandbox").await.unwrap().version, Some(2));
  assert_eq!(source.calls.load(Ordering::SeqCst), 2);
  let fallback = cache.get("fail").await.unwrap();
  assert_eq!(fallback.version, None);
  assert!(fallback.policy.allows_ip("127.0.0.1".parse().unwrap()));
  let _ = cache.get("fail").await.unwrap();
  assert_eq!(source.calls.load(Ordering::SeqCst), 3);
  tokio::time::advance(Duration::from_secs(61)).await;
  let _ = cache.get("fail").await.unwrap();
  assert_eq!(source.calls.load(Ordering::SeqCst), 4);
}

struct SequenceSource {
  steps: std::sync::Mutex<
    std::collections::VecDeque<anyhow::Result<Update>>,
  >,
  versions: std::sync::Mutex<Vec<Option<u64>>>,
}
impl Source for SequenceSource {
  fn fetch<'a>(
    &'a self,
    _: &'a str,
    version: Option<u64>,
  ) -> Pin<Box<dyn Future<Output = anyhow::Result<Update>> + Send + 'a>>
  {
    self.versions.lock().unwrap().push(version);
    let update = self.steps.lock().unwrap().pop_front().unwrap();
    Box::pin(async move { update })
  }
}
#[tokio::test(start_paused = true)]
async fn test_get_version_rollback_and_equal_version_preserve_policy() {
  let deny = Arc::new(
    Policy::parse(serde_json::json!({"denyOut":["0.0.0.0/0"]}))
      .unwrap(),
  );
  let allow = Arc::new(Policy::parse(serde_json::json!({})).unwrap());
  let ttl = Duration::from_secs(10);
  let source = Arc::new(SequenceSource {
    steps: std::sync::Mutex::new(std::collections::VecDeque::from([
      Ok(Update::Modified { version: 3, ttl, policy: deny.clone() }),
      Ok(Update::Modified { version: 3, ttl, policy: allow.clone() }),
      Ok(Update::Modified { version: 2, ttl, policy: allow.clone() }),
      Err(anyhow::anyhow!("offline")),
      Ok(Update::Modified { version: 4, ttl, policy: allow.clone() }),
    ])),
    versions: std::sync::Mutex::new(Vec::new()),
  });
  let cache = Cache::new(
    source.clone(),
    allow,
    Duration::from_secs(60),
    NonZeroUsize::new(1024).unwrap(),
  );
  for elapsed in [0, 11, 11, 61] {
    tokio::time::advance(Duration::from_secs(elapsed)).await;
    let snapshot = cache.get("sandbox").await.unwrap();
    assert_eq!(snapshot.version, Some(3));
    assert!(!snapshot.policy.allows_ip("1.1.1.1".parse().unwrap()));
  }
  tokio::time::advance(Duration::from_secs(61)).await;
  let snapshot = cache.get("sandbox").await.unwrap();
  assert_eq!(snapshot.version, Some(4));
  assert!(snapshot.policy.allows_ip("1.1.1.1".parse().unwrap()));
  assert_eq!(
    *source.versions.lock().unwrap(),
    vec![None, Some(3), Some(3), Some(3), Some(3)]
  );
}

#[tokio::test(start_paused = true)]
async fn test_get_cancelled_fetch_releases_sandbox_mutex() {
  let source = Arc::new(SourceStub {
    calls: AtomicUsize::new(0),
    gate: Semaphore::new(0),
  });
  let cache = make_cache(source.clone());
  let pending = {
    let cache = cache.clone();
    tokio::spawn(async move { cache.get("sandbox").await })
  };
  tokio::task::yield_now().await;
  pending.abort();
  let result = pending.await;
  assert!(matches!(result, Err(error) if error.is_cancelled()));
  source.gate.add_permits(1);
  assert_eq!(cache.get("sandbox").await.unwrap().version, Some(2));
  assert_eq!(source.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test(start_paused = true)]
async fn test_get_capacity_preserves_remote_policy_and_version_on_refresh_failure()
 {
  let deny = Arc::new(
    Policy::parse(serde_json::json!({"denyOut":["0.0.0.0/0"]}))
      .unwrap(),
  );
  let source = Arc::new(SequenceSource {
    steps: std::sync::Mutex::new(std::collections::VecDeque::from([
      Ok(Update::Modified {
        version: 2,
        ttl: Duration::from_secs(10),
        policy: deny.clone(),
      }),
      Ok(Update::Modified {
        version: 2,
        ttl: Duration::from_secs(10),
        policy: deny,
      }),
      Err(anyhow::anyhow!("offline")),
    ])),
    versions: std::sync::Mutex::new(Vec::new()),
  });
  let cache = Cache::new(
    source.clone(),
    Arc::new(Policy::parse(serde_json::json!({})).unwrap()),
    Duration::from_secs(60),
    NonZeroUsize::new(2).unwrap(),
  );
  assert_eq!(cache.get("a").await.unwrap().version, Some(2));
  assert_eq!(cache.get("b").await.unwrap().version, Some(2));
  assert!(cache.get("c").await.is_err());
  tokio::time::advance(Duration::from_secs(11)).await;
  let snapshot = cache.get("a").await.unwrap();
  assert_eq!(snapshot.version, Some(2));
  assert!(!snapshot.policy.allows_ip("1.1.1.1".parse().unwrap()));
  assert_eq!(
    *source.versions.lock().unwrap(),
    vec![None, None, Some(2)]
  );
}

#[tokio::test(start_paused = true)]
async fn test_get_capacity_reclaims_only_expired_default_policy() {
  let source = Arc::new(SourceStub {
    calls: AtomicUsize::new(0),
    gate: Semaphore::new(3),
  });
  let cache = Cache::new(
    source.clone(),
    Arc::new(Policy::parse(serde_json::json!({})).unwrap()),
    Duration::from_secs(60),
    NonZeroUsize::new(1).unwrap(),
  );
  assert!(cache.get("fail").await.unwrap().version.is_none());
  assert!(cache.get("new").await.is_err());
  tokio::time::advance(Duration::from_secs(61)).await;
  assert_eq!(cache.get("new").await.unwrap().version, Some(2));
  assert_eq!(source.calls.load(Ordering::SeqCst), 2);
}
