//! Black-box tests for the shutdown module.

use std::time::Duration;

use crate::shutdown::ShutdownHandle;

#[tokio::test]
async fn test_notified_observes_shutdown_before_subscription() {
  let handle = ShutdownHandle::new();
  handle.shutdown();
  for _ in 0..3 {
    assert!(
      tokio::time::timeout(
        Duration::from_millis(100),
        handle.notified()
      )
      .await
      .is_ok()
    );
  }
}

#[test]
fn test_shutdown_handle_new_is_not_shutdown() {
  let handle = ShutdownHandle::new();
  assert!(
    !handle.is_shutdown(),
    "New ShutdownHandle should not be in shutdown state"
  );
}

#[test]
fn test_shutdown_handle_is_shutdown_after_shutdown() {
  let handle = ShutdownHandle::new();
  handle.shutdown();
  assert!(
    handle.is_shutdown(),
    "ShutdownHandle should be in shutdown state after shutdown() is \
     called"
  );
}

#[test]
fn test_shutdown_handle_clone_shares_state() {
  let handle = ShutdownHandle::new();
  let cloned = handle.clone();
  handle.shutdown();
  assert!(
    cloned.is_shutdown(),
    "Cloned ShutdownHandle should share shutdown state"
  );
}

#[test]
fn test_shutdown_handle_multiple_shutdown_calls() {
  let handle = ShutdownHandle::new();
  handle.shutdown();
  handle.shutdown();
  handle.shutdown();
  assert!(
    handle.is_shutdown(),
    "Multiple shutdown calls should not cause issues"
  );
}

#[test]
fn test_shutdown_handle_multiple_clones() {
  let handle = ShutdownHandle::new();
  let clone1 = handle.clone();
  let clone2 = clone1.clone();
  let clone3 = handle.clone();
  clone2.shutdown();
  assert!(handle.is_shutdown(), "Original should show shutdown");
  assert!(clone1.is_shutdown(), "Clone1 should show shutdown");
  assert!(clone2.is_shutdown(), "Clone2 should show shutdown");
  assert!(clone3.is_shutdown(), "Clone3 should show shutdown");
}

#[tokio::test]
async fn test_shutdown_handle_notified_after_shutdown() {
  let handle = ShutdownHandle::new();
  let handle_clone = handle.clone();

  let notified = tokio::spawn(async move {
    handle_clone.notified().await;
    true
  });

  tokio::task::yield_now().await;
  handle.shutdown();

  let result =
    tokio::time::timeout(Duration::from_millis(100), notified).await;

  assert!(
    result.is_ok(),
    "notified() should complete after shutdown()"
  );
  assert!(result.unwrap().unwrap(), "notified() should have completed");
}

#[test]
fn test_child_shutdown_is_scoped_and_parent_shutdown_propagates() {
  let parent = ShutdownHandle::new();
  let child = parent.child();
  let sibling = parent.child();
  child.shutdown();
  assert!(child.is_shutdown());
  assert!(!parent.is_shutdown());
  assert!(!sibling.is_shutdown());
  parent.shutdown();
  assert!(sibling.is_shutdown());
  assert!(parent.child().is_shutdown());
}
