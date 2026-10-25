use crate::process::run;
use crate::shutdown::ShutdownHandle;

fn runtime() -> tokio::runtime::Runtime {
  tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .unwrap()
}

#[tokio::test]
async fn test_run_signal_shutdown_without_workers() {
  let shutdown = ShutdownHandle::new();
  assert_eq!(run(vec![], shutdown.clone(), async {}).await, 0);
  assert!(shutdown.is_shutdown());
}

#[test]
fn test_run_worker_failure_stops_other_workers() {
  let shutdown = ShutdownHandle::new();
  let peer_shutdown = shutdown.clone();
  std::thread::scope(|scope| {
    let worker = scope.spawn(move || {
      while !peer_shutdown.is_shutdown() {
        std::thread::yield_now();
      }
      Ok(())
    });
    let failed =
      scope.spawn(|| Err(anyhow::anyhow!("listener bind failed")));
    assert_eq!(
      runtime().block_on(run(
        vec![worker, failed],
        shutdown.clone(),
        std::future::pending(),
      )),
      2
    );
  });
  assert!(shutdown.is_shutdown());
}

#[test]
fn test_run_worker_panic_returns_failure_exit_code() {
  std::thread::scope(|scope| {
    // Deliberately panic a worker. The supervisor must join it and
    // report failure before leaving the scope.
    let worker = scope.spawn(|| panic!("programming error"));
    assert_eq!(
      runtime().block_on(run(
        vec![worker],
        ShutdownHandle::new(),
        std::future::pending(),
      )),
      1
    );
  });
}

#[test]
fn test_run_tracked_task_panic_stops_other_workers() {
  let shutdown = ShutdownHandle::new();
  let peer_shutdown = shutdown.clone();
  std::thread::scope(|scope| {
    let peer = scope.spawn(move || {
      while !peer_shutdown.is_shutdown() {
        std::thread::yield_now();
      }
      Ok(())
    });
    let failed = scope.spawn(|| {
      runtime().block_on(tokio::task::LocalSet::new().run_until(
        async {
          let tracker = crate::tracker::StreamTracker::new();
          tracker.register(async {
            // Intentionally crash a connection task: joining it must
            // unwind this worker, stop its peers, and
            // produce a failure exit code.
            panic!("connection task programming error")
          });
          tracker.wait_shutdown().await;
        },
      ));
      Ok(())
    });
    assert_eq!(
      runtime().block_on(run(
        vec![peer, failed],
        shutdown.clone(),
        std::future::pending(),
      )),
      1
    );
  });
  assert!(shutdown.is_shutdown());
}

#[test]
fn test_run_normal_exit_stops_and_joins_peers_borrowing_local_state() {
  let shutdown = ShutdownHandle::new();
  let mut peer_stopped = false;
  let worker_name = String::from("borrowed worker");
  std::thread::scope(|scope| {
    let peer = scope.spawn(|| {
      while !shutdown.is_shutdown() {
        std::thread::yield_now();
      }
      peer_stopped = true;
      Ok(())
    });
    let finished = scope.spawn(|| {
      assert_eq!(worker_name, "borrowed worker");
      Ok(())
    });
    assert_eq!(
      runtime().block_on(run(
        vec![peer, finished],
        shutdown.clone(),
        std::future::pending(),
      )),
      0
    );
  });
  assert!(peer_stopped);
  assert!(shutdown.is_shutdown());
}
