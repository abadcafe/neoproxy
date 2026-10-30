use crate::process::Workers;
use crate::shutdown::ShutdownHandle;

#[tokio::test]
async fn test_shutdown_signal_subscribes_before_future_is_polled() {
  // Install a guard first so this regression cannot terminate the test
  // process even when the implementation subscribes too late.
  let mut guard = tokio::signal::unix::signal(
    tokio::signal::unix::SignalKind::terminate(),
  )
  .unwrap();
  let pending =
    crate::process::shutdown_signal(&tokio::runtime::Handle::current())
      .unwrap();
  assert!(
    tokio::process::Command::new("kill")
      .arg("-TERM")
      .arg(std::process::id().to_string())
      .status()
      .await
      .unwrap()
      .success()
  );
  tokio::time::timeout(std::time::Duration::from_secs(1), guard.recv())
    .await
    .unwrap()
    .unwrap();
  tokio::time::timeout(std::time::Duration::from_secs(1), pending)
    .await
    .expect(
      "shutdown subscription missed the signal before its first poll",
    );
}

fn runtime() -> tokio::runtime::Runtime {
  tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .unwrap()
}

#[test]
fn test_run_completed_worker_does_not_wait_for_a_polling_timer() {
  std::thread::scope(|scope| {
    let mut workers = Workers::new(ShutdownHandle::new());
    workers.spawn(scope, "finished", || Ok(())).unwrap();
    runtime().block_on(async {
      tokio::time::pause();
      let started = tokio::time::Instant::now();
      assert_eq!(workers.run(std::future::pending()).await, 0);
      assert_eq!(tokio::time::Instant::now(), started);
    });
  });
}

#[test]
fn test_run_worker_completion_wakes_pending_supervisor_without_a_timer()
{
  std::thread::scope(|scope| {
    let mut workers = Workers::new(ShutdownHandle::new());
    let (release, wait) = std::sync::mpsc::channel();
    workers
      .spawn(scope, "waiting", move || {
        wait.recv().unwrap();
        Ok(())
      })
      .unwrap();
    runtime().block_on(async {
      tokio::time::pause();
      let started = tokio::time::Instant::now();
      let release = async {
        tokio::task::yield_now().await;
        release.send(()).unwrap();
      };
      let (exit, ()) =
        tokio::join!(workers.run(std::future::pending()), release);
      assert_eq!(exit, 0);
      assert_eq!(tokio::time::Instant::now(), started);
    });
  });
}

#[tokio::test]
async fn test_run_signal_shutdown_without_workers() {
  let shutdown = ShutdownHandle::new();
  assert_eq!(Workers::new(shutdown.clone()).run(async {}).await, 0);
  assert!(shutdown.is_shutdown());
}

#[test]
fn test_run_worker_failure_stops_other_workers() {
  let shutdown = ShutdownHandle::new();
  let peer_shutdown = shutdown.clone();
  std::thread::scope(|scope| {
    let mut workers = Workers::new(shutdown.clone());
    workers
      .spawn(scope, "peer", move || {
        while !peer_shutdown.is_shutdown() {
          std::thread::yield_now();
        }
        Ok(())
      })
      .unwrap();
    workers
      .spawn(scope, "failed", || {
        Err(anyhow::anyhow!("listener bind failed"))
      })
      .unwrap();
    assert_eq!(
      runtime().block_on(workers.run(std::future::pending())),
      2
    );
  });
  assert!(shutdown.is_shutdown());
}

#[test]
fn test_run_worker_panic_returns_failure_exit_code() {
  std::thread::scope(|scope| {
    let mut workers = Workers::new(ShutdownHandle::new());
    // Deliberately panic a worker. Joining must record failure before
    // leaving the scope, without unwinding the parent a second time.
    workers
      .spawn(scope, "panicked", || panic!("programming error"))
      .unwrap();
    assert_eq!(
      runtime().block_on(workers.run(std::future::pending())),
      1
    );
  });
}

#[test]
fn test_run_panic_takes_precedence_over_other_worker_errors() {
  std::thread::scope(|scope| {
    let mut workers = Workers::new(ShutdownHandle::new());
    workers
      .spawn(scope, "failed", || {
        Err(anyhow::anyhow!("listener bind failed"))
      })
      .unwrap();
    workers
      .spawn(scope, "panicked", || panic!("programming error"))
      .unwrap();
    workers.spawn(scope, "finished", || Ok(())).unwrap();
    assert_eq!(
      runtime().block_on(workers.run(std::future::pending())),
      1
    );
  });
}

#[test]
fn test_run_tracked_task_panic_stops_other_workers() {
  let shutdown = ShutdownHandle::new();
  let peer_shutdown = shutdown.clone();
  std::thread::scope(|scope| {
    let mut workers = Workers::new(shutdown.clone());
    workers
      .spawn(scope, "peer", move || {
        while !peer_shutdown.is_shutdown() {
          std::thread::yield_now();
        }
        Ok(())
      })
      .unwrap();
    workers
      .spawn(scope, "failed", || {
        runtime().block_on(tokio::task::LocalSet::new().run_until(
          async {
            let reservation =
              std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = reservation.local_addr().unwrap();
            drop(reservation);
            let listener =
              crate::listeners::tcp_listener_base::TcpListenerBase::new(
              );
            let running = listener
              .start(
                &[address],
                "panic",
                Default::default(),
                |_| async {
                  // No new connection or shutdown may be needed to
                  // observe a handler failure and
                  // stop the other workers.
                  panic!("connection task programming error")
                },
              )
              .unwrap();
            let _client =
              tokio::net::TcpStream::connect(address).await.unwrap();
            running.await.unwrap();
          },
        ));
        Ok(())
      })
      .unwrap();
    assert_eq!(
      runtime().block_on(workers.run(std::future::pending())),
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
    let mut workers = Workers::new(shutdown.clone());
    workers
      .spawn(scope, "peer", || {
        while !shutdown.is_shutdown() {
          std::thread::yield_now();
        }
        peer_stopped = true;
        Ok(())
      })
      .unwrap();
    workers
      .spawn(scope, "finished", || {
        assert_eq!(worker_name, "borrowed worker");
        Ok(())
      })
      .unwrap();
    assert_eq!(
      runtime().block_on(workers.run(std::future::pending())),
      0
    );
  });
  assert!(peer_stopped);
  assert!(shutdown.is_shutdown());
}

#[test]
fn test_drop_stops_and_joins_unfinished_workers() {
  let shutdown = ShutdownHandle::new();
  let mut peer_stopped = false;
  std::thread::scope(|scope| {
    let mut workers = Workers::new(shutdown.clone());
    workers
      .spawn(scope, "peer", || {
        while !shutdown.is_shutdown() {
          std::thread::yield_now();
        }
        peer_stopped = true;
        Ok(())
      })
      .unwrap();
    drop(workers);
  });
  assert!(peer_stopped);
  assert!(shutdown.is_shutdown());
}
