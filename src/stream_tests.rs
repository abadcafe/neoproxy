//! Black-box tests for the stream module.

use std::time::Duration;

use crate::shutdown::ShutdownHandle;
use crate::stream::run_tunnel;

// ============== run_tunnel Tests ==============

#[tokio::test]
async fn test_run_tunnel_idle_timeout_on_no_data() {
  let listener =
    tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let addr = listener.local_addr().unwrap();
  let client = tokio::net::TcpStream::connect(addr).await.unwrap();
  let (server, _) = listener.accept().await.unwrap();

  let shutdown = ShutdownHandle::new();
  let idle_timeout = Duration::from_millis(200);

  let start = std::time::Instant::now();
  run_tunnel(client, server, shutdown, idle_timeout, "test").await;
  let elapsed = start.elapsed();

  assert!(
    elapsed >= Duration::from_millis(150),
    "Should wait for idle timeout, only waited {elapsed:?}"
  );
  assert!(
    elapsed < Duration::from_secs(2),
    "Should not wait much longer than idle timeout, waited {elapsed:?}"
  );
}

#[tokio::test]
async fn test_run_tunnel_no_timeout_with_active_data() {
  let listener =
    tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let addr = listener.local_addr().unwrap();

  let server_handle = tokio::spawn(async move {
    let (mut server, _) = listener.accept().await.unwrap();
    let data = vec![0xABu8; 4096];
    for _ in 0..20 {
      tokio::time::sleep(Duration::from_millis(100)).await;
      if tokio::io::AsyncWriteExt::write_all(&mut server, &data)
        .await
        .is_err()
      {
        break;
      }
    }
    let _ = tokio::io::AsyncWriteExt::shutdown(&mut server).await;
  });

  let client = tokio::net::TcpStream::connect(addr).await.unwrap();

  let (target, _drain) = tokio::io::duplex(65536);

  let drainer = tokio::spawn(async move {
    let mut drain = _drain;
    let mut buf = [0u8; 4096];
    loop {
      match tokio::io::AsyncReadExt::read(&mut drain, &mut buf).await {
        Ok(0) => break,
        Ok(_) => continue,
        Err(_) => break,
      }
    }
  });

  let shutdown = ShutdownHandle::new();
  let idle_timeout = Duration::from_millis(200);

  let start = std::time::Instant::now();
  run_tunnel(client, target, shutdown, idle_timeout, "test").await;
  let elapsed = start.elapsed();

  assert!(
    elapsed >= Duration::from_millis(500),
    "Tunnel should survive past idle_timeout while data flows, only \
     lasted {elapsed:?}"
  );

  let _ = server_handle.await;
  let _ = drainer.await;
}

#[tokio::test]
async fn test_run_tunnel_completes_on_eof() {
  let listener =
    tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let addr = listener.local_addr().unwrap();
  let client = tokio::net::TcpStream::connect(addr).await.unwrap();
  let (server, _) = listener.accept().await.unwrap();

  drop(server);

  let shutdown = ShutdownHandle::new();
  let idle_timeout = Duration::from_secs(60);

  let (target, _drain) = tokio::io::duplex(64);
  drop(_drain);

  let start = std::time::Instant::now();
  run_tunnel(client, target, shutdown, idle_timeout, "test").await;
  let elapsed = start.elapsed();

  assert!(
    elapsed < Duration::from_secs(5),
    "Tunnel should complete on EOF, not wait for idle timeout. \
     Elapsed: {elapsed:?}"
  );
}

#[tokio::test]
async fn test_run_tunnel_shutdown_notification() {
  let listener =
    tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let addr = listener.local_addr().unwrap();
  let client = tokio::net::TcpStream::connect(addr).await.unwrap();
  let (server, _) = listener.accept().await.unwrap();

  let shutdown = ShutdownHandle::new();
  let shutdown_clone = shutdown.clone();
  let idle_timeout = Duration::from_secs(60);

  let tunnel_task = tokio::spawn(async move {
    run_tunnel(client, server, shutdown_clone, idle_timeout, "test")
      .await;
  });

  tokio::time::sleep(Duration::from_millis(50)).await;
  shutdown.shutdown();

  let start = std::time::Instant::now();
  let result = tunnel_task.await;
  let elapsed = start.elapsed();

  assert!(result.is_ok(), "Tunnel task should complete");
  assert!(
    elapsed < Duration::from_secs(2),
    "Tunnel should exit quickly on shutdown, took {elapsed:?}"
  );
}
