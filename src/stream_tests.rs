//! Black-box tests for the stream module.

use std::time::Duration;

use bytes::Bytes;
use http_body_util::Empty;

use crate::http_message::{BytesBufBodyWrapper, RequestBody};
use crate::shutdown::ShutdownHandle;
use crate::stream::{
  OnUpgrade, http_status_to_socks5_error, run_tunnel,
};

#[tokio::test]
async fn test_on_upgrade_extracts_from_extensions() {
  let (_trigger, upgrade) = OnUpgrade::pair();

  let mut req = http::Request::builder()
    .method(http::Method::CONNECT)
    .uri("example.com:443")
    .body(RequestBody::new(BytesBufBodyWrapper::new(
      Empty::<Bytes>::new(),
    )))
    .unwrap();

  req.extensions_mut().insert(upgrade);

  let extracted = OnUpgrade::on(&mut req);
  assert!(
    extracted.is_some(),
    "Should extract OnUpgrade from extensions"
  );

  let second = OnUpgrade::on(&mut req);
  assert!(second.is_none(), "Second extraction should return None");
}

#[tokio::test]
async fn test_on_upgrade_is_available() {
  let (_trigger, upgrade) = OnUpgrade::pair();

  let mut req = http::Request::builder()
    .method(http::Method::CONNECT)
    .uri("example.com:443")
    .body(RequestBody::new(BytesBufBodyWrapper::new(
      Empty::<Bytes>::new(),
    )))
    .unwrap();

  assert!(
    !OnUpgrade::is_available(&req),
    "Should not be available before insert"
  );
  req.extensions_mut().insert(upgrade);
  assert!(
    OnUpgrade::is_available(&req),
    "Should be available after insert"
  );
}

#[tokio::test]
async fn test_on_upgrade_resolves_with_error_on_cancel() {
  let (trigger, upgrade) = OnUpgrade::pair();
  drop(trigger); // Drop trigger to cancel

  let result = upgrade.await;
  assert!(result.is_err(), "Upgrade should resolve with Err on cancel");
}

#[tokio::test]
async fn test_upgrade_trigger_send_success() {
  let listener =
    tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let addr = listener.local_addr().unwrap();
  let client_fut = tokio::net::TcpStream::connect(addr);
  let (client, server_res) =
    tokio::join!(client_fut, listener.accept());
  let client = client.unwrap();
  let (server, _) = server_res.unwrap();

  let (trigger, upgrade) = OnUpgrade::pair();
  trigger.send(Ok(Box::new(client))).unwrap();

  let result = upgrade.await;
  assert!(result.is_ok(), "Upgrade should resolve with Ok");

  drop(server);
}

#[tokio::test]
async fn test_upgrade_trigger_send_error() {
  let (trigger, upgrade) = OnUpgrade::pair();
  trigger.send(Err(anyhow::anyhow!("test error"))).unwrap();

  let result = upgrade.await;
  assert!(result.is_err(), "Upgrade should resolve with Err");
}

// ============== IdleTracker Tests ==============

#[test]
fn test_idle_tracker_new_not_idle() {
  let tracker =
    crate::stream::IdleTracker::new(Duration::from_secs(30));
  assert!(
    !tracker.is_idle(),
    "Newly created tracker should not be idle"
  );
}

#[test]
fn test_idle_tracker_touch_updates_deadline() {
  let tracker =
    crate::stream::IdleTracker::new(Duration::from_secs(30));
  let d1 = tracker.deadline();
  std::thread::sleep(std::time::Duration::from_millis(50));
  tracker.touch();
  let d2 = tracker.deadline();
  assert!(
    d2 > d1,
    "After touch, deadline should advance: {d2:?} <= {d1:?}"
  );
}

#[test]
fn test_idle_tracker_stale_alarm_not_idle() {
  let tracker =
    crate::stream::IdleTracker::new(Duration::from_millis(200));

  assert!(!tracker.is_idle());

  std::thread::sleep(std::time::Duration::from_millis(150));
  tracker.touch();

  assert!(!tracker.is_idle(), "Should not be idle right after touch");

  std::thread::sleep(std::time::Duration::from_millis(50));
  assert!(
    !tracker.is_idle(),
    "50ms after touch should not be idle with 200ms timeout"
  );

  std::thread::sleep(std::time::Duration::from_millis(200));
  assert!(
    tracker.is_idle(),
    "200ms after touch should be idle with 200ms timeout"
  );
}

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

#[test]
fn test_http_status_to_socks5_error_proxy_auth_required() {
  assert!(matches!(
    http_status_to_socks5_error(
      http::StatusCode::PROXY_AUTHENTICATION_REQUIRED
    ),
    fast_socks5::ReplyError::ConnectionNotAllowed
  ));
}
