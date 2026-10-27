//! Black-box contracts for TCP listener ownership and shutdown.

use std::cell::Cell;
use std::net::SocketAddr;
use std::rc::Rc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::tcp_listener_base::TcpListenerBase;

fn available_address() -> SocketAddr {
  let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
  socket.local_addr().unwrap()
}

#[tokio::test]
async fn test_start_accepts_multiple_addresses_with_connection_metadata()
 {
  tokio::task::LocalSet::new()
    .run_until(async {
      let addresses = [available_address(), available_address()];
      let base = TcpListenerBase::new();
      let running = tokio::task::spawn_local(
        base
          .start(
            &addresses,
            "test",
            Default::default(),
            |mut connection| async move {
              assert!(connection.stream.nodelay().unwrap());
              assert_eq!(
                connection.stream.local_addr().unwrap(),
                connection.local_addr
              );
              assert_eq!(
                connection.stream.peer_addr().unwrap(),
                connection.peer_addr
              );
              connection.stream.write_all(b"accepted").await.unwrap();
            },
          )
          .unwrap(),
      );
      for address in addresses {
        let mut client =
          tokio::net::TcpStream::connect(address).await.unwrap();
        let mut bytes = [0; 8];
        client.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"accepted");
      }
      base.stop();
      running.await.unwrap().unwrap();
      for address in addresses {
        assert!(std::net::TcpListener::bind(address).is_ok());
      }
    })
    .await;
}

#[tokio::test]
async fn test_start_bind_failure_releases_previously_bound_addresses() {
  let base = TcpListenerBase::new();
  let address = available_address();
  let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
  let result = base.start(
    &[address, occupied.local_addr().unwrap()],
    "test",
    Default::default(),
    |_| async {
      panic!("failed startup must not dispatch connections")
    },
  );
  assert!(result.is_err());
  assert!(std::net::TcpListener::bind(address).is_ok());
}

#[tokio::test]
async fn test_start_rejects_empty_addresses() {
  let base = TcpListenerBase::new();
  assert!(
    base.start(&[], "test", Default::default(), |_| async {}).is_err()
  );
}

#[tokio::test]
async fn test_start_after_stop_does_not_bind() {
  let base = TcpListenerBase::new();
  base.stop();
  let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
  base
    .start(
      &[occupied.local_addr().unwrap()],
      "test",
      Default::default(),
      |_| async {},
    )
    .unwrap()
    .await
    .unwrap();
}

#[tokio::test]
async fn test_stop_notifies_and_drains_connection_handlers() {
  tokio::task::LocalSet::new()
    .run_until(async {
      let base = TcpListenerBase::new();
      let address = available_address();
      let completed = Rc::new(Cell::new(false));
      let stopped = completed.clone();
      let (accepted, ready) = tokio::sync::oneshot::channel();
      let accepted = Rc::new(std::cell::RefCell::new(Some(accepted)));
      let running = tokio::task::spawn_local(
        base
          .start(
            &[address],
            "test",
            Default::default(),
            move |connection| {
              let stopped = stopped.clone();
              let accepted = accepted.borrow_mut().take().unwrap();
              async move {
                accepted.send(()).unwrap();
                connection.shutdown.notified().await;
                stopped.set(true);
              }
            },
          )
          .unwrap(),
      );
      let _client =
        tokio::net::TcpStream::connect(address).await.unwrap();
      ready.await.unwrap();
      base.stop();
      running.await.unwrap().unwrap();
      assert!(completed.get());
    })
    .await;
}

#[tokio::test(start_paused = true)]
async fn test_stop_aborts_unresponsive_connection_after_grace_period() {
  tokio::task::LocalSet::new()
    .run_until(async {
      let base = TcpListenerBase::new();
      let address = available_address();
      let (accepted, ready) = tokio::sync::oneshot::channel();
      let accepted = Rc::new(std::cell::RefCell::new(Some(accepted)));
      let running = tokio::task::spawn_local(
        base
          .start(
            &[address],
            "test",
            Default::default(),
            move |connection| {
              let accepted = accepted.borrow_mut().take().unwrap();
              async move {
                accepted.send(()).unwrap();
                std::future::pending::<()>().await;
                drop(connection);
              }
            },
          )
          .unwrap(),
      );
      let mut client =
        tokio::net::TcpStream::connect(address).await.unwrap();
      ready.await.unwrap();
      base.stop();
      let started = tokio::time::Instant::now();
      running.await.unwrap().unwrap();
      assert_eq!(
        started.elapsed(),
        crate::shutdown::LISTENER_SHUTDOWN_TIMEOUT
      );
      assert_eq!(client.read(&mut [0]).await.unwrap(), 0);
    })
    .await;
}
