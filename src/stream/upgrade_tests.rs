use bytes::Bytes;
use http_body_util::Empty;

use super::upgrade::OnUpgrade;
use crate::http_message::{BytesBufBodyWrapper, RequestBody};

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
async fn test_on_upgrade_on_absent_then_inserted() {
  let (_trigger, upgrade) = OnUpgrade::pair();

  let mut req = http::Request::builder()
    .method(http::Method::CONNECT)
    .uri("example.com:443")
    .body(RequestBody::new(BytesBufBodyWrapper::new(
      Empty::<Bytes>::new(),
    )))
    .unwrap();

  assert!(OnUpgrade::on(&mut req).is_none());

  req.extensions_mut().insert(upgrade);
  assert!(OnUpgrade::on(&mut req).is_some());
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

#[tokio::test]
async fn test_on_upgrade_pending_clone_drop_keeps_receiver_available() {
  let (trigger, upgrade) = OnUpgrade::pair();
  let mut clone = upgrade.clone();
  let mut context = Context::from_waker(Waker::noop());
  assert!(Pin::new(&mut clone).poll(&mut context).is_pending());
  drop(clone);

  trigger.send(Ok(Box::new(tokio::io::duplex(64).0))).unwrap();
  assert!(upgrade.await.is_ok());
}

#[tokio::test]
#[should_panic]
async fn test_on_upgrade_duplicate_consumption_panics() {
  let (trigger, upgrade) = OnUpgrade::pair();
  let clone = upgrade.clone();
  trigger.send(Ok(Box::new(tokio::io::duplex(64).0))).unwrap();
  let _stream = upgrade.await.unwrap();

  // Clones share one receiver, as in Hyper. Consuming it twice is a
  // programming error; it must not be disguised as a business error.
  let _ = clone.await;
}
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Waker};
