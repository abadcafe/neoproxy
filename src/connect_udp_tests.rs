//! Public CONNECT-UDP framing and request contracts.
use tokio::io::AsyncWriteExt;

use super::connect_udp::{capsule, request};

#[tokio::test]
async fn test_capsule_preserves_empty_and_fragmented_datagrams() {
  let (mut tx, rx) = tokio::io::duplex(32);
  let writer = tokio::spawn(async move {
    for data in [b"".as_slice(), b"hello"] {
      let encoded = capsule::encode(data);
      for byte in encoded {
        tx.write_all(&[byte]).await.unwrap();
      }
    }
  });
  let mut reader = capsule::Reader::new(rx);
  assert_eq!(reader.receive().await.unwrap().unwrap(), b"".as_slice());
  assert_eq!(
    reader.receive().await.unwrap().unwrap(),
    b"hello".as_slice()
  );
  assert!(reader.receive().await.unwrap().is_none());
  writer.await.unwrap();
}

#[test]
fn test_target_ipv6_round_trip_and_invalid_targets() {
  let path = "/.well-known/masque/udp/2001%3Adb8%3A%3A1/53/";
  assert_eq!(request::target(path).unwrap(), "[2001:db8::1]:53");
  for path in [
    "/.well-known/masque/udp/host/0/",
    "/.well-known/masque/udp/a%2Fb/53/",
    "/.well-known/masque/udp/host/65536/",
  ] {
    assert!(request::target(path).is_err());
  }
}

#[tokio::test]
async fn test_capsule_skips_unknown_types_contexts_and_oversized_capsules()
 {
  let (mut tx, rx) = tokio::io::duplex(256);
  let task = tokio::spawn(async move {
    tx.write_all(&[23, 3, 1, 2, 3, 0, 2, 1, 42]).await.unwrap();
    let mut header = vec![0];
    capsule::varint(70000, &mut header);
    tx.write_all(&header).await.unwrap();
    tx.write_all(&vec![0; 70000]).await.unwrap();
    tx.write_all(&capsule::encode(b"after")).await.unwrap();
  });
  let mut reader = capsule::Reader::new(rx);
  assert_eq!(
    reader.receive().await.unwrap().unwrap(),
    b"after".as_slice()
  );
  task.await.unwrap();
}

#[tokio::test]
async fn test_capsule_rejects_truncation_and_missing_context() {
  for wire in [vec![0, 3, 0], vec![0, 0]] {
    let (mut tx, rx) = tokio::io::duplex(32);
    tx.write_all(&wire).await.unwrap();
    drop(tx);
    assert!(capsule::Reader::new(rx).receive().await.is_err());
  }
}

#[test]
fn test_request_requires_valid_upgrade_and_default_template() {
  let mut request = http::Request::builder()
    .method("GET")
    .uri("/.well-known/masque/udp/example.com/53/")
    .header("host", "proxy.test")
    .header("connection", "Upgrade")
    .header("upgrade", "connect-udp")
    .header("capsule-protocol", "?1")
    .body(())
    .unwrap()
    .into_parts()
    .0;
  assert!(request::recognize(&request).unwrap().is_some());
  request.method = http::Method::POST;
  assert!(request::recognize(&request).is_err());
  request.method = http::Method::GET;
  request.headers.remove("capsule-protocol");
  assert!(request::recognize(&request).is_err());
}
