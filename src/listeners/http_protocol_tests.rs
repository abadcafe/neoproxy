//! Negotiation must preserve every pre-read byte, including upgrade
//! payloads.
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::http_protocol::{Protocol, detect};

#[tokio::test]
async fn test_detect_preserves_http1_prefetched_bytes() {
  let (mut peer, io) = tokio::io::duplex(128);
  let wire = b"POST / HTTP/1.1\r\nHost: local\r\n\r\npayload";
  peer.write_all(wire).await.unwrap();
  peer.shutdown().await.unwrap();
  let (protocol, mut io) = detect(io).await.unwrap();
  assert!(matches!(protocol, Protocol::Http1));
  let mut received = Vec::new();
  io.read_to_end(&mut received).await.unwrap();
  assert_eq!(received, wire);
  io.write_all(b"response").await.unwrap();
  let mut response = [0; 8];
  peer.read_exact(&mut response).await.unwrap();
  assert_eq!(&response, b"response");
}

#[tokio::test]
async fn test_detect_fragmented_http2_preface_is_replayed() {
  let (mut peer, io) = tokio::io::duplex(1);
  let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
  let sending = async {
    peer.write_all(preface).await.unwrap();
    peer.shutdown().await.unwrap();
  };
  let receiving = async {
    let (protocol, mut io) = detect(io).await.unwrap();
    assert!(matches!(protocol, Protocol::Http2));
    let mut received = Vec::new();
    io.read_to_end(&mut received).await.unwrap();
    assert_eq!(received, preface);
  };
  tokio::join!(sending, receiving);
}
