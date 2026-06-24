use std::rc::Rc;
use std::task::Context;
use std::time::Duration;

use bytes::Bytes;
use futures::task::noop_waker;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower::Service;

use super::ClientProtocol;
use super::http::{HttpClient, ProxyConnector, Rewind};
use crate::tracker::StreamTracker;

#[test]
fn test_proxy_connector_poll_ready_returns_ready() {
  let mut connector = ProxyConnector::new(
    "127.0.0.1:1".to_string(),
    Duration::from_millis(10),
    Duration::from_millis(10),
  );
  let waker = noop_waker();
  let mut cx = Context::from_waker(&waker);

  assert!(matches!(
    connector.poll_ready(&mut cx),
    std::task::Poll::Ready(Ok(()))
  ));
}

#[tokio::test]
async fn test_proxy_connector_call_connects_to_configured_proxy() {
  let listener =
    tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let addr = listener.local_addr().unwrap();
  let mut connector = ProxyConnector::new(
    addr.to_string(),
    Duration::from_secs(1),
    Duration::from_secs(1),
  );

  let accept = async {
    let (_stream, peer) = listener.accept().await.unwrap();
    peer
  };
  let uri = "http://ignored.example/".parse().unwrap();
  let (connected, peer) = tokio::join!(connector.call(uri), accept);

  assert!(connected.is_ok());
  assert_eq!(
    peer.ip(),
    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
  );
}

#[tokio::test]
async fn test_rewind_reads_prefix_before_inner_stream() {
  let (mut writer, reader) = tokio::io::duplex(64);
  writer.write_all(b"tail").await.unwrap();
  writer.shutdown().await.unwrap();
  let mut rewind =
    Rewind::new(reader, Some(Bytes::from_static(b"head")));

  let mut first = [0u8; 4];
  rewind.read_exact(&mut first).await.unwrap();
  let mut second = Vec::new();
  rewind.read_to_end(&mut second).await.unwrap();

  assert_eq!(&first, b"head");
  assert_eq!(second, b"tail");
}

#[tokio::test]
async fn test_http_client_direct_tunnel_connects_to_target() {
  let listener =
    tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let addr = listener.local_addr().unwrap();
  let connector = HttpConnector::new();
  let client = Client::builder(hyper_util::rt::TokioExecutor::new())
    .build(connector);
  let http_client = HttpClient {
    client,
    proxy_addr: None,
    connect_timeout: Duration::from_secs(1),
    tunnel_idle_timeout: Duration::from_secs(30),
    dns_resolve_timeout: Duration::from_secs(1),
    user: None,
  };
  let tracker = Rc::new(StreamTracker::new());

  let accept = async {
    let (_stream, peer) = listener.accept().await.unwrap();
    peer
  };
  let target = addr.to_string();
  let (result, peer) = tokio::join!(
    http_client.connect_for_tunnel(&target, &None, &tracker),
    accept
  );
  let result = result.unwrap();

  assert_eq!(result.upstream_addr.map(|a| a.ip()), Some(peer.ip()));
  assert!(result.upstream_proxy_status.is_none());
  assert_eq!(result.tunnel_idle_timeout, Duration::from_secs(30));
}
