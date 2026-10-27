use std::task::Context;
use std::time::Duration;

use futures::task::noop_waker;
use tower::Service;

use super::connector::ProxyConnector;

#[test]
fn test_proxy_connector_poll_ready_returns_ready() {
  let mut connector = ProxyConnector::new(
    "127.0.0.1:1".parse().unwrap(),
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
  let mut connector = ProxyConnector::new(addr, Duration::from_secs(1));

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
