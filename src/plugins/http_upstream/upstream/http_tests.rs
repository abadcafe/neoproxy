//! Black-box tunnel handoff contract for the HTTP proxy adapter.

use std::rc::Rc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::http::HttpProxyClient;
use super::http::connector::ProxyConnector;
use super::http_pool::ProxyPool;
use super::protocol::ClientProtocol;
use crate::plugins::http_upstream::target_parser::parse_connect_target;
use crate::tracker::StreamTracker;

#[tokio::test]
async fn test_connect_for_tunnel_preserves_peer_and_bytes_after_response_headers()
 {
  tokio::task::LocalSet::new()
    .run_until(async {
      let listener =
        tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
      let address = listener.local_addr().unwrap();
      let peer = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut headers = Vec::new();
        while !headers.ends_with(b"\r\n\r\n") {
          headers.push(socket.read_u8().await.unwrap());
        }
        assert!(
          headers.starts_with(b"CONNECT origin.test:443 HTTP/1.1\r\n")
        );
        socket
          .write_all(b"HTTP/1.1 200 OK\r\n\r\nhello")
          .await
          .unwrap();
        let mut request = [0; 4];
        socket.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"ping");
        socket.write_all(b"pong").await.unwrap();
      });
      let tracker = Rc::new(StreamTracker::new());
      let connector = ProxyConnector::new(
        address.to_string(),
        Duration::from_secs(1),
        Duration::from_secs(1),
      );
      let client = HttpProxyClient::new(
        ProxyPool::new(
          connector,
          1,
          Duration::from_secs(1),
          tracker.clone(),
        ),
        Duration::from_secs(1),
        None,
      );
      let request = http::Request::builder()
        .method("CONNECT")
        .uri("origin.test:443")
        .body(())
        .unwrap();
      let (parts, ()) = request.into_parts();
      let target = parse_connect_target(&parts).unwrap();
      let mut connected = client
        .connect_for_tunnel(&target, &parts, &None, &tracker)
        .await
        .unwrap();
      assert_eq!(connected.upstream_addr, Some(address));
      let mut greeting = [0; 5];
      connected.transport.read_exact(&mut greeting).await.unwrap();
      assert_eq!(&greeting, b"hello");
      connected.transport.write_all(b"ping").await.unwrap();
      let mut response = Vec::new();
      connected.transport.read_to_end(&mut response).await.unwrap();
      assert_eq!(&response, b"pong");
      peer.await.unwrap();
      drop(connected);
      tracker.wait_shutdown().await;
    })
    .await;
}
