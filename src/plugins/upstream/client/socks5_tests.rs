//! Public adapter contract: selected endpoint, observations and tunnel
//! handoff.
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::http::connector::ProxyConnector;
use super::protocol::ClientProtocol;
use super::socks5::Socks5Client;
use crate::context::{RequestContext, fields};
use crate::plugins::upstream::target_parser::parse_connect_target;
use crate::task_tracker::TaskTracker;

#[tokio::test]
async fn test_connect_for_tunnel_records_peer_and_preserves_bytes_and_eof()
 {
  let listener =
    tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let address = listener.local_addr().unwrap();
  let server = tokio::spawn(async move {
    let (mut stream, _) = listener.accept().await.unwrap();
    let mut greeting = [0; 3];
    stream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 1, 0]);
    stream.write_all(&[5, 0]).await.unwrap();
    let mut request = [0; 10];
    stream.read_exact(&mut request).await.unwrap();
    assert_eq!(request, [5, 1, 0, 1, 127, 0, 0, 1, 0, 80]);
    stream
      .write_all(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00hello")
      .await
      .unwrap();
    let mut payload = Vec::new();
    stream.read_to_end(&mut payload).await.unwrap();
    assert_eq!(payload, b"ping");
    stream.write_all(b"pong").await.unwrap();
  });
  let ctx = RequestContext::new();
  let request = http::Request::builder()
    .method("CONNECT")
    .uri("127.0.0.1:80")
    .extension(ctx.clone())
    .body(())
    .unwrap();
  let parts = request.into_parts().0;
  let target = parse_connect_target(&parts).unwrap();
  let client = Socks5Client::new(
    ProxyConnector::new(address, Duration::from_secs(1)),
    Duration::from_secs(17),
    None,
  );
  let tracker = std::rc::Rc::new(TaskTracker::new());
  let mut result = client
    .connect_for_tunnel(&target, &parts, &None, &tracker)
    .await
    .unwrap();
  assert_eq!(result.upstream_addr, Some(address));
  assert!(result.upstream_response.is_none());
  assert_eq!(result.tunnel_idle_timeout, Duration::from_secs(17));
  assert!(
    ctx.get(fields::connection::REUSED).is_some_and(|reused| !reused)
  );
  let mut greeting = [0; 5];
  result.transport.read_exact(&mut greeting).await.unwrap();
  assert_eq!(&greeting, b"hello");
  result.transport.write_all(b"ping").await.unwrap();
  result.transport.shutdown().await.unwrap();
  let mut response = Vec::new();
  result.transport.read_to_end(&mut response).await.unwrap();
  assert_eq!(response, b"pong");
  server.await.unwrap();
}
