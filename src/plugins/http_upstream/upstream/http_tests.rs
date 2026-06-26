use std::rc::Rc;
use std::task::Context;
use std::time::Duration;

use bytes::Bytes;
use futures::task::noop_waker;
use http_body_util::BodyExt;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use tower::Service;

use super::ClientProtocol;
use super::http::{HttpClient, ProxyConnector, chain_forward_http};
use crate::context::RequestContext;
use crate::http_message::{BytesBufBodyWrapper, RequestBody};
use crate::plugins::http_upstream::target_parser::parse_forward_target;
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

#[tokio::test]
async fn test_chain_forward_http_rewrites_host_from_forward_target() {
  let listener =
    tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let addr = listener.local_addr().unwrap();

  let server = tokio::spawn(async move {
    let (stream, _) = listener.accept().await.unwrap();
    let io = hyper_util::rt::TokioIo::new(stream);
    hyper::server::conn::http1::Builder::new()
      .serve_connection(
        io,
        hyper::service::service_fn(
          |req: hyper::Request<_>| async move {
            let host = req
              .headers()
              .get(http::header::HOST)
              .and_then(|v| v.to_str().ok())
              .unwrap_or("")
              .to_string();
            Ok::<_, std::convert::Infallible>(
              http::Response::builder()
                .status(http::StatusCode::OK)
                .body(http_body_util::Full::new(Bytes::from(host)))
                .unwrap(),
            )
          },
        ),
      )
      .await
      .unwrap();
  });

  let mut connector = HttpConnector::new();
  connector.set_connect_timeout(Some(Duration::from_secs(1)));
  let client = Client::builder(hyper_util::rt::TokioExecutor::new())
    .build(connector);
  let req = http::Request::builder()
    .method(http::Method::GET)
    .uri(format!("http://{addr}/path"))
    .header(http::header::HOST, "wrong.example")
    .body(RequestBody::new(BytesBufBodyWrapper::new(
      http_body_util::Empty::new(),
    )))
    .unwrap();
  let (parts, body) = req.into_parts();
  let target = parse_forward_target(&parts).unwrap();
  let ctx = RequestContext::new();

  let resp =
    chain_forward_http(client, None, &target, parts, body, &ctx).await;
  let body = resp.into_body().collect().await.unwrap().to_bytes();

  assert_eq!(body, Bytes::from(addr.to_string()));
  server.await.unwrap();
}
