use std::time::Duration;

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;

use super::forward::{ForwardClient, forward_request};
use crate::context::RequestContext;
use crate::http_message::{BytesBufBodyWrapper, RequestBody};
use crate::plugins::http_upstream::target_parser::parse_forward_target;

#[tokio::test]
async fn test_forward_request_rewrites_host_from_forward_target() {
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

  let resp = forward_request(client, &None, &target, parts, body, &ctx)
    .await
    .unwrap();
  let body = resp.into_body().collect().await.unwrap().to_bytes();

  assert_eq!(body, Bytes::from(addr.to_string()));
  server.await.unwrap();
}

struct CapturingClient {
  request: std::rc::Rc<
    std::cell::RefCell<Option<crate::http_message::Request>>,
  >,
}

#[tokio::test]
async fn test_forward_request_sets_context_id_after_hop_header_cleaning()
 {
  let source = http::Request::builder()
    .uri("http://origin.test/")
    .header("connection", "x-request-id")
    .header("x-request-id", "wrong-header")
    .body(RequestBody::new(BytesBufBodyWrapper::new(
      http_body_util::Empty::<Bytes>::new(),
    )))
    .unwrap();
  let mut headers = http::HeaderMap::new();
  headers.insert("x-request-id", "context-id".parse().unwrap());
  let context = RequestContext::new().with_request_id(
    crate::request_id::RequestId::read_or_generate(&headers).unwrap(),
  );
  let (parts, body) = source.into_parts();
  let target = parse_forward_target(&parts).unwrap();
  let captured = std::rc::Rc::new(std::cell::RefCell::new(None));
  let _ = forward_request(
    CapturingClient { request: captured.clone() },
    &None,
    &target,
    parts,
    body,
    &context,
  )
  .await;
  let request = captured.borrow_mut().take().unwrap();
  assert_eq!(request.headers()["x-request-id"], "context-id");
  assert!(!request.headers().contains_key("connection"));
}

impl ForwardClient for CapturingClient {
  async fn send(
    &self,
    request: crate::http_message::Request,
  ) -> Result<
    crate::http_message::Response,
    crate::plugins::http_upstream::error::UpstreamError,
  > {
    *self.request.borrow_mut() = Some(request);
    let mut response = crate::http_message::build_empty_response(
      http::StatusCode::ACCEPTED,
    );
    *response.version_mut() = http::Version::HTTP_3;
    Ok(response)
  }
}

#[tokio::test]
async fn test_forward_request_normalizes_policy_without_choosing_wire_protocol()
 {
  for version in [
    http::Version::HTTP_10,
    http::Version::HTTP_11,
    http::Version::HTTP_3,
  ] {
    let request = http::Request::builder()
      .version(version)
      .uri("http://example.test/path?q=1")
      .header("host", "wrong.test")
      .header("cookie", "first=a")
      .header("cookie", "second=b")
      .header("connection", "x-private")
      .header("x-private", "remove")
      .header("proxy-authorization", "Basic previous")
      .body(RequestBody::new(BytesBufBodyWrapper::new(
        http_body_util::Full::new(Bytes::from_static(b"payload")),
      )))
      .unwrap();
    let (parts, body) = request.into_parts();
    let target = parse_forward_target(&parts).unwrap();
    let captured = std::rc::Rc::new(std::cell::RefCell::new(None));
    let client = CapturingClient { request: captured.clone() };
    let context = RequestContext::new();
    let response =
      forward_request(client, &None, &target, parts, body, &context)
        .await
        .unwrap();
    assert_eq!(response.status(), http::StatusCode::ACCEPTED);
    assert_eq!(response.headers()["via"], "3 neoproxy");
    assert_eq!(
      context.get(crate::context::fields::upstream::FORWARD_STATUS),
      Some(202)
    );
    let forwarded = captured.borrow_mut().take().unwrap();
    assert_eq!(forwarded.version(), version);
    assert_eq!(forwarded.headers()["host"], "example.test");
    assert_eq!(forwarded.headers()["cookie"], "first=a; second=b");
    assert!(!forwarded.headers().contains_key("connection"));
    assert!(!forwarded.headers().contains_key("x-private"));
    assert!(!forwarded.headers().contains_key("proxy-authorization"));
    assert_eq!(
      forwarded.into_body().collect().await.unwrap().to_bytes(),
      b"payload"[..]
    );
  }
}

async fn verify_unknown_length_requests<C: ForwardClient>(
  build: impl Fn(
    std::net::SocketAddr,
    std::rc::Rc<crate::tracker::StreamTracker>,
  ) -> C,
) {
  tokio::task::LocalSet::new().run_until(async {
    for method in [http::Method::GET, http::Method::HEAD] {
      let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
      let address = listener.local_addr().unwrap();
      let peer = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        hyper::server::conn::http1::Builder::new().serve_connection(
          hyper_util::rt::TokioIo::new(socket),
          hyper::service::service_fn(|request: hyper::Request<hyper::body::Incoming>| async move {
            let body = request.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(body.as_ref(), b"streamed-payload");
            Ok::<_, std::convert::Infallible>(http::Response::new(http_body_util::Empty::<Bytes>::new()))
          }),
        ).await.unwrap();
      });
      let tracker = std::rc::Rc::new(crate::tracker::StreamTracker::new());
      let client = build(address, tracker.clone());
      let body = http_body_util::StreamBody::new(futures::stream::iter([
        Ok::<_, std::io::Error>(http_body::Frame::data(Bytes::from_static(b"streamed-"))),
        Ok(http_body::Frame::data(Bytes::from_static(b"payload"))),
      ]));
      let request = http::Request::builder()
        .method(method)
        .uri(format!("http://{address}/"))
        .header("connection", "close")
        .body(RequestBody::new(BytesBufBodyWrapper::new(body)))
        .unwrap();
      let response = tokio::time::timeout(Duration::from_secs(2), client.send(request)).await.unwrap().unwrap();
      response.into_body().collect().await.unwrap();
      peer.await.unwrap();
      drop(client);
      tracker.wait_shutdown().await;
    }
  }).await;
}

#[tokio::test]
async fn test_send_direct_preserves_unknown_length_get_and_head_bodies()
{
  verify_unknown_length_requests(|_, _| {
    Client::builder(hyper_util::rt::TokioExecutor::new())
      .build(HttpConnector::new())
  })
  .await;
}

#[tokio::test]
async fn test_send_proxy_preserves_unknown_length_get_and_head_bodies()
{
  verify_unknown_length_requests(|address, tracker| {
    super::http_pool::ProxyPool::new(
      super::http::connector::ProxyConnector::new(
        address,
        Duration::from_secs(1),
      ),
      1,
      Duration::from_secs(1),
      tracker,
    )
  })
  .await;
}

async fn verify_trailer_forwarding<C: ForwardClient>(
  build: impl Fn(
    std::net::SocketAddr,
    std::rc::Rc<crate::tracker::StreamTracker>,
  ) -> C,
) {
  tokio::task::LocalSet::new().run_until(async {
    for known_length in [false, true] {
      let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
      let address = listener.local_addr().unwrap();
      let peer = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        hyper::server::conn::http1::Builder::new().serve_connection(
          hyper_util::rt::TokioIo::new(socket),
          hyper::service::service_fn(|request: hyper::Request<hyper::body::Incoming>| async move {
            assert_eq!(request.headers()["trailer"], "x-checksum");
            let body = request.into_body().collect().await.unwrap();
            let trailers = body.trailers().expect("forwarded trailer section");
            assert_eq!(trailers["x-checksum"], "complete");
            assert_eq!(trailers.len(), 1);
            assert_eq!(body.to_bytes().as_ref(), b"payload");
            Ok::<_, std::convert::Infallible>(http::Response::builder().header("connection", "close").body(http_body_util::Empty::<Bytes>::new()).unwrap())
          }),
        ).await.unwrap();
      });
      let tracker = std::rc::Rc::new(crate::tracker::StreamTracker::new());
      let client = build(address, tracker.clone());
      let mut trailers = http::HeaderMap::new();
      trailers.insert("x-checksum", "complete".parse().unwrap());
      trailers.insert("x-private", "secret".parse().unwrap());
      trailers.insert("content-length", "123".parse().unwrap());
      let body = if known_length {
        RequestBody::new(BytesBufBodyWrapper::new(
          http_body_util::Full::new(Bytes::from_static(b"payload"))
            .with_trailers(async move { Some(Ok(trailers)) }),
        ))
      } else {
        RequestBody::new(BytesBufBodyWrapper::new(
          http_body_util::StreamBody::new(futures::stream::iter([
            Ok::<_, std::io::Error>(http_body::Frame::data(Bytes::from_static(b"payload"))),
            Ok(http_body::Frame::trailers(trailers)),
          ])),
        ))
      };
      let mut request = http::Request::builder().method("POST")
        .uri(format!("http://{address}/"))
        .header("connection", "x-private")
        .header("trailer", "x-checksum, x-private, content-length")
        .body(body).unwrap();
      if known_length { request.headers_mut().insert("content-length", "7".parse().unwrap()); }
      let (parts, body) = request.into_parts();
      let target = parse_forward_target(&parts).unwrap();
      let response = tokio::time::timeout(Duration::from_secs(2), forward_request(client, &None, &target, parts, body, &RequestContext::new())).await.unwrap().unwrap();
      assert_eq!(response.status(), http::StatusCode::OK);
      response.into_body().collect().await.unwrap();
      peer.await.unwrap();
      tracker.wait_shutdown().await;
    }
  }).await;
}

#[tokio::test]
async fn test_forward_request_direct_preserves_filtered_trailers() {
  verify_trailer_forwarding(|_, _| {
    Client::builder(hyper_util::rt::TokioExecutor::new())
      .build(HttpConnector::new())
  })
  .await;
}

#[tokio::test]
async fn test_forward_request_proxy_preserves_filtered_trailers() {
  verify_trailer_forwarding(|address, tracker| {
    super::http_pool::ProxyPool::new(
      super::http::connector::ProxyConnector::new(
        address,
        Duration::from_secs(1),
      ),
      1,
      Duration::from_secs(1),
      tracker,
    )
  })
  .await;
}
