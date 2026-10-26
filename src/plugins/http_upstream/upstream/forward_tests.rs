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

  let resp =
    forward_request(client, &None, &target, parts, body, &ctx).await;
  let body = resp.into_body().collect().await.unwrap().to_bytes();

  assert_eq!(body, Bytes::from(addr.to_string()));
  server.await.unwrap();
}

struct CapturingClient {
  request: std::rc::Rc<
    std::cell::RefCell<Option<crate::http_message::Request>>,
  >,
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
        .await;
    assert_eq!(response.status(), http::StatusCode::ACCEPTED);
    assert_eq!(response.headers()["via"], "3 neoproxy");
    assert_eq!(
      context.get("upstream.forward_status").as_deref(),
      Some("202")
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
