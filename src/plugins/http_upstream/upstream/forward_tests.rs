use std::time::Duration;

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;

use super::forward::chain_forward_http;
use crate::context::RequestContext;
use crate::http_message::{BytesBufBodyWrapper, RequestBody};
use crate::plugins::http_upstream::target_parser::parse_forward_target;

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
