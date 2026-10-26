use super::response::forward_response;
use crate::context::build_request_context;
use crate::http_message::build_empty_response;

#[test]
fn test_forward_response_preserves_chain_and_consumes_hop_fields() {
  let mut original = build_empty_response(http::StatusCode::ACCEPTED);
  original
    .headers_mut()
    .append("proxy-status", "first".parse().unwrap());
  original
    .headers_mut()
    .append("proxy-status", "second".parse().unwrap());
  original.headers_mut().insert("connection", "x-hop".parse().unwrap());
  original.headers_mut().insert("x-hop", "private".parse().unwrap());
  original
    .headers_mut()
    .insert("proxy-authenticate", "Basic".parse().unwrap());
  original
    .headers_mut()
    .append("alt-svc", "h3=\":443\"; ma=60".parse().unwrap());
  original
    .headers_mut()
    .append("alt-svc", "h2=\":8443\"".parse().unwrap());
  let ctx = build_request_context(
    &"127.0.0.1:1234".parse().unwrap(),
    &"127.0.0.1:8080".parse().unwrap(),
    "proxy",
  );
  let (parts, body) = original.into_parts();
  let response = forward_response(parts, body, &ctx);
  assert_eq!(response.status(), http::StatusCode::ACCEPTED);
  assert_eq!(
    response.headers()["proxy-status"],
    "first, second, \"127.0.0.1:8080\"; received-status=202"
  );
  for name in ["connection", "x-hop", "proxy-authenticate", "alt-svc"] {
    assert!(!response.headers().contains_key(name));
  }
}

#[tokio::test]
async fn test_forward_response_selects_chunked_framing_for_known_length_trailers()
 {
  use bytes::Bytes;
  use http_body_util::BodyExt;

  use crate::http_message::{BytesBufBodyWrapper, ResponseBody};
  let mut trailers = http::HeaderMap::new();
  trailers.insert("x-checksum", "complete".parse().unwrap());
  trailers.insert("x-private", "secret".parse().unwrap());
  let body = http_body_util::Full::new(Bytes::from_static(b"payload"))
    .with_trailers(async move { Some(Ok(trailers)) });
  let response = http::Response::builder()
    .header("content-length", "7")
    .header("trailer", "x-checksum, x-private")
    .header("connection", "x-private")
    .body(ResponseBody::new(BytesBufBodyWrapper::new(body)))
    .unwrap();
  let (parts, body) = response.into_parts();
  let response = forward_response(
    parts,
    body,
    &crate::context::RequestContext::new(),
  );
  assert_eq!(response.headers()["transfer-encoding"], "chunked");
  assert!(!response.headers().contains_key("content-length"));
  assert_eq!(response.headers()["trailer"], "x-checksum");
  let collected = response.into_body().collect().await.unwrap();
  assert_eq!(collected.trailers().unwrap()["x-checksum"], "complete");
  assert_eq!(collected.trailers().unwrap().len(), 1);
  assert_eq!(collected.to_bytes(), Bytes::from_static(b"payload"));
}

#[tokio::test]
async fn test_forward_response_transmits_known_length_trailers_on_http1_wire()
 {
  use bytes::Bytes;
  use http_body_util::{BodyExt, Empty, Full};
  use hyper_util::rt::TokioIo;

  use crate::http_message::{BytesBufBodyWrapper, ResponseBody};

  let listener =
    tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let address = listener.local_addr().unwrap();
  let server = tokio::spawn(async move {
    let (stream, _) = listener.accept().await.unwrap();
    hyper::server::conn::http1::Builder::new()
      .serve_connection(
        TokioIo::new(stream),
        hyper::service::service_fn(|_| async {
          let mut trailers = http::HeaderMap::new();
          trailers.insert("x-checksum", "complete".parse().unwrap());
          let body = Full::new(Bytes::from_static(b"payload"))
            .with_trailers(async move { Some(Ok(trailers)) });
          let response = http::Response::builder()
            .header("content-length", "7")
            .header("trailer", "x-checksum")
            .body(ResponseBody::new(BytesBufBodyWrapper::new(body)))
            .unwrap();
          let (parts, body) = response.into_parts();
          Ok::<_, std::convert::Infallible>(forward_response(
            parts,
            body,
            &crate::context::RequestContext::new(),
          ))
        }),
      )
      .await
      .unwrap();
  });
  let stream = tokio::net::TcpStream::connect(address).await.unwrap();
  let (mut client, connection) =
    hyper::client::conn::http1::handshake(TokioIo::new(stream))
      .await
      .unwrap();
  let connection = tokio::spawn(connection);
  let request = http::Request::builder()
    .uri("/")
    .header("host", address.to_string())
    .header("te", "trailers")
    .header("connection", "close")
    .body(Empty::<Bytes>::new())
    .unwrap();
  let response = tokio::time::timeout(
    std::time::Duration::from_secs(2),
    client.send_request(request),
  )
  .await
  .unwrap()
  .unwrap();
  assert_eq!(response.headers()["transfer-encoding"], "chunked");
  assert!(!response.headers().contains_key("content-length"));
  let content = response.into_body().collect().await.unwrap();
  assert_eq!(content.trailers().unwrap()["x-checksum"], "complete");
  assert_eq!(content.to_bytes(), Bytes::from_static(b"payload"));
  connection.await.unwrap().unwrap();
  server.await.unwrap();
}
