use std::rc::Rc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Empty;

use super::http3::{Http3Client, SessionPool};
use super::protocol::{ClientProtocol, QuicConfig};
use crate::context::RequestContext;
use crate::http_message::{BytesBufBodyWrapper, RequestBody};
use crate::plugins::upstream::error::UpstreamError;
use crate::plugins::upstream::target_parser::{
  parse_connect_target, parse_forward_target,
};
use crate::tracker::StreamTracker;

fn quic_config() -> QuicConfig {
  QuicConfig {
    datagram: Default::default(),
    max_idle_timeout: None,
    keep_alive_interval: Duration::from_secs(3),
    max_concurrent_bidi_streams: None,
    initial_mtu: None,
    send_window: None,
    stream_receive_window: None,
    receive_window: None,
  }
}

fn http3_client() -> Http3Client {
  Http3Client {
    session: SessionPool::new(
      "127.0.0.1:443".parse().unwrap(),
      None,
      quic_config(),
      Duration::from_millis(100),
      Default::default(),
    ),
    tunnel_idle_timeout: Duration::from_secs(30),
    user: None,
  }
}

#[tokio::test]
async fn test_http3_client_forward_without_tls_config_is_rejected() {
  let client = http3_client();
  let tracker = Rc::new(StreamTracker::new());
  let ctx = RequestContext::new();
  let req = http::Request::builder()
    .method(http::Method::GET)
    .uri("http://example.com/")
    .body(RequestBody::new(BytesBufBodyWrapper::new(
      Empty::<Bytes>::new(),
    )))
    .unwrap();
  let (parts, body) = req.into_parts();
  let target = parse_forward_target(&parts).unwrap();

  let result =
    client.forward(&None, &tracker, &target, parts, body, &ctx).await;

  assert!(matches!(result, Err(UpstreamError::TlsCertificateError(_))));
}

#[tokio::test]
async fn test_http3_client_tunnel_without_tls_config_is_rejected() {
  let client = http3_client();
  let tracker = Rc::new(StreamTracker::new());

  let request = http::Request::builder()
    .method(http::Method::CONNECT)
    .uri("example.com:443")
    .body(())
    .unwrap();
  let (parts, ()) = request.into_parts();
  let target = parse_connect_target(&parts).unwrap();
  let result =
    client.connect_for_tunnel(&target, &parts, &None, &tracker).await;

  assert!(matches!(result, Err(UpstreamError::TlsCertificateError(_))));
}

#[tokio::test]
async fn test_http3_client_reconnects_after_goaway_without_quic_close()
{
  use http_body_util::BodyExt;
  let _ = rustls::crypto::ring::default_provider().install_default();
  let identity =
    rcgen::generate_simple_self_signed(vec!["localhost".into()])
      .unwrap();
  let certificate = identity.cert.der().clone();
  let key = rustls::pki_types::PrivatePkcs8KeyDer::from(
    identity.key_pair.serialize_der(),
  );
  let mut server_tls = rustls::ServerConfig::builder()
    .with_no_client_auth()
    .with_single_cert(vec![certificate.clone()], key.into())
    .unwrap();
  server_tls.alpn_protocols = vec![b"h3".to_vec()];
  let server = quinn::ServerConfig::with_crypto(std::sync::Arc::new(
    quinn::crypto::rustls::QuicServerConfig::try_from(server_tls)
      .unwrap(),
  ));
  let endpoint =
    quinn::Endpoint::server(server, "127.0.0.1:0".parse().unwrap())
      .unwrap();
  let address = endpoint.local_addr().unwrap();
  let mut roots = rustls::RootCertStore::empty();
  roots.add(certificate).unwrap();
  let tls = Some(std::sync::Arc::new(
    rustls::ClientConfig::builder()
      .with_root_certificates(roots)
      .with_no_client_auth(),
  ));
  let local = tokio::task::LocalSet::new();
  local
    .run_until(async move {
      let endpoint_copy = endpoint.clone();
      let server = tokio::task::spawn_local(async move {
        let mut connections = Vec::new();
        for _ in 0..2 {
          let connection =
            endpoint_copy.accept().await.unwrap().await.unwrap();
          let mut h3 = h3::server::Connection::<_, Bytes>::new(
            h3_quinn::Connection::new(connection),
          )
          .await
          .unwrap();
          let resolver = h3.accept().await.unwrap().unwrap();
          let (_, mut stream) =
            resolver.resolve_request().await.unwrap();
          // Keep QUIC alive after GOAWAY: transport liveness does not
          // imply that the H3 connection still admits requests.
          h3.shutdown(1).await.unwrap();
          stream.send_response(http::Response::new(())).await.unwrap();
          stream.send_data(Bytes::from_static(b"OK")).await.unwrap();
          stream.finish().await.unwrap();
          connections.push(h3);
        }
        connections
      });
      let mut client = http3_client();
      client.session = SessionPool::new(
        address,
        Some("localhost".into()),
        quic_config(),
        Duration::from_secs(2),
        Default::default(),
      );
      let tracker = Rc::new(StreamTracker::new());

      for _ in 0..2 {
        let request = http::Request::builder()
          .uri("http://example.test/")
          .body(RequestBody::new(BytesBufBodyWrapper::new(Empty::<
            Bytes,
          >::new(
          ))))
          .unwrap();
        let (parts, body) = request.into_parts();
        let target = parse_forward_target(&parts).unwrap();
        let response = tokio::time::timeout(
          Duration::from_secs(3),
          client.forward(
            &tls,
            &tracker,
            &target,
            parts,
            body,
            &RequestContext::new(),
          ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        assert_eq!(
          response.into_body().collect().await.unwrap().to_bytes(),
          "OK"
        );
        tokio::task::yield_now().await;
      }
      let connections = server.await.unwrap();
      drop(connections);
      client.close();
      endpoint.close(0_u32.into(), b"test complete");
      tracker.abort_all();
      tracker.drain().await;
    })
    .await;
}
