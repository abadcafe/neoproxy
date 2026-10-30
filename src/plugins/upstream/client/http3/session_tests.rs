use std::sync::Arc;
use std::time::Duration;

use super::session::SessionPool;
use crate::plugins::upstream::client::protocol::QuicConfig;
use crate::task_tracker::TaskTracker;

#[tokio::test(start_paused = true)]
async fn test_session_pool_drop_cancels_maintenance_after_failed_handshake()
 {
  tokio::task::LocalSet::new()
    .run_until(async {
      let peer =
        tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
      let tracker = std::sync::Arc::new(TaskTracker::new());
      let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
      ))
      .with_safe_default_protocol_versions()
      .unwrap()
      .with_root_certificates(rustls::RootCertStore::empty())
      .with_no_client_auth();
      let pool = SessionPool::shared(
        peer.local_addr().unwrap(),
        Some("localhost".into()),
        QuicConfig {
          datagram: Default::default(),
          max_idle_timeout: None,
          keep_alive_interval: Duration::from_secs(3),
          max_concurrent_bidi_streams: None,
          initial_mtu: None,
          send_window: None,
          stream_receive_window: None,
          receive_window: None,
        },
        Duration::from_millis(100),
        super::sessions::Store::new(
          1,
          Duration::from_secs(60),
          crate::header_limits::ResponseLimits::default().limits(),
          tracker.clone(),
        ),
        tokio::runtime::Handle::current(),
      );
      assert!(
        pool
          .open(
            http::Request::builder()
              .uri("https://localhost/")
              .body(())
              .unwrap(),
            &tls,
            &tracker
          )
          .await
          .is_err()
      );
      drop(pool);
      assert!(
        tokio::time::timeout(
          Duration::from_millis(100),
          tracker.wait_shutdown()
        )
        .await
        .is_ok(),
        "retired pool left its idle task alive"
      );
    })
    .await;
}

#[tokio::test]
async fn test_session_pool_peer_closure_during_h3_setup_is_bad_gateway()
{
  use crate::plugins::upstream::error::UpstreamError;

  let identity =
    rcgen::generate_simple_self_signed(vec!["localhost".into()])
      .unwrap();
  let certificate = identity.cert.der().clone();
  let key = rustls::pki_types::PrivatePkcs8KeyDer::from(
    identity.key_pair.serialize_der(),
  );
  let provider = Arc::new(rustls::crypto::ring::default_provider());
  let mut server_tls =
    rustls::ServerConfig::builder_with_provider(provider.clone())
      .with_safe_default_protocol_versions()
      .unwrap()
      .with_no_client_auth()
      .with_single_cert(vec![certificate.clone()], key.into())
      .unwrap();
  server_tls.alpn_protocols = vec![b"h3".to_vec()];
  let mut server = quinn::ServerConfig::with_crypto(Arc::new(
    quinn::crypto::rustls::QuicServerConfig::try_from(server_tls)
      .unwrap(),
  ));
  // Hold H3 control-stream creation pending after the QUIC handshake.
  Arc::get_mut(&mut server.transport)
    .unwrap()
    .max_concurrent_uni_streams(0_u32.into());
  let endpoint =
    quinn::Endpoint::server(server, "127.0.0.1:0".parse().unwrap())
      .unwrap();
  let mut roots = rustls::RootCertStore::empty();
  roots.add(certificate).unwrap();
  let tls = rustls::ClientConfig::builder_with_provider(provider)
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
  tokio::task::LocalSet::new().run_until(async {
    let peer = tokio::task::spawn_local({
      let endpoint = endpoint.clone();
      async move {
        let connection = endpoint.accept().await.unwrap().await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        connection.close(0_u32.into(), b"reject H3 setup");
      }
    });
    let tracker = std::sync::Arc::new(TaskTracker::new());
    let pool = SessionPool::new(
      endpoint.local_addr().unwrap(), Some("localhost".into()),
      QuicConfig {
    datagram:Default::default(),
        max_idle_timeout: None, keep_alive_interval: Duration::from_secs(3),
        max_concurrent_bidi_streams: None, initial_mtu: None,
        send_window: None, receive_window: None, stream_receive_window: None,
      },
      Duration::from_secs(2), Default::default(),
    );
    let result = pool.open(
      http::Request::builder().uri("https://localhost/").body(()).unwrap(),
      &tls, &tracker,
    ).await;
    let Err(error) = result else { panic!("peer rejection unexpectedly succeeded") };
    assert!(matches!(&error, UpstreamError::ConnectionTerminated(message) if message.contains("H3 connection setup")), "{error}");
    assert_eq!(error.http_status(), http::StatusCode::BAD_GATEWAY);
    peer.await.unwrap();
    drop(pool);
    tracker.drain().await;
    endpoint.close(0_u32.into(), b"done");
  }).await;
}

#[tokio::test]
async fn test_session_pool_cancelled_handshake_releases_capacity() {
  let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
  let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
    rustls::crypto::ring::default_provider(),
  ))
  .with_safe_default_protocol_versions()
  .unwrap()
  .with_root_certificates(rustls::RootCertStore::empty())
  .with_no_client_auth();
  let pool = SessionPool::new(
    peer.local_addr().unwrap(),
    Some("localhost".into()),
    QuicConfig {
      datagram: Default::default(),
      max_idle_timeout: None,
      keep_alive_interval: Duration::from_secs(3),
      max_concurrent_bidi_streams: None,
      initial_mtu: None,
      send_window: None,
      receive_window: None,
      stream_receive_window: None,
    },
    Duration::from_secs(30),
    Default::default(),
  );
  let tracker = std::sync::Arc::new(TaskTracker::new());
  let mut bytes = [0; 2048];
  let first_address = {
    let request = pool.open(http::Request::new(()), &tls, &tracker);
    tokio::pin!(request);
    tokio::select! {
      result = &mut request => panic!("handshake completed unexpectedly: {}", result.is_ok()),
      packet = peer.recv_from(&mut bytes) => packet.unwrap().1,
    }
  };
  let second = async {
    let request = pool.open(http::Request::new(()), &tls, &tracker);
    tokio::pin!(request);
    loop {
      tokio::select! {
        result = &mut request => panic!("handshake completed unexpectedly: {}", result.is_ok()),
        packet = peer.recv_from(&mut bytes) => {
          if packet.unwrap().1 != first_address { break; }
        }
      }
    }
  };
  tokio::time::timeout(Duration::from_secs(2), second)
    .await
    .expect("cancelled handshake retained the only pool slot");
}
