use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use super::session::SessionPool;
use crate::plugins::http_upstream::upstream::protocol::QuicConfig;
use crate::tracker::StreamTracker;

#[tokio::test(start_paused = true)]
async fn test_session_pool_drop_cancels_maintenance_after_failed_handshake()
 {
  tokio::task::LocalSet::new()
    .run_until(async {
      let peer =
        tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
      let tracker = Rc::new(StreamTracker::new());
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
          max_idle_timeout: None,
          keep_alive_interval: Duration::from_secs(3),
          max_concurrent_bidi_streams: None,
          initial_mtu: None,
          send_window: None,
          receive_window: None,
        },
        Duration::from_millis(100),
        Default::default(),
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
