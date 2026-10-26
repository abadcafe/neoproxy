use std::sync::Arc;
use std::time::Duration;

use super::quic_connect::connect;

#[tokio::test]
async fn test_connect_quic_falls_back_from_unreachable_first_address() {
  let _ = rustls::crypto::ring::default_provider().install_default();
  let identity =
    rcgen::generate_simple_self_signed(vec!["localhost".into()])
      .unwrap();
  let certificate = identity.cert.der().clone();
  let key = rustls::pki_types::PrivatePkcs8KeyDer::from(
    identity.key_pair.serialize_der(),
  );
  let server = quinn::ServerConfig::with_single_cert(
    vec![certificate.clone()],
    key.into(),
  )
  .unwrap();
  let endpoint =
    quinn::Endpoint::server(server, "127.0.0.1:0".parse().unwrap())
      .unwrap();
  let address = endpoint.local_addr().unwrap();
  let mut roots = rustls::RootCertStore::empty();
  roots.add(certificate).unwrap();
  let tls = rustls::ClientConfig::builder()
    .with_root_certificates(roots)
    .with_no_client_auth();
  let client = quinn::ClientConfig::new(Arc::new(
    quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
  ));
  let unreachable = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
  let (connection, peer) = tokio::join!(
    connect(
      vec![unreachable.local_addr().unwrap(), address],
      "localhost",
      client,
      Duration::from_secs(2)
    ),
    async { endpoint.accept().await.unwrap().await.unwrap() },
  );
  let connection = connection.unwrap();
  assert_eq!(connection.remote_address(), address);
  connection.close(0_u32.into(), b"done");
  peer.close(0_u32.into(), b"done");
  endpoint.close(0_u32.into(), b"done");
}
