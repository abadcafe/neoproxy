use std::io::Cursor;

use super::{
  SocketUse, TlsClientConfigOptions, TlsError, create_client_config,
  create_default_root_cert_store, load_certs, load_private_keys,
};

fn ensure_crypto_provider() {
  let _ = super::rustls::crypto::ring::default_provider().install_default();
}

#[test]
fn test_default_root_cert_store_contains_webpki_roots() {
  let store = create_default_root_cert_store();

  assert!(!store.is_empty());
}

#[test]
fn test_create_client_config_sets_http_alpn_protocols() {
  ensure_crypto_provider();

  let config = create_client_config(TlsClientConfigOptions {
    socket_use: SocketUse::Http,
    ..Default::default()
  })
  .unwrap();

  assert_eq!(
    config.alpn_protocols,
    vec![b"h2".to_vec(), b"http/1.1".to_vec()]
  );
}

#[test]
fn test_load_certs_rejects_empty_pem_input() {
  let mut reader = Cursor::new(Vec::<u8>::new());

  let err = load_certs(&mut reader).unwrap_err();

  assert!(matches!(err, TlsError::CertsNotFound));
}

#[test]
fn test_load_private_keys_rejects_empty_pem_input() {
  let err = load_private_keys(&[]).unwrap_err();

  assert!(matches!(err, TlsError::KeysNotFound));
}
