use super::proxy::ProxyConfig;

#[test]
fn test_compile_validates_proxy_credentials_and_tls() {
  let _ = rustls::crypto::ring::default_provider().install_default();
  for value in [
    serde_json::json!({"address":"127.0.0.1:1080"}),
    serde_json::json!({"address":"[::1]:1080","username":"user","password":"pass"}),
    serde_json::json!({"address":"proxy.test:1080","tls":{"enabled":true}}),
  ] {
    assert!(
      serde_json::from_value::<ProxyConfig>(value)
        .unwrap()
        .compile()
        .is_ok()
    );
  }
  for value in [
    serde_json::json!({"address":"host"}),
    serde_json::json!({"address":"host:0"}),
    serde_json::json!({"address":"host:1080","username":"user"}),
    serde_json::json!({"address":"host:1080","tls":{"enabled":false,"serverName":"proxy.test"}}),
    serde_json::json!({"address":"host:1080","tls":{"enabled":true,"caCert":"invalid"}}),
  ] {
    assert!(
      serde_json::from_value::<ProxyConfig>(value)
        .unwrap()
        .compile()
        .is_err()
    );
  }
}
