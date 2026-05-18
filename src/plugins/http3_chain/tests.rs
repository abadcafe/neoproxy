#[cfg(test)]
mod tests {
  use std::cell::RefCell;
  use std::future::pending;
  use std::rc::Rc;
  use std::time::Duration;

  use tower::Service as TowerService;

  use crate::config::UserCredential;
  use crate::http_utils::{build_empty_response, build_error_response};
  use crate::plugin::Plugin;
  use crate::plugins::http3_chain::config::*;
  use crate::plugins::http3_chain::upstream::*;
  use crate::plugins::http3_chain::service::*;
  use crate::plugins::http3_chain::{Http3ChainPlugin, SHUTDOWN_TIMEOUT, default_idle_timeout, create_plugin};
  use crate::plugins::utils::{self as utils, ConnectTargetError, ForwardTargetError};
  use crate::service::Service as RuntimeService;

  // ============== ClientTlsConfig Tests ==============

  #[test]
  fn test_client_tls_config_deserialize_empty() {
    let yaml = r#"{}"#;
    let config: ClientTlsConfig = serde_yaml::from_str(yaml).unwrap();
    assert!(config.client_cert_path.is_none());
    assert!(config.client_key_path.is_none());
    assert!(config.server_ca_path.is_none());
  }

  #[test]
  fn test_client_tls_config_deserialize_with_server_ca_path() {
    let yaml = r#"
server_ca_path: /path/to/ca.pem
"#;
    let config: ClientTlsConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(
      config.server_ca_path,
      Some("/path/to/ca.pem".to_string())
    );
    assert!(config.client_cert_path.is_none());
  }

  #[test]
  fn test_client_tls_config_validate_cert_without_key_is_error() {
    let config = ClientTlsConfig {
      client_cert_path: Some("/path/to/cert.pem".to_string()),
      client_key_path: None,
      server_ca_path: None,
    };
    assert!(config.validate_if_non_empty().is_err());
  }

  #[test]
  fn test_user_password_credential_none() {
    let cred = UserPasswordCredential::none();
    assert!(cred.user.is_none());
  }

  #[test]
  fn test_user_password_credential_apply() {
    let cred = UserPasswordCredential {
      user: Some(UserCredential {
        username: "admin".to_string(),
        password: "secret".to_string(),
      }),
    };
    assert!(cred.user.is_some());
    let mut req = http::Request::builder()
      .method("CONNECT")
      .uri("example.com:443")
      .body(())
      .unwrap();
    cred.apply(&mut req);
    assert!(req.headers().contains_key("Proxy-Authorization"));
  }

  #[test]
  fn test_user_password_credential_apply_none_no_header() {
    let cred = UserPasswordCredential::none();
    let mut req = http::Request::builder()
      .method("CONNECT")
      .uri("example.com:443")
      .body(())
      .unwrap();
    cred.apply(&mut req);
    assert!(!req.headers().contains_key("Proxy-Authorization"));
  }

  #[test]
  fn test_client_cert_credential_none() {
    let cred = ClientCertCredential::none();
    assert!(cred.cert_path.is_none());
    assert!(cred.key_path.is_none());
  }

  // ============== deep_merge Tests ==============

  #[test]
  fn test_deep_merge_proxy_overrides_default_server_ca() {
    let default_tls = ClientTlsConfig {
      client_cert_path: None,
      client_key_path: None,
      server_ca_path: Some("/default/ca.pem".to_string()),
    };
    let proxy_tls = ClientTlsConfig {
      client_cert_path: None,
      client_key_path: None,
      server_ca_path: Some("/proxy/ca.pem".to_string()),
    };
    let merged = proxy_tls.deep_merge(&default_tls);
    assert_eq!(
      merged.server_ca_path,
      Some("/proxy/ca.pem".to_string())
    );
  }

  #[test]
  fn test_deep_merge_inherits_all_from_default() {
    let default_tls = ClientTlsConfig {
      client_cert_path: Some("/default/cert.pem".to_string()),
      client_key_path: Some("/default/key.pem".to_string()),
      server_ca_path: Some("/default/ca.pem".to_string()),
    };
    let proxy_tls = ClientTlsConfig {
      client_cert_path: None,
      client_key_path: None,
      server_ca_path: None,
    };
    let merged = proxy_tls.deep_merge(&default_tls);
    assert_eq!(
      merged.client_cert_path,
      Some("/default/cert.pem".to_string())
    );
    assert_eq!(
      merged.client_key_path,
      Some("/default/key.pem".to_string())
    );
    assert_eq!(
      merged.server_ca_path,
      Some("/default/ca.pem".to_string())
    );
  }

  #[test]
  fn test_deep_merge_proxy_overrides_all() {
    let default_tls = ClientTlsConfig {
      client_cert_path: Some("/default/cert.pem".to_string()),
      client_key_path: Some("/default/key.pem".to_string()),
      server_ca_path: Some("/default/ca.pem".to_string()),
    };
    let proxy_tls = ClientTlsConfig {
      client_cert_path: Some("/proxy/cert.pem".to_string()),
      client_key_path: Some("/proxy/key.pem".to_string()),
      server_ca_path: Some("/proxy/ca.pem".to_string()),
    };
    let merged = proxy_tls.deep_merge(&default_tls);
    assert_eq!(
      merged.client_cert_path,
      Some("/proxy/cert.pem".to_string())
    );
    assert_eq!(
      merged.client_key_path,
      Some("/proxy/key.pem".to_string())
    );
    assert_eq!(
      merged.server_ca_path,
      Some("/proxy/ca.pem".to_string())
    );
  }

  // ============== Three-level Config Resolution Tests ==============

  #[test]
  fn test_plugin_config_deserialize() {
    let yaml = r#"
upstreams:
  - name: hk_relay
    addresses:
      - address: "hk.fwcoding.tech:8443"
        hostname: "hk.fwcoding.tech"
        weight: 1
max_idle_timeout: "5m"
user:
  username: "np_proxy"
  password: "Tj4nW8bF3yHc"
tls:
  client_cert_path: "conf/certs/client.crt"
  client_key_path: "conf/certs/client.key"
  server_ca_path: "conf/certs/server-ca.crt"
"#;
    let config: Http3ChainPluginConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.upstreams.len(), 1);
    assert_eq!(config.upstreams[0].name, "hk_relay");
    assert_eq!(config.upstreams[0].addresses.len(), 1);
    assert_eq!(config.upstreams[0].addresses[0].address, "hk.fwcoding.tech:8443");
    assert!(config.max_idle_timeout.is_some());
    assert!(config.user.is_some());
    assert!(config.tls.is_some());
  }

  #[test]
  fn test_resolve_three_level_plugin_only() {
    let config = Http3ChainPluginConfig {
      upstreams: vec![UpstreamConfig {
        name: "test".into(),
        addresses: vec![UpstreamAddressConfig {
          address: "127.0.0.1:443".into(),
          hostname: Some("test.example.com".into()),
          weight: 1,
          max_idle_timeout: None,
          quic: None,
          user: None,
          tls: None,
        }],
        max_idle_timeout: None,
        quic: None,
        user: None,
        tls: None,
      }],
      max_idle_timeout: Some(Duration::from_secs(300)),
      quic: None,
      user: Some(UserCredential {
        username: "plugin_user".into(),
        password: "plugin_pass".into(),
      }),
      tls: Some(ClientTlsConfig {
        server_ca_path: Some("/plugin/ca.pem".into()),
        ..Default::default()
      }),
    };

    let resolved = resolve_three_level(&config).unwrap();
    let upstream = resolved.get("test").unwrap();
    assert_eq!(upstream.addresses.len(), 1);
    let addr = &upstream.addresses[0];
    assert_eq!(addr.max_idle_timeout, Duration::from_secs(300));
    assert!(addr.user_password_credential.user.is_some());
    assert_eq!(addr.server_ca_path, Some("/plugin/ca.pem".into()));
  }

  #[test]
  fn test_resolve_three_level_address_override() {
    let config = Http3ChainPluginConfig {
      upstreams: vec![UpstreamConfig {
        name: "test".into(),
        addresses: vec![UpstreamAddressConfig {
          address: "127.0.0.1:443".into(),
          hostname: Some("test.example.com".into()),
          weight: 1,
          max_idle_timeout: Some(Duration::from_secs(60)),
          quic: None,
          user: Some(UserCredential {
            username: "addr_user".into(),
            password: "addr_pass".into(),
          }),
          tls: None,
        }],
        max_idle_timeout: Some(Duration::from_secs(120)),
        quic: None,
        user: Some(UserCredential {
          username: "upstream_user".into(),
          password: "upstream_pass".into(),
        }),
        tls: None,
      }],
      max_idle_timeout: Some(Duration::from_secs(300)),
      quic: None,
      user: Some(UserCredential {
        username: "plugin_user".into(),
        password: "plugin_pass".into(),
      }),
      tls: None,
    };

    let resolved = resolve_three_level(&config).unwrap();
    let addr = &resolved.get("test").unwrap().addresses[0];
    // Address-level overrides upstream and plugin
    assert_eq!(addr.max_idle_timeout, Duration::from_secs(60));
    let user = addr.user_password_credential.user.as_ref().unwrap();
    assert_eq!(user.username, "addr_user");
  }

  #[test]
  fn test_resolve_three_level_upstream_override() {
    let config = Http3ChainPluginConfig {
      upstreams: vec![UpstreamConfig {
        name: "test".into(),
        addresses: vec![UpstreamAddressConfig {
          address: "127.0.0.1:443".into(),
          hostname: Some("test.example.com".into()),
          weight: 1,
          max_idle_timeout: None, // inherit from upstream
          quic: None,
          user: None, // inherit from upstream
          tls: None,
        }],
        max_idle_timeout: Some(Duration::from_secs(120)),
        quic: None,
        user: Some(UserCredential {
          username: "upstream_user".into(),
          password: "upstream_pass".into(),
        }),
        tls: None,
      }],
      max_idle_timeout: Some(Duration::from_secs(300)),
      quic: None,
      user: None,
      tls: None,
    };

    let resolved = resolve_three_level(&config).unwrap();
    let addr = &resolved.get("test").unwrap().addresses[0];
    // Inherits from upstream level
    assert_eq!(addr.max_idle_timeout, Duration::from_secs(120));
    let user = addr.user_password_credential.user.as_ref().unwrap();
    assert_eq!(user.username, "upstream_user");
  }

  #[test]
  fn test_resolve_three_level_inherits_default_idle_timeout() {
    let config = Http3ChainPluginConfig {
      upstreams: vec![UpstreamConfig {
        name: "test".into(),
        addresses: vec![UpstreamAddressConfig {
          address: "127.0.0.1:443".into(),
          hostname: Some("test.example.com".into()),
          weight: 1,
          max_idle_timeout: None,
          quic: None,
          user: None,
          tls: None,
        }],
        max_idle_timeout: None,
        quic: None,
        user: None,
        tls: None,
      }],
      ..Default::default()
    };

    let resolved = resolve_three_level(&config).unwrap();
    let addr = &resolved.get("test").unwrap().addresses[0];
    assert_eq!(addr.max_idle_timeout, default_idle_timeout());
  }

  // ============== Http3ChainServiceArgs Tests ==============

  #[test]
  fn test_service_args_deserialize() {
    let yaml = r#"
upstream: hk_relay
"#;
    let args: Http3ChainServiceArgs = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(args.upstream, "hk_relay");
  }

  #[test]
  fn test_service_args_empty_upstream_fails() {
    let args = Http3ChainServiceArgs { upstream: "".into() };
    assert!(args.validate().is_err());
  }

  // ============== WRR Tests ==============

  #[test]
  fn test_schedule_wrr_single() {
    let mut addresses = vec![ResolvedAddress {
      address: "127.0.0.1:8080".into(),
      hostname: Some("proxy.example.com".into()),
      weight: 1,
      current_weight: 0,
      max_idle_timeout: Duration::from_secs(300),
      quic: QuicResolved {
        keep_alive_interval: Duration::from_secs(3),
        max_idle_timeout: None,
      },
      user_password_credential: UserPasswordCredential::none(),
      client_cert_credential: ClientCertCredential::none(),
      server_ca_path: None,
    }];
    assert_eq!(schedule_wrr(&mut addresses), Some(0));
  }

  #[test]
  fn test_schedule_wrr_two_proxies_weight_2_to_1() {
    let mut addresses = vec![
      ResolvedAddress {
        address: "127.0.0.1:8080".into(),
        hostname: Some("p1.example.com".into()),
        weight: 2,
        current_weight: 0,
        max_idle_timeout: Duration::from_secs(300),
        quic: QuicResolved {
          keep_alive_interval: Duration::from_secs(3),
          max_idle_timeout: None,
        },
        user_password_credential: UserPasswordCredential::none(),
        client_cert_credential: ClientCertCredential::none(),
        server_ca_path: None,
      },
      ResolvedAddress {
        address: "127.0.0.1:8081".into(),
        hostname: Some("p2.example.com".into()),
        weight: 1,
        current_weight: 0,
        max_idle_timeout: Duration::from_secs(300),
        quic: QuicResolved {
          keep_alive_interval: Duration::from_secs(3),
          max_idle_timeout: None,
        },
        user_password_credential: UserPasswordCredential::none(),
        client_cert_credential: ClientCertCredential::none(),
        server_ca_path: None,
      },
    ];

    let selections: Vec<usize> =
      (0..6).map(|_| schedule_wrr(&mut addresses).unwrap()).collect();

    let count_0 = selections.iter().filter(|&&x| x == 0).count();
    let count_1 = selections.iter().filter(|&&x| x == 1).count();
    assert_eq!(count_0, 4);
    assert_eq!(count_1, 2);
  }

  #[test]
  fn test_schedule_wrr_empty_returns_none() {
    let mut addresses: Vec<ResolvedAddress> = vec![];
    assert_eq!(schedule_wrr(&mut addresses), None);
  }

  // ============== Address Resolution Tests ==============

  #[test]
  fn test_resolve_address_ip_port() {
    let addr = resolve_address("127.0.0.1:8080").unwrap();
    assert_eq!(addr, "127.0.0.1:8080".parse().unwrap());
  }

  #[test]
  fn test_resolve_address_localhost() {
    let addr = resolve_address("localhost:8080").unwrap();
    assert!(addr.is_ipv4() || addr.is_ipv6());
    assert_eq!(addr.port(), 8080);
  }

  #[test]
  fn test_resolve_address_unresolvable_fails() {
    let result = resolve_address("this.host.does.not.exist.invalid:8080");
    assert!(result.is_err());
  }

  #[test]
  fn test_resolve_address_missing_port_fails() {
    let result = resolve_address("127.0.0.1");
    assert!(result.is_err());
  }

  #[test]
  fn test_resolve_address_garbage_fails() {
    let result = resolve_address("not-a-valid-address");
    assert!(result.is_err());
  }

  // ============== Response Builder Tests ==============

  #[test]
  fn test_build_empty_response_ok() {
    let resp = build_empty_response(http::StatusCode::OK);
    assert_eq!(resp.status(), http::StatusCode::OK);
  }

  #[test]
  fn test_build_empty_response_bad_gateway() {
    let resp = build_empty_response(http::StatusCode::BAD_GATEWAY);
    assert_eq!(resp.status(), http::StatusCode::BAD_GATEWAY);
  }

  #[test]
  fn test_build_empty_response_service_unavailable() {
    let resp =
      build_empty_response(http::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(resp.status(), http::StatusCode::SERVICE_UNAVAILABLE);
  }

  #[test]
  fn test_build_error_response_method_not_allowed() {
    let resp = build_error_response(
      http::StatusCode::METHOD_NOT_ALLOWED,
      "Only CONNECT method is supported",
    );
    assert_eq!(resp.status(), http::StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(
      resp.headers().get(http::header::CONTENT_TYPE).unwrap(),
      "text/plain"
    );
  }

  #[test]
  fn test_build_tunnel_response() {
    let resp = build_tunnel_response();
    assert_eq!(resp.status(), http::StatusCode::OK);
  }

  // ============== CONNECT Validation Tests ==============

  #[test]
  fn test_parse_connect_target_rejects_non_connect_method() {
    let req = http::Request::builder()
      .method(http::Method::GET)
      .uri("http://example.com/")
      .body(())
      .unwrap();
    let (parts, _) = req.into_parts();
    let result = utils::parse_connect_target(&parts);
    assert!(matches!(
      result,
      Err(ConnectTargetError::NotConnectMethod)
    ));
  }

  #[test]
  fn test_connect_missing_port_produces_400() {
    let req = http::Request::builder()
      .method(http::Method::CONNECT)
      .uri("example.com")
      .body(())
      .unwrap();
    let (parts, _) = req.into_parts();
    let result = utils::parse_connect_target(&parts);
    assert!(matches!(
      result,
      Err(ConnectTargetError::NoAuthority)
        | Err(ConnectTargetError::NoPort)
    ));
  }

  #[test]
  fn test_connect_port_zero_produces_400() {
    let req = http::Request::builder()
      .method(http::Method::CONNECT)
      .uri("example.com:0")
      .body(())
      .unwrap();
    let (parts, _) = req.into_parts();
    let result = utils::parse_connect_target(&parts);
    assert!(matches!(result, Err(ConnectTargetError::PortZero)));
  }

  // ============== Forward Proxy Validation Tests ==============

  #[test]
  fn test_parse_forward_target_https_returns_unsupported_scheme() {
    let (parts, _) = http::Request::builder()
      .method(http::Method::GET)
      .uri("https://example.com/path")
      .body(())
      .unwrap()
      .into_parts();
    let result = utils::parse_forward_target(&parts);
    assert!(matches!(
      result,
      Err(ForwardTargetError::UnsupportedScheme)
    ));
  }

  #[test]
  fn test_parse_forward_target_origin_form_returns_not_absolute() {
    let (parts, _) = http::Request::builder()
      .method(http::Method::GET)
      .uri("/path")
      .body(())
      .unwrap()
      .into_parts();
    let result = utils::parse_forward_target(&parts);
    assert!(matches!(
      result,
      Err(ForwardTargetError::NotAbsoluteForm)
    ));
  }

  #[test]
  fn test_parse_forward_target_valid_http() {
    let (parts, _) = http::Request::builder()
      .method(http::Method::GET)
      .uri("http://example.com:8080/path?q=1")
      .body(())
      .unwrap()
      .into_parts();
    let result = utils::parse_forward_target(&parts);
    assert!(result.is_ok());
    let (host, port, _) = result.unwrap();
    assert_eq!(host, "example.com");
    assert_eq!(port, 8080);
  }

  // ============== Http3ChainService Dispatch Tests ==============

  fn make_h3_service_request(
    method: http::Method,
    uri: &str,
  ) -> crate::http_utils::Request {
    use crate::context::RequestContext;
    use crate::http_utils::{BytesBufBodyWrapper, RequestBody};

    let mut req = http::Request::builder()
      .method(method)
      .uri(uri)
      .body(RequestBody::new(BytesBufBodyWrapper::new(
        http_body_util::Empty::new(),
      )))
      .unwrap();
    req.extensions_mut().insert(RequestContext::new());
    req
  }

  #[tokio::test]
  async fn test_service_non_connect_origin_form_returns_400() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let svc = Http3ChainService::new_for_test("test_upstream");
        let mut svc = RuntimeService::new(svc);
        let req =
          make_h3_service_request(http::Method::GET, "/path");
        let resp = TowerService::call(&mut svc, req).await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
      })
      .await;
  }

  #[tokio::test]
  async fn test_service_non_connect_https_scheme_returns_400() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let svc = Http3ChainService::new_for_test("test_upstream");
        let mut svc = RuntimeService::new(svc);
        let req = make_h3_service_request(
          http::Method::GET,
          "https://example.com/",
        );
        let resp = TowerService::call(&mut svc, req).await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
      })
      .await;
  }

  #[tokio::test]
  async fn test_service_non_connect_valid_http_no_upstream_returns_error() {
    // No upstream registered → get_upstream_handle fails → 502/503/504
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let svc =
          Http3ChainService::new_for_test("nonexistent_upstream");
        let mut svc = RuntimeService::new(svc);
        let req = make_h3_service_request(
          http::Method::GET,
          "http://example.com/path",
        );
        let resp = TowerService::call(&mut svc, req).await.unwrap();
        assert!(
          resp.status() == http::StatusCode::BAD_GATEWAY
            || resp.status() == http::StatusCode::SERVICE_UNAVAILABLE
            || resp.status() == http::StatusCode::GATEWAY_TIMEOUT,
          "expected 502/503/504, got {}",
          resp.status()
        );
      })
      .await;
  }

  #[tokio::test]
  async fn test_service_connect_no_upstream_returns_error() {
    // CONNECT path: no upstream → get_upstream_handle fails → 502/503/504
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let svc =
          Http3ChainService::new_for_test("nonexistent_upstream");
        let mut svc = RuntimeService::new(svc);
        let req = make_h3_service_request(
          http::Method::CONNECT,
          "example.com:443",
        );
        let resp = TowerService::call(&mut svc, req).await.unwrap();
        assert!(
          resp.status() == http::StatusCode::BAD_GATEWAY
            || resp.status() == http::StatusCode::SERVICE_UNAVAILABLE
            || resp.status() == http::StatusCode::GATEWAY_TIMEOUT,
          "expected 502/503/504, got {}",
          resp.status()
        );
      })
      .await;
  }

  // ============== RequestContext Integration Tests ==============

  #[test]
  fn test_request_context_insert_and_get_roundtrip() {
    use crate::context::RequestContext;

    let ctx = RequestContext::new();
    ctx.insert("http3_chain.connect_ms", "42".to_string());
    let connect_ms =
      ctx.get("http3_chain.connect_ms").unwrap();
    assert_eq!(connect_ms, "42");
  }

  // ============== Plugin Tests ==============

  #[test]
  fn test_plugin_new() {
    let plugin = Http3ChainPlugin::new();
    assert!(plugin.service_builder("http3_chain").is_some());
    assert!(plugin.service_builder("nonexistent").is_none());
  }

  #[test]
  fn test_create_plugin_no_config() {
    let plugin = create_plugin(None);
    assert!(plugin.service_builder("http3_chain").is_some());
  }

  #[tokio::test]
  async fn test_uninstall_empty_plugin() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let plugin = Http3ChainPlugin::new();

        let result = tokio::time::timeout(
          Duration::from_millis(100),
          plugin.uninstall(),
        )
        .await;
        assert!(
          result.is_ok(),
          "Uninstall should complete quickly with no streams"
        );
      })
      .await;
  }

  #[tokio::test]
  async fn test_uninstall_with_pending_stream() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let plugin = Http3ChainPlugin::new();

        plugin.stream_tracker.register(async {
          pending::<()>().await;
        });

        tokio::task::yield_now().await;

        let start = std::time::Instant::now();
        plugin.uninstall().await;
        let elapsed = start.elapsed();

        assert!(
          elapsed >= SHUTDOWN_TIMEOUT,
          "Uninstall should wait for timeout"
        );
        assert!(
          elapsed < SHUTDOWN_TIMEOUT + Duration::from_millis(500),
          "Uninstall should not take much longer than timeout"
        );

        assert_eq!(plugin.stream_tracker.active_count(), 0);
      })
      .await;
  }

  #[tokio::test]
  async fn test_uninstall_with_completing_stream() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let plugin = Http3ChainPlugin::new();

        let completed = Rc::new(RefCell::new(false));
        let completed_clone = completed.clone();

        plugin.stream_tracker.register(async move {
          tokio::time::sleep(Duration::from_millis(10)).await;
          completed_clone.replace(true);
        });

        tokio::task::yield_now().await;

        let start = std::time::Instant::now();
        plugin.uninstall().await;
        let elapsed = start.elapsed();

        assert!(
          elapsed < SHUTDOWN_TIMEOUT,
          "Uninstall should complete before timeout"
        );
        assert!(*completed.borrow(), "Stream should have completed");
      })
      .await;
  }

  #[tokio::test]
  async fn test_uninstall_multiple_times() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let plugin = Http3ChainPlugin::new();
        plugin.uninstall().await;
        plugin.uninstall().await;
        plugin.uninstall().await;
      })
      .await;
  }

  // ============== Service Args Rejects Unknown Fields ==============

  #[test]
  fn test_service_args_rejects_unknown_fields() {
    let yaml = r#"
upstream: hk_relay
old_field: value
"#;
    let result: Result<Http3ChainServiceArgs, _> =
      serde_yaml::from_str(yaml);
    assert!(result.is_err(), "Should reject unknown fields");
  }

  // ============== Plugin Config Rejects Unknown Fields ==============

  #[test]
  fn test_plugin_config_rejects_unknown_fields() {
    let yaml = r#"
upstreams:
  - name: hk_relay
    addresses:
      - address: "hk.fwcoding.tech:8443"
        hostname: "hk.fwcoding.tech"
        weight: 1
old_field: value
"#;
    let result: Result<Http3ChainPluginConfig, _> =
      serde_yaml::from_str(yaml);
    assert!(result.is_err(), "Should reject unknown fields");
  }

  // ============== Resolve Address Validation ==============

  #[test]
  fn test_resolve_three_level_invalid_address_fails() {
    let config = Http3ChainPluginConfig {
      upstreams: vec![UpstreamConfig {
        name: "test".into(),
        addresses: vec![UpstreamAddressConfig {
          address: "not-a-valid-address".into(),
          hostname: None,
          weight: 1,
          max_idle_timeout: None,
          quic: None,
          user: None,
          tls: None,
        }],
        max_idle_timeout: None,
        quic: None,
        user: None,
        tls: None,
      }],
      ..Default::default()
    };

    let result = resolve_three_level(&config);
    assert!(result.is_err());
  }
}