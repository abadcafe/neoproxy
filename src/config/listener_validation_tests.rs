use super::listener_validation::*;
use super::listener_validation_test_support::MockListenerProps;
use super::{ConfigError, ConfigErrorCollector};

// =========================================================================
// validate_listener_addresses Tests
// =========================================================================

#[test]
fn test_validate_valid_address() {
  let addresses = vec!["127.0.0.1:8080".to_string()];
  let mut collector = ConfigErrorCollector::new();
  validate_listener_addresses(&addresses, "test", &mut collector);
  assert!(!collector.has_errors());
}

#[test]
fn test_validate_invalid_address() {
  let addresses = vec!["invalid:address".to_string()];
  let mut collector = ConfigErrorCollector::new();
  validate_listener_addresses(&addresses, "test", &mut collector);
  assert!(collector.has_errors());
  let errors = collector.errors();
  assert_eq!(errors.len(), 1);
  assert!(matches!(&errors[0], ConfigError::InvalidAddress { .. }));
}

#[test]
fn test_validate_multiple_invalid_addresses() {
  let addresses = vec![
    "invalid1".to_string(),
    "127.0.0.1:8080".to_string(),
    "invalid2".to_string(),
  ];
  let mut collector = ConfigErrorCollector::new();
  validate_listener_addresses(&addresses, "test", &mut collector);
  assert!(collector.has_errors());
  assert_eq!(collector.errors().len(), 2);
}

#[test]
fn test_validate_addresses_empty_array() {
  let addresses: Vec<String> = vec![];
  let mut collector = ConfigErrorCollector::new();
  validate_listener_addresses(&addresses, "test", &mut collector);
  assert!(collector.has_errors());
  assert!(matches!(
    &collector.errors()[0],
    ConfigError::InvalidAddress { message, .. } if message == "addresses list cannot be empty"
  ));
}

// =========================================================================
// validate_hostname Tests
// =========================================================================

#[test]
fn test_validate_hostname_empty_is_error() {
  let mut collector = ConfigErrorCollector::new();
  validate_hostname("", "test.hostname", &mut collector);
  assert!(collector.has_errors());
  assert!(matches!(
    &collector.errors()[0],
    ConfigError::InvalidFormat { message, .. } if message == "hostname cannot be empty"
  ));
}

#[test]
fn test_validate_hostname_valid_exact() {
  let mut collector = ConfigErrorCollector::new();
  validate_hostname("api.example.com", "test.hostname", &mut collector);
  assert!(!collector.has_errors(), "{:?}", collector.errors());
}

#[test]
fn test_validate_hostname_valid_single_label() {
  let mut collector = ConfigErrorCollector::new();
  validate_hostname("localhost", "test.hostname", &mut collector);
  assert!(!collector.has_errors(), "{:?}", collector.errors());
}

#[test]
fn test_validate_hostname_valid_wildcard() {
  let mut collector = ConfigErrorCollector::new();
  validate_hostname("*.example.com", "test.hostname", &mut collector);
  assert!(!collector.has_errors(), "{:?}", collector.errors());
}

#[test]
fn test_validate_hostname_bare_wildcard_is_error() {
  let mut collector = ConfigErrorCollector::new();
  validate_hostname("*", "test.hostname", &mut collector);
  assert!(collector.has_errors());
  assert!(matches!(
    &collector.errors()[0],
    ConfigError::InvalidFormat { .. }
  ));
}

#[test]
fn test_validate_hostname_wildcard_no_dot_is_error() {
  let mut collector = ConfigErrorCollector::new();
  validate_hostname("*example.com", "test.hostname", &mut collector);
  assert!(collector.has_errors());
  assert!(matches!(
    &collector.errors()[0],
    ConfigError::InvalidFormat { .. }
  ));
}

#[test]
fn test_validate_hostname_wildcard_with_subdomain_is_valid() {
  let mut collector = ConfigErrorCollector::new();
  validate_hostname(
    "*.sub.example.com",
    "test.hostname",
    &mut collector,
  );
  assert!(!collector.has_errors(), "{:?}", collector.errors());
}

// =========================================================================
// validate_hostname_routing_compatibility Tests
// =========================================================================

#[test]
fn test_validate_hostname_routing_socks5_with_hostnames_error() {
  // Negative: socks5 does NOT support hostname routing
  let config = super::Config {
    listeners: vec![super::ListenerConfig {
      name: "socks5_main".to_string(),
      kind: "socks5".to_string(),
      addresses: vec!["127.0.0.1:1080".to_string()],
      ..Default::default()
    }],
    servers: vec![super::Server {
      name: "socks_server".to_string(),
      hostnames: vec!["api.example.com".to_string()],
      listeners: vec!["socks5_main".to_string()],
      service: "".to_string(),
      ..Default::default()
    }],
    ..Default::default()
  };
  let mut collector = ConfigErrorCollector::new();
  let lm = MockListenerProps;
  validate_hostname_routing_compatibility(&config, &mut collector, &lm);
  assert!(collector.has_errors());
  assert!(matches!(
    &collector.errors()[0],
    ConfigError::InvalidFormat { .. }
  ));
}

#[test]
fn test_validate_hostname_routing_socks5_empty_hostnames_ok() {
  // Positive: socks5 with empty hostnames is valid
  let config = super::Config {
    listeners: vec![super::ListenerConfig {
      name: "socks5_main".to_string(),
      kind: "socks5".to_string(),
      addresses: vec!["127.0.0.1:1080".to_string()],
      ..Default::default()
    }],
    servers: vec![super::Server {
      name: "socks_server".to_string(),
      hostnames: vec![],
      listeners: vec!["socks5_main".to_string()],
      service: "".to_string(),
      ..Default::default()
    }],
    ..Default::default()
  };
  let mut collector = ConfigErrorCollector::new();
  let lm = MockListenerProps;
  validate_hostname_routing_compatibility(&config, &mut collector, &lm);
  assert!(!collector.has_errors());
}

#[test]
fn test_validate_hostname_routing_http_with_hostnames_ok() {
  // Positive: http supports hostname routing
  let config = super::Config {
    listeners: vec![super::ListenerConfig {
      name: "http_main".to_string(),
      kind: "http".to_string(),
      addresses: vec!["127.0.0.1:8080".to_string()],
      ..Default::default()
    }],
    servers: vec![super::Server {
      name: "http_server".to_string(),
      hostnames: vec!["api.example.com".to_string()],
      listeners: vec!["http_main".to_string()],
      service: "".to_string(),
      ..Default::default()
    }],
    ..Default::default()
  };
  let mut collector = ConfigErrorCollector::new();
  let lm = MockListenerProps;
  validate_hostname_routing_compatibility(&config, &mut collector, &lm);
  assert!(!collector.has_errors());
}

#[test]
fn test_validate_hostname_routing_https_with_hostnames_ok() {
  // Positive: https supports hostname routing
  let config = super::Config {
    listeners: vec![super::ListenerConfig {
      name: "https_main".to_string(),
      kind: "https".to_string(),
      addresses: vec!["127.0.0.1:8443".to_string()],
      ..Default::default()
    }],
    servers: vec![super::Server {
      name: "https_server".to_string(),
      hostnames: vec!["api.example.com".to_string()],
      listeners: vec!["https_main".to_string()],
      service: "".to_string(),
      tls: Some(super::ServerTlsConfig {
        certificates: vec![],
        client_ca_certs: None,
      }),
      ..Default::default()
    }],
    ..Default::default()
  };
  let mut collector = ConfigErrorCollector::new();
  let lm = MockListenerProps;
  validate_hostname_routing_compatibility(&config, &mut collector, &lm);
  assert!(!collector.has_errors());
}

#[test]
fn test_validate_hostname_routing_http3_with_hostnames_ok() {
  // Positive: http3 supports hostname routing
  let config = super::Config {
    listeners: vec![super::ListenerConfig {
      name: "http3_main".to_string(),
      kind: "http3".to_string(),
      addresses: vec!["127.0.0.1:443".to_string()],
      ..Default::default()
    }],
    servers: vec![super::Server {
      name: "http3_server".to_string(),
      hostnames: vec!["api.example.com".to_string()],
      listeners: vec!["http3_main".to_string()],
      service: "".to_string(),
      tls: Some(super::ServerTlsConfig {
        certificates: vec![],
        client_ca_certs: None,
      }),
      ..Default::default()
    }],
    ..Default::default()
  };
  let mut collector = ConfigErrorCollector::new();
  let lm = MockListenerProps;
  validate_hostname_routing_compatibility(&config, &mut collector, &lm);
  assert!(!collector.has_errors());
}

#[test]
fn test_validate_hostname_routing_mixed_listeners_error() {
  // Negative: one server with http + socks5, hostnames configured
  // socks5 doesn't support hostname routing, should error
  let config = super::Config {
    listeners: vec![
      super::ListenerConfig {
        name: "http_main".to_string(),
        kind: "http".to_string(),
        addresses: vec!["127.0.0.1:8080".to_string()],
        ..Default::default()
      },
      super::ListenerConfig {
        name: "socks5_main".to_string(),
        kind: "socks5".to_string(),
        addresses: vec!["127.0.0.1:1080".to_string()],
        ..Default::default()
      },
    ],
    servers: vec![super::Server {
      name: "mixed_server".to_string(),
      hostnames: vec!["api.example.com".to_string()],
      listeners: vec![
        "http_main".to_string(),
        "socks5_main".to_string(),
      ],
      service: "".to_string(),
      ..Default::default()
    }],
    ..Default::default()
  };
  let mut collector = ConfigErrorCollector::new();
  let lm = MockListenerProps;
  validate_hostname_routing_compatibility(&config, &mut collector, &lm);
  assert!(collector.has_errors());
  // Should have exactly one error for the socks5 listener
  let errors: Vec<_> = collector
    .errors()
    .iter()
    .filter(|e| matches!(e, ConfigError::InvalidFormat { .. }))
    .collect();
  assert_eq!(errors.len(), 1);
  // Error should point to the socks5 listener
  assert!(errors[0].location().contains("listeners[1]"));
}

#[test]
fn test_validate_hostname_routing_multiple_servers_partial_error() {
  // Multiple servers: one valid, one invalid
  let config = super::Config {
    listeners: vec![
      super::ListenerConfig {
        name: "http_main".to_string(),
        kind: "http".to_string(),
        addresses: vec!["127.0.0.1:8080".to_string()],
        ..Default::default()
      },
      super::ListenerConfig {
        name: "socks5_main".to_string(),
        kind: "socks5".to_string(),
        addresses: vec!["127.0.0.1:1080".to_string()],
        ..Default::default()
      },
    ],
    servers: vec![
      super::Server {
        name: "http_server".to_string(),
        hostnames: vec!["api.example.com".to_string()],
        listeners: vec!["http_main".to_string()],
        service: "".to_string(),
        ..Default::default()
      },
      super::Server {
        name: "socks_server".to_string(),
        hostnames: vec!["api.example.com".to_string()],
        listeners: vec!["socks5_main".to_string()],
        service: "".to_string(),
        ..Default::default()
      },
    ],
    ..Default::default()
  };
  let mut collector = ConfigErrorCollector::new();
  let lm = MockListenerProps;
  validate_hostname_routing_compatibility(&config, &mut collector, &lm);
  assert!(collector.has_errors());
  // Only socks_server should have error (servers[1])
  let errors: Vec<_> = collector
    .errors()
    .iter()
    .filter(|e| matches!(e, ConfigError::InvalidFormat { .. }))
    .collect();
  assert_eq!(errors.len(), 1);
  // Error location should reference the second server
  assert!(errors[0].location().contains("servers[1]"));
}

#[test]
fn test_validate_hostname_routing_unknown_listener_kind_skipped() {
  // Unknown listener kind should be skipped (no error)
  let config = super::Config {
    listeners: vec![super::ListenerConfig {
      name: "unknown_main".to_string(),
      kind: "unknown_kind".to_string(),
      addresses: vec!["127.0.0.1:9999".to_string()],
      ..Default::default()
    }],
    servers: vec![super::Server {
      name: "unknown_server".to_string(),
      hostnames: vec!["api.example.com".to_string()],
      listeners: vec!["unknown_main".to_string()],
      service: "".to_string(),
      ..Default::default()
    }],
    ..Default::default()
  };
  let mut collector = ConfigErrorCollector::new();
  let lm = MockListenerProps;
  validate_hostname_routing_compatibility(&config, &mut collector, &lm);
  // Unknown listener kind is skipped, no error
  assert!(!collector.has_errors());
}

#[test]
fn test_validate_hostname_routing_no_hostnames_skipped() {
  // Server without hostnames should be skipped entirely
  let config = super::Config {
    listeners: vec![super::ListenerConfig {
      name: "socks5_main".to_string(),
      kind: "socks5".to_string(),
      addresses: vec!["127.0.0.1:1080".to_string()],
      ..Default::default()
    }],
    servers: vec![super::Server {
      name: "default_server".to_string(),
      hostnames: vec![], // empty hostnames
      listeners: vec!["socks5_main".to_string()],
      service: "".to_string(),
      ..Default::default()
    }],
    ..Default::default()
  };
  let mut collector = ConfigErrorCollector::new();
  let lm = MockListenerProps;
  validate_hostname_routing_compatibility(&config, &mut collector, &lm);
  assert!(!collector.has_errors());
}

#[test]
fn test_validate_hostname_routing_all_supported_listeners_ok() {
  // Server with http + https + http3, all support hostname routing
  let config = super::Config {
    listeners: vec![
      super::ListenerConfig {
        name: "http_main".to_string(),
        kind: "http".to_string(),
        addresses: vec!["127.0.0.1:8080".to_string()],
        ..Default::default()
      },
      super::ListenerConfig {
        name: "https_main".to_string(),
        kind: "https".to_string(),
        addresses: vec!["127.0.0.1:8443".to_string()],
        ..Default::default()
      },
      super::ListenerConfig {
        name: "http3_main".to_string(),
        kind: "http3".to_string(),
        addresses: vec!["127.0.0.1:443".to_string()],
        ..Default::default()
      },
    ],
    servers: vec![super::Server {
      name: "all_supported".to_string(),
      hostnames: vec!["api.example.com".to_string()],
      listeners: vec![
        "http_main".to_string(),
        "https_main".to_string(),
        "http3_main".to_string(),
      ],
      service: "".to_string(),
      tls: Some(super::ServerTlsConfig {
        certificates: vec![],
        client_ca_certs: None,
      }),
      ..Default::default()
    }],
    ..Default::default()
  };
  let mut collector = ConfigErrorCollector::new();
  let lm = MockListenerProps;
  validate_hostname_routing_compatibility(&config, &mut collector, &lm);
  assert!(!collector.has_errors());
}

// =========================================================================
// validate_address_conflicts Tests
// =========================================================================

fn has_error_of_type(
  collector: &ConfigErrorCollector,
  discriminant: impl Fn(&ConfigError) -> bool,
) -> bool {
  collector.errors().iter().any(|e| discriminant(e))
}

#[test]
fn test_address_conflict_tcp_vs_tcp_different_kind() {
  let config = super::Config {
    listeners: vec![
      super::ListenerConfig {
        name: "http_main".to_string(),
        kind: "http".to_string(),
        addresses: vec!["127.0.0.1:8080".to_string()],
        ..Default::default()
      },
      super::ListenerConfig {
        name: "socks5_main".to_string(),
        kind: "socks5".to_string(),
        addresses: vec!["127.0.0.1:8080".to_string()],
        ..Default::default()
      },
    ],
    servers: vec![
      super::Server {
        name: "server1".to_string(),
        hostnames: vec![],
        listeners: vec!["http_main".to_string()],
        service: "echo".to_string(),
        ..Default::default()
      },
      super::Server {
        name: "server2".to_string(),
        hostnames: vec![],
        listeners: vec!["socks5_main".to_string()],
        service: "echo".to_string(),
        ..Default::default()
      },
    ],
    ..Default::default()
  };

  let mut collector = ConfigErrorCollector::new();
  let lm = MockListenerProps;
  validate_address_conflicts(&config, &mut collector, &lm);
  assert!(collector.has_errors());
  assert!(has_error_of_type(&collector, |e| matches!(
    e,
    ConfigError::AddressConflict { .. }
  )));
}

#[test]
fn test_address_same_kind_can_share_with_hostnames() {
  let config = super::Config {
    listeners: vec![super::ListenerConfig {
      name: "http_main".to_string(),
      kind: "http".to_string(),
      addresses: vec!["127.0.0.1:8080".to_string()],
      ..Default::default()
    }],
    servers: vec![
      super::Server {
        name: "default_server".to_string(),
        hostnames: vec![],
        listeners: vec!["http_main".to_string()],
        service: "echo".to_string(),
        ..Default::default()
      },
      super::Server {
        name: "api_server".to_string(),
        hostnames: vec!["api.example.com".to_string()],
        listeners: vec!["http_main".to_string()],
        service: "echo".to_string(),
        ..Default::default()
      },
    ],
    ..Default::default()
  };

  let mut collector = ConfigErrorCollector::new();
  let lm = MockListenerProps;
  validate_address_conflicts(&config, &mut collector, &lm);
  assert!(!collector.has_errors(), "{:?}", collector.errors());
}

#[test]
fn test_address_multiple_default_servers_conflict() {
  let config = super::Config {
    listeners: vec![super::ListenerConfig {
      name: "http_main".to_string(),
      kind: "http".to_string(),
      addresses: vec!["127.0.0.1:8080".to_string()],
      ..Default::default()
    }],
    servers: vec![
      super::Server {
        name: "server1".to_string(),
        hostnames: vec![],
        listeners: vec!["http_main".to_string()],
        service: "echo".to_string(),
        ..Default::default()
      },
      super::Server {
        name: "server2".to_string(),
        hostnames: vec![],
        listeners: vec!["http_main".to_string()],
        service: "echo".to_string(),
        ..Default::default()
      },
    ],
    ..Default::default()
  };

  let mut collector = ConfigErrorCollector::new();
  let lm = MockListenerProps;
  validate_address_conflicts(&config, &mut collector, &lm);
  assert!(collector.has_errors());
  assert!(has_error_of_type(&collector, |e| matches!(
    e,
    ConfigError::HostnameConflict { .. }
  )));
}

#[test]
fn test_hostname_exact_duplicate_conflict() {
  let config = super::Config {
    listeners: vec![super::ListenerConfig {
      name: "http_main".to_string(),
      kind: "http".to_string(),
      addresses: vec!["127.0.0.1:8080".to_string()],
      ..Default::default()
    }],
    servers: vec![
      super::Server {
        name: "server_a".to_string(),
        hostnames: vec!["api.example.com".to_string()],
        listeners: vec!["http_main".to_string()],
        service: "".to_string(),
        ..Default::default()
      },
      super::Server {
        name: "server_b".to_string(),
        hostnames: vec!["api.example.com".to_string()],
        listeners: vec!["http_main".to_string()],
        service: "".to_string(),
        ..Default::default()
      },
    ],
    ..Default::default()
  };

  let mut collector = ConfigErrorCollector::new();
  let lm = MockListenerProps;
  validate_address_conflicts(&config, &mut collector, &lm);
  assert!(collector.has_errors());
  assert!(has_error_of_type(&collector, |e| matches!(
    e,
    ConfigError::HostnameConflict { .. }
  )));
}

#[test]
fn test_hostname_wildcard_duplicate_conflict() {
  let config = super::Config {
    listeners: vec![super::ListenerConfig {
      name: "http_main".to_string(),
      kind: "http".to_string(),
      addresses: vec!["127.0.0.1:8080".to_string()],
      ..Default::default()
    }],
    servers: vec![
      super::Server {
        name: "server_a".to_string(),
        hostnames: vec!["*.example.com".to_string()],
        listeners: vec!["http_main".to_string()],
        service: "".to_string(),
        ..Default::default()
      },
      super::Server {
        name: "server_b".to_string(),
        hostnames: vec!["*.example.com".to_string()],
        listeners: vec!["http_main".to_string()],
        service: "".to_string(),
        ..Default::default()
      },
    ],
    ..Default::default()
  };

  let mut collector = ConfigErrorCollector::new();
  let lm = MockListenerProps;
  validate_address_conflicts(&config, &mut collector, &lm);
  assert!(collector.has_errors());
  assert!(has_error_of_type(&collector, |e| matches!(
    e,
    ConfigError::HostnameConflict { .. }
  )));
}

#[test]
fn test_hostname_case_insensitive_conflict() {
  let config = super::Config {
    listeners: vec![super::ListenerConfig {
      name: "http_main".to_string(),
      kind: "http".to_string(),
      addresses: vec!["127.0.0.1:8080".to_string()],
      ..Default::default()
    }],
    servers: vec![
      super::Server {
        name: "server_a".to_string(),
        hostnames: vec!["API.EXAMPLE.COM".to_string()],
        listeners: vec!["http_main".to_string()],
        service: "".to_string(),
        ..Default::default()
      },
      super::Server {
        name: "server_b".to_string(),
        hostnames: vec!["api.example.com".to_string()],
        listeners: vec!["http_main".to_string()],
        service: "".to_string(),
        ..Default::default()
      },
    ],
    ..Default::default()
  };

  let mut collector = ConfigErrorCollector::new();
  let lm = MockListenerProps;
  validate_address_conflicts(&config, &mut collector, &lm);
  assert!(collector.has_errors());
  assert!(has_error_of_type(&collector, |e| matches!(
    e,
    ConfigError::HostnameConflict { .. }
  )));
}

#[test]
fn test_different_hostnames_no_conflict() {
  let config = super::Config {
    listeners: vec![super::ListenerConfig {
      name: "http_main".to_string(),
      kind: "http".to_string(),
      addresses: vec!["127.0.0.1:8080".to_string()],
      ..Default::default()
    }],
    servers: vec![
      super::Server {
        name: "server_a".to_string(),
        hostnames: vec!["api.example.com".to_string()],
        listeners: vec!["http_main".to_string()],
        service: "".to_string(),
        ..Default::default()
      },
      super::Server {
        name: "server_b".to_string(),
        hostnames: vec!["web.example.com".to_string()],
        listeners: vec!["http_main".to_string()],
        service: "".to_string(),
        ..Default::default()
      },
    ],
    ..Default::default()
  };

  let mut collector = ConfigErrorCollector::new();
  let lm = MockListenerProps;
  validate_address_conflicts(&config, &mut collector, &lm);
  let found = has_error_of_type(&collector, |e| {
    matches!(e, ConfigError::AddressConflict { .. })
  });
  assert!(!found);
}

#[test]
fn test_wildcard_and_exact_no_conflict() {
  let config = super::Config {
    listeners: vec![super::ListenerConfig {
      name: "http_main".to_string(),
      kind: "http".to_string(),
      addresses: vec!["127.0.0.1:8080".to_string()],
      ..Default::default()
    }],
    servers: vec![
      super::Server {
        name: "wildcard".to_string(),
        hostnames: vec!["*.example.com".to_string()],
        listeners: vec!["http_main".to_string()],
        service: "".to_string(),
        ..Default::default()
      },
      super::Server {
        name: "specific".to_string(),
        hostnames: vec!["api.example.com".to_string()],
        listeners: vec!["http_main".to_string()],
        service: "".to_string(),
        ..Default::default()
      },
    ],
    ..Default::default()
  };

  let mut collector = ConfigErrorCollector::new();
  let lm = MockListenerProps;
  validate_address_conflicts(&config, &mut collector, &lm);
  let found = has_error_of_type(&collector, |e| {
    matches!(e, ConfigError::AddressConflict { .. })
  });
  assert!(!found);
}

// =========================================================================
// validate_listener_references Tests
// =========================================================================

#[test]
fn test_validate_listener_references_valid() {
  let config = super::Config {
    listeners: vec![super::ListenerConfig {
      name: "http_main".to_string(),
      kind: "http".to_string(),
      addresses: vec!["127.0.0.1:8080".to_string()],
      ..Default::default()
    }],
    servers: vec![super::Server {
      name: "s1".to_string(),
      listeners: vec!["http_main".to_string()],
      service: "".to_string(),
      ..Default::default()
    }],
    ..Default::default()
  };
  let mut collector = ConfigErrorCollector::new();
  validate_listener_references(&config, &mut collector);
  assert!(
    !collector.has_errors(),
    "Valid reference should pass: {:?}",
    collector.errors()
  );
}

#[test]
fn test_validate_listener_references_not_found() {
  let config = super::Config {
    listeners: vec![],
    servers: vec![super::Server {
      name: "s1".to_string(),
      listeners: vec!["nonexistent".to_string()],
      service: "".to_string(),
      ..Default::default()
    }],
    ..Default::default()
  };
  let mut collector = ConfigErrorCollector::new();
  validate_listener_references(&config, &mut collector);
  assert!(collector.has_errors());
  assert!(matches!(
    &collector.errors()[0],
    ConfigError::NotFound { .. }
  ));
}
