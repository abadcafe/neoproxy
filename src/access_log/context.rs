use std::collections::HashMap;
use std::net::SocketAddr;

use time::OffsetDateTime;

/// Authentication type used for the request.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AuthType {
  #[default]
  None,
  Password,
}

/// Service-provided metrics (key-value pairs).
#[derive(Debug, Clone, Default)]
pub struct ServiceMetrics {
  metrics: HashMap<String, String>,
}

impl ServiceMetrics {
  pub fn new() -> Self {
    Self::default()
  }

  pub fn add(&mut self, key: impl Into<String>, value: impl ToString) {
    self.metrics.insert(key.into(), value.to_string());
  }

  pub fn iter(&self) -> impl Iterator<Item = (&String, &String)> {
    self.metrics.iter()
  }
}

/// A complete access log entry ready for formatting.
#[derive(Debug, Clone)]
pub struct AccessLogEntry {
  pub time: OffsetDateTime,
  pub client_ip: String,
  pub client_port: u16,
  pub user: Option<String>,
  pub auth_type: AuthType,
  pub method: String,
  pub target: String,
  pub status: u16,
  pub duration_ms: u64,
  pub service: String,
  pub service_metrics: ServiceMetrics,
}

/// Parameters for recording an HTTP access log entry.
///
/// Bundles request/response information to avoid functions with too many
/// arguments. Used by listeners to pass access log data.
#[derive(Debug, Clone)]
pub struct HttpAccessLogParams {
  pub client_addr: SocketAddr,
  pub user: Option<String>,
  pub auth_type: AuthType,
  pub method: String,
  pub target: String,
  pub status: u16,
  pub duration: std::time::Duration,
  pub service_name: String,
  pub service_metrics: ServiceMetrics,
}

#[cfg(test)]
mod tests {
  use super::*;

  // ============== AuthType Tests ==============

  #[test]
  fn test_auth_type_default_is_none() {
    let at = AuthType::default();
    assert_eq!(at, AuthType::None);
  }

  #[test]
  fn test_auth_type_variants() {
    assert_eq!(AuthType::None, AuthType::None);
    assert_eq!(AuthType::Password, AuthType::Password);
    assert_ne!(AuthType::None, AuthType::Password);
  }

  #[test]
  fn test_auth_type_clone() {
    let at = AuthType::Password;
    let cloned = at;
    assert_eq!(at, cloned);
  }

  // ============== ServiceMetrics Tests ==============

  #[test]
  fn test_service_metrics_new_is_empty() {
    let sm = ServiceMetrics::new();
    assert!(sm.iter().next().is_none());
  }

  #[test]
  fn test_service_metrics_add_and_iter() {
    let mut sm = ServiceMetrics::new();
    sm.add("dns_ms", 5u64);
    sm.add("connect_ms", 10u64);
    assert!(sm.iter().next().is_some());

    let collected: HashMap<&String, &String> = sm.iter().collect();
    assert_eq!(collected.len(), 2);
    assert_eq!(
      collected.get(&"dns_ms".to_string()),
      Some(&&"5".to_string())
    );
    assert_eq!(
      collected.get(&"connect_ms".to_string()),
      Some(&&"10".to_string())
    );
  }

  #[test]
  fn test_service_metrics_default() {
    let sm = ServiceMetrics::default();
    assert!(sm.iter().next().is_none());
  }

  #[test]
  fn test_service_metrics_clone() {
    let mut sm = ServiceMetrics::new();
    sm.add("key", "value");
    let cloned = sm.clone();
    assert!(cloned.iter().next().is_some());
  }

  // ============== AccessLogEntry Tests ==============

  #[test]
  fn test_access_log_entry_creation() {
    let entry = AccessLogEntry {
      time: OffsetDateTime::now_utc(),
      client_ip: "192.168.1.1".to_string(),
      client_port: 54321,
      user: Some("admin".to_string()),
      auth_type: AuthType::Password,
      method: "CONNECT".to_string(),
      target: "example.com:443".to_string(),
      status: 200,
      duration_ms: 50,
      service: "tunnel".to_string(),
      service_metrics: ServiceMetrics::new(),
    };
    assert_eq!(entry.client_ip, "192.168.1.1");
    assert_eq!(entry.client_port, 54321);
    assert_eq!(entry.method, "CONNECT");
    assert_eq!(entry.target, "example.com:443");
    assert_eq!(entry.status, 200);
    assert_eq!(entry.duration_ms, 50);
    assert_eq!(entry.service, "tunnel");
  }

  #[test]
  fn test_access_log_entry_no_user() {
    let entry = AccessLogEntry {
      time: OffsetDateTime::now_utc(),
      client_ip: "10.0.0.1".to_string(),
      client_port: 1234,
      user: None,
      auth_type: AuthType::None,
      method: "CONNECT".to_string(),
      target: "example.com:80".to_string(),
      status: 502,
      duration_ms: 1000,
      service: "tunnel".to_string(),
      service_metrics: ServiceMetrics::new(),
    };
    assert!(entry.user.is_none());
    assert_eq!(entry.status, 502);
  }

  #[test]
  fn test_access_log_entry_debug_impl() {
    let entry = AccessLogEntry {
      time: OffsetDateTime::now_utc(),
      client_ip: "192.168.1.1".to_string(),
      client_port: 54321,
      user: Some("admin".to_string()),
      auth_type: AuthType::Password,
      method: "CONNECT".to_string(),
      target: "example.com:443".to_string(),
      status: 200,
      duration_ms: 50,
      service: "tunnel".to_string(),
      service_metrics: ServiceMetrics::new(),
    };
    let debug_str = format!("{:?}", entry);
    assert!(debug_str.contains("AccessLogEntry"));
    assert!(debug_str.contains("client_ip"));
    assert!(debug_str.contains("192.168.1.1"));
    assert!(debug_str.contains("CONNECT"));
    assert!(debug_str.contains("example.com:443"));
  }

  #[test]
  fn test_access_log_entry_clone_impl() {
    let entry = AccessLogEntry {
      time: OffsetDateTime::now_utc(),
      client_ip: "192.168.1.1".to_string(),
      client_port: 54321,
      user: Some("admin".to_string()),
      auth_type: AuthType::Password,
      method: "CONNECT".to_string(),
      target: "example.com:443".to_string(),
      status: 200,
      duration_ms: 50,
      service: "tunnel".to_string(),
      service_metrics: ServiceMetrics::new(),
    };
    let cloned = entry.clone();
    assert_eq!(entry.client_ip, cloned.client_ip);
    assert_eq!(entry.status, cloned.status);
    assert_eq!(entry.method, cloned.method);
  }

  // ============== HttpAccessLogParams Tests ==============

  #[test]
  fn test_http_access_log_params_creation() {
    use std::time::Duration;

    let params = HttpAccessLogParams {
      client_addr: "192.168.1.1:54321".parse().unwrap(),
      user: Some("admin".to_string()),
      auth_type: AuthType::Password,
      method: "CONNECT".to_string(),
      target: "example.com:443".to_string(),
      status: 200,
      duration: Duration::from_millis(50),
      service_name: "tunnel".to_string(),
      service_metrics: ServiceMetrics::new(),
    };
    assert_eq!(
      params.client_addr,
      "192.168.1.1:54321".parse().unwrap()
    );
    assert_eq!(params.user, Some("admin".to_string()));
    assert_eq!(params.auth_type, AuthType::Password);
    assert_eq!(params.method, "CONNECT");
    assert_eq!(params.target, "example.com:443");
    assert_eq!(params.status, 200);
    assert_eq!(params.duration, Duration::from_millis(50));
    assert_eq!(params.service_name, "tunnel");
  }

  #[test]
  fn test_http_access_log_params_no_user() {
    use std::time::Duration;

    let params = HttpAccessLogParams {
      client_addr: "10.0.0.1:1234".parse().unwrap(),
      user: None,
      auth_type: AuthType::None,
      method: "GET".to_string(),
      target: "http://example.com".to_string(),
      status: 404,
      duration: Duration::from_millis(100),
      service_name: "proxy".to_string(),
      service_metrics: ServiceMetrics::new(),
    };
    assert!(params.user.is_none());
    assert_eq!(params.auth_type, AuthType::None);
    assert_eq!(params.status, 404);
  }

  #[test]
  fn test_http_access_log_params_clone() {
    use std::time::Duration;

    let params = HttpAccessLogParams {
      client_addr: "192.168.1.1:54321".parse().unwrap(),
      user: Some("admin".to_string()),
      auth_type: AuthType::Password,
      method: "CONNECT".to_string(),
      target: "example.com:443".to_string(),
      status: 200,
      duration: Duration::from_millis(50),
      service_name: "tunnel".to_string(),
      service_metrics: ServiceMetrics::new(),
    };
    let cloned = params.clone();
    assert_eq!(params.client_addr, cloned.client_addr);
    assert_eq!(params.user, cloned.user);
    assert_eq!(params.method, cloned.method);
    assert_eq!(params.status, cloned.status);
  }

  #[test]
  fn test_http_access_log_params_debug_impl() {
    use std::time::Duration;

    let params = HttpAccessLogParams {
      client_addr: "192.168.1.1:54321".parse().unwrap(),
      user: Some("admin".to_string()),
      auth_type: AuthType::Password,
      method: "CONNECT".to_string(),
      target: "example.com:443".to_string(),
      status: 200,
      duration: Duration::from_millis(50),
      service_name: "tunnel".to_string(),
      service_metrics: ServiceMetrics::new(),
    };
    let debug_str = format!("{:?}", params);
    assert!(debug_str.contains("HttpAccessLogParams"));
    assert!(debug_str.contains("client_addr"));
    assert!(debug_str.contains("auth_type"));
  }
}
