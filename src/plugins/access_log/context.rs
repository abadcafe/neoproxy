//! Access log entry types.

use std::collections::HashMap;

use time::OffsetDateTime;

/// A complete access log entry ready for formatting.
#[derive(Debug, Clone)]
pub struct AccessLogEntry {
  pub time: OffsetDateTime,
  pub client_ip: String,
  pub client_port: u16,
  pub server_ip: String,
  pub server_port: u16,
  pub method: String,
  pub target: String,
  pub status: u16,
  pub duration_ms: u64,
  pub service: String,
  pub err: Option<String>,
  pub extensions: HashMap<String, String>,
}

/// Log format type.
#[derive(
  Debug,
  Clone,
  Copy,
  PartialEq,
  Eq,
  Default,
  serde::Deserialize,
  serde::Serialize,
)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
  #[default]
  Text,
  Json,
}
