//! Access log entry types.

use std::collections::HashMap;

use time::OffsetDateTime;

/// A complete access log entry ready for formatting.
#[derive(Debug, Clone)]
pub(crate) struct AccessLogEntry {
  pub(crate) time: OffsetDateTime,
  pub(crate) client_ip: String,
  pub(crate) client_port: u16,
  pub(crate) server_ip: String,
  pub(crate) server_port: u16,
  pub(crate) method: String,
  pub(crate) target: String,
  pub(crate) status: u16,
  pub(crate) duration_ms: u64,
  pub(crate) service: String,
  pub(crate) err: Option<String>,
  pub(crate) extensions: HashMap<String, String>,
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
pub(crate) enum LogFormat {
  #[default]
  Text,
  Json,
}
