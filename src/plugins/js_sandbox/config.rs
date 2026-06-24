use serde::Deserialize;

/// Plugin-level configuration (from YAML `plugins.js_sandbox` section).
#[derive(Debug, Deserialize)]
pub(crate) struct PluginConfig {
  pub(crate) source_dir: String,
  #[serde(default = "default_worker_threads")]
  pub(crate) worker_threads: usize,
  #[serde(default = "default_cpu_limit_ms")]
  pub(crate) default_cpu_limit_ms: u64,
  #[serde(default = "default_mem_limit_mb")]
  pub(crate) default_mem_limit_mb: u64,
}

fn default_worker_threads() -> usize {
  100
}
fn default_cpu_limit_ms() -> u64 {
  5000
}
fn default_mem_limit_mb() -> u64 {
  128
}
