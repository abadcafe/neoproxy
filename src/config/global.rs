//! Global config singleton.

use std::sync::OnceLock;

use super::Config;

/// Global config instance, initialized via `Config::init_global()`.
static GLOBAL_CONFIG: OnceLock<Config> = OnceLock::new();

impl Config {
  /// Initialize the global config. Must be called before
  /// `Config::global()`.
  pub(crate) fn init_global(config: Config) {
    GLOBAL_CONFIG.set(config).ok();
  }

  pub(crate) fn global() -> &'static Config {
    GLOBAL_CONFIG.get().expect(
      "Config not initialized - call Config::init_global() first",
    )
  }
}
