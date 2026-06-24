//! Command line options.

use std::sync::LazyLock;

use clap::Parser;

/// Command line options.
#[derive(Parser, Debug)]
pub(crate) struct CmdOpt {
  /// Sets a custom config file
  #[arg(
    short,
    long = "config",
    value_name = "CONFIG_FILE",
    default_value_t = String::from("conf/server.yaml")
  )]
  config_file: String,

  /// Gets version
  #[arg(short, long = "version")]
  version: bool,
}

impl CmdOpt {
  pub(crate) fn global() -> &'static LazyLock<CmdOpt> {
    static CMD_OPT: LazyLock<CmdOpt> = LazyLock::new(CmdOpt::parse);
    &CMD_OPT
  }

  pub(crate) fn config_file(&self) -> &str {
    &self.config_file
  }
}
