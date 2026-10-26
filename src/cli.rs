//! module: cli
//! responsibility: parse process command-line actions
//! public operations: CmdOpt, global, config_file
//! data entities: CmdOpt
//! tests: cli_tests.rs

//! Command line options.

use std::sync::LazyLock;

use clap::Parser;

/// Command line options.
#[derive(Parser, Debug)]
#[command(version, disable_version_flag = true)]
#[command(arg(clap::Arg::new("version")
  .short('v')
  .long("version")
  .action(clap::ArgAction::Version)
  .help("Show version")))]
pub(crate) struct CmdOpt {
  /// Sets a custom config file
  #[arg(
    short,
    long = "config",
    value_name = "CONFIG_FILE",
    default_value_t = String::from("conf/server.yaml")
  )]
  config_file: String,
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
