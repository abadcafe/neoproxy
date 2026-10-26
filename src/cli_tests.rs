//! Black-box tests for the cli module.

use clap::Parser;

use crate::cli::CmdOpt;

#[test]
fn test_parse_default_config_file() {
  let opt = CmdOpt::parse_from(["neoproxy"]);

  assert_eq!(opt.config_file(), "conf/server.yaml");
}

#[test]
fn test_parse_short_config_file() {
  let opt = CmdOpt::parse_from(["neoproxy", "-c", "conf/test.yaml"]);

  assert_eq!(opt.config_file(), "conf/test.yaml");
}

#[test]
fn test_parse_long_config_file() {
  let opt =
    CmdOpt::parse_from(["neoproxy", "--config", "conf/test.yaml"]);

  assert_eq!(opt.config_file(), "conf/test.yaml");
}

#[test]
fn test_parse_version_flags_display_version_without_configuration() {
  for flag in ["-v", "--version"] {
    let result = CmdOpt::try_parse_from(["neoproxy", flag]);
    let error = result.unwrap_err();
    assert_eq!(error.kind(), clap::error::ErrorKind::DisplayVersion);
    assert_eq!(
      error.to_string(),
      format!("neoproxy {}\n", env!("CARGO_PKG_VERSION"))
    );
  }
}

#[test]
fn test_global_returns_lazy_options() {
  let _ = CmdOpt::global();
}
