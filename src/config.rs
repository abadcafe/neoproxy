use std::{fs, sync};

use anyhow::{Context, Result};
use clap::Parser;
use serde::Deserialize;

#[derive(Parser, Debug)]
pub struct CmdOpt {
  /// Sets a custom config file
  #[arg(
    short,
    long = "config",
    value_name = "CONFIG_FILE",
    default_value_t = String::from("conf/server.yaml")
  )]
  pub config_file: String,

  /// Gets version
  #[arg(short, long = "version")]
  pub version: bool,
}

impl CmdOpt {
  pub fn global() -> &'static sync::LazyLock<CmdOpt> {
    static CMD_OPT: sync::LazyLock<CmdOpt> =
      sync::LazyLock::new(|| CmdOpt::parse());
    &CMD_OPT
  }
}

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
pub struct Listener {
  pub kind: String,
  pub args: serde_yaml::Value,
}

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
pub struct Server {
  pub name: String,
  pub listeners: Vec<Listener>,
  pub service: String,
}

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
pub struct Layer {
  pub kind: String,
  // delegate the deserializition to layer factories
  pub args: serde_yaml::Value,
}

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
pub struct Service {
  pub name: String,
  pub kind: String,
  // delegate the deserializition to service factories.
  pub args: serde_yaml::Value,
  pub layers: Vec<Layer>,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(default)]
pub struct Config {
  pub worker_threads: usize,
  pub log_directory: String,
  pub services: Vec<Service>,
  pub servers: Vec<Server>,
}

impl Default for Config {
  fn default() -> Self {
    Self {
      worker_threads: 1,
      log_directory: String::from("logs/"),
      services: vec![],
      servers: vec![],
    }
  }
}

impl Config {
  pub fn parse_string(&mut self, s: &str) -> Result<()> {
    let de = serde_yaml::Deserializer::from_str(s);
    Deserialize::deserialize_in_place(de, self)
      .with_context(|| format!("parse config text failed"))?;
    Ok(())
  }

  pub fn parse_file(&mut self, path: &str) -> Result<()> {
    let s = fs::read_to_string(std::path::Path::new(path))
      .with_context(|| format!("read config file '{}' failed", path))?;
    self.parse_string(&s)?;
    Ok(())
  }

  pub fn new(conf_path: &str) -> Config {
    let mut config: Config = Default::default();
    config.parse_file(conf_path).expect(
      format!("parse config file '{}' failed", conf_path).as_str(),
    );
    config
  }

  pub fn global() -> &'static sync::LazyLock<Config> {
    static CONFIG: sync::LazyLock<Config> = sync::LazyLock::new(|| {
      Config::new(&CmdOpt::global().config_file)
    });
    &CONFIG
  }
}
