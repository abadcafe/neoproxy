//! module: config
//! responsibility: expose configuration parsing and validation
//! contracts
//! public operations: module reexports
//! data entities: none
//! tests: config_tests.rs

//! Configuration types, parsing, and validation.
//!
//! This module provides:
//! - Core configuration types (Config, Server, Service, ListenerConfig)
//! - Configuration parsing from YAML files
//! - Configuration validation with detailed error reporting
//! - `SerializedArgs` type for configuration data

mod args;
mod auth;
mod bindings;
#[cfg(test)]
mod bindings_tests;
mod document;
mod error;
mod listener;
mod listener_validation;
mod server;
#[cfg(test)]
mod server_tests;
mod service;
mod tls;
mod validate;

#[cfg(test)]
mod auth_tests;
#[cfg(test)]
mod error_tests;
#[cfg(test)]
mod listener_tests;
#[cfg(test)]
mod listener_validation_conflict_tests;
#[cfg(test)]
mod listener_validation_test_support;
#[cfg(test)]
mod listener_validation_test_support_tests;
#[cfg(test)]
mod listener_validation_tests;
#[cfg(test)]
mod service_tests;
#[cfg(test)]
mod tls_tests;
#[cfg(test)]
mod validate_tests;

pub(crate) use args::{EmptyArgs, SerializedArgs};
pub(crate) use auth::UserCredential;
pub(crate) use document::Config;
pub(crate) use error::{ConfigError, ConfigErrorCollector};
pub(crate) use listener::{
  ListenerConfig, ListenerPropertiesProvider, ListenerPropertyValues,
  TransportLayer,
};
pub(crate) use server::Server;
pub(crate) use tls::ServerTlsConfig;
