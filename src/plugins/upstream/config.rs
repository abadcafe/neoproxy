//! module: plugins::upstream::config
//! responsibility: expose upstream configuration resolution
//! public operations: module reexports
//! data entities: none
//! tests: config_tests.rs

mod defaults;
#[cfg(test)]
mod defaults_tests;
pub(super) mod protocol;
pub(super) mod raw;
#[cfg(test)]
mod raw_tests;
mod resolved;
#[cfg(test)]
mod resolved_tests;
mod resolver;
#[cfg(test)]
mod resolver_tests;
mod validation;
#[cfg(test)]
mod validation_tests;

pub(crate) use raw::{
  CertificateConfig, UpstreamPluginConfig, UpstreamServiceArgs,
};
pub(crate) use resolved::{
  Address, ClientCertCredential, Protocol, Upstream,
};
pub(crate) use resolver::merge_chain_config;
#[cfg(test)]
pub(crate) use validation::validate_address_format;
