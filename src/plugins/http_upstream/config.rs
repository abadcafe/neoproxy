mod defaults;
#[cfg(test)]
mod defaults_tests;
mod raw;
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

#[cfg(test)]
pub(crate) use raw::UpstreamAddressConfig;
pub(crate) use raw::{
  CertificateConfig, HttpUpstreamPluginConfig, UpstreamServiceArgs,
};
#[cfg(test)]
pub(crate) use resolved::ProtocolKind;
pub(crate) use resolved::{ClientCertCredential, Protocol, Upstream};
pub(crate) use resolver::merge_chain_config;
#[cfg(test)]
pub(crate) use validation::validate_address_format;
