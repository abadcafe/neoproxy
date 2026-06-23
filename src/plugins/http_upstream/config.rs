mod defaults;
mod raw;
mod resolved;
mod resolver;
mod validation;

pub(crate) use raw::{
  CertificateConfig, HttpUpstreamPluginConfig, UpstreamServiceArgs,
};
pub(crate) use resolved::{ClientCertCredential, Protocol, Upstream};
pub(crate) use resolver::merge_chain_config;

#[cfg(test)]
pub(crate) use raw::UpstreamAddressConfig;
#[cfg(test)]
pub(crate) use resolved::ProtocolKind;
#[cfg(test)]
pub(crate) use validation::validate_address_format;
