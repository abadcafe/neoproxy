mod defaults;
mod raw;
mod resolved;
mod resolver;
mod validation;

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
