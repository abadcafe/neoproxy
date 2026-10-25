//! module: args
//! responsibilities: define the serialized plugin configuration
//! boundary public operations: SerializedArgs
//! data entities: SerializedArgs
//! tests: configuration parser and builder tests
pub(crate) type SerializedArgs = serde_yaml::Value;

/// A schema for components that accept no configuration fields.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EmptyArgs {}
