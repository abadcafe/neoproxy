//! module: fields
//! responsibility: group declared context fields by their owner
//! public operations: auth, upstream, dns, connection
//! data entities: none
//! tests: context_tests.rs and plugin tests
pub(crate) mod auth;
pub(crate) mod connection;
pub(crate) mod dns;
pub(crate) mod upstream;
