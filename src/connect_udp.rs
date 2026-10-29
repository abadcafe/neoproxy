//! module: connect_udp
//! responsibility: adapt RFC 9298 UDP tunnels to bounded capsule I/O
//! public operations: capsule, request, direct, h3
//! data entities: none
//! tests: connect_udp_tests.rs and CONNECT-UDP process contracts
mod bridge;
pub(crate) mod capsule;
pub(crate) mod direct;
pub(crate) mod h3;
pub(crate) mod request;
