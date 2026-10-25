//! Tests for HTTP/3 stream handling.
//!
//! The stream handler and response writer require a real QUIC
//! connection and H3 server to construct their parameters
//! (`h3::server::RequestStream`, `h3_quinn::BidiStream`).
//! Their behavior is covered by integration tests that start a real
//! HTTP/3 listener and send actual QUIC requests.
