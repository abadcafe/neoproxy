//! Tests for HTTP/3 stream handling.
//!
//! `handle_h3_stream`, `send_h3_response`, and `handle_h3_connection`
//! all require a real QUIC connection and H3 server to construct their
//! parameters (`h3::server::RequestStream`, `h3_quinn::BidiStream`).
//! Their behavior is covered by integration tests that start a real
//! HTTP/3 listener and send actual QUIC requests.
