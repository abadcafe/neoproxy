//! Tests for H3RecvBody.
//!
//! H3RecvBody wraps an H3 `RequestStream<RecvStream, Bytes>` which
//! requires a real QUIC connection to construct. Its behavior is
//! covered by integration tests that start a real HTTP/3 listener.
