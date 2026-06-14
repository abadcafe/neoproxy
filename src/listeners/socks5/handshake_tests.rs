//! Tests for HandshakeError Display and From implementations.

use std::io;

use super::handshake::HandshakeError;

// ========== Display ==========

#[test]
fn test_handshake_error_display_timeout() {
  let err = HandshakeError::Timeout;
  assert_eq!(err.to_string(), "handshake timed out");
}

#[test]
fn test_handshake_error_display_invalid_version() {
  let err = HandshakeError::InvalidVersion(4);
  assert_eq!(err.to_string(), "invalid SOCKS version: 4");
}

#[test]
fn test_handshake_error_display_method_not_acceptable() {
  let err = HandshakeError::MethodNotAcceptable(vec![0x01, 0x02]);
  assert!(err.to_string().contains("authentication method not acceptable"));
}

#[test]
fn test_handshake_error_display_client_disconnected() {
  let err = HandshakeError::ClientDisconnected;
  assert_eq!(err.to_string(), "client disconnected during handshake");
}

#[test]
fn test_handshake_error_display_io_error() {
  let io_err = io::Error::new(io::ErrorKind::Other, "test error");
  let err = HandshakeError::IoError(io_err);
  assert!(err.to_string().contains("IO error during handshake"));
  assert!(err.to_string().contains("test error"));
}

// ========== From<io::Error> ==========

#[test]
fn test_handshake_error_from_unexpected_eof() {
  let io_err = io::Error::new(io::ErrorKind::UnexpectedEof, "");
  let err = HandshakeError::from(io_err);
  assert!(matches!(err, HandshakeError::ClientDisconnected));
}

#[test]
fn test_handshake_error_from_connection_reset() {
  let io_err = io::Error::new(io::ErrorKind::ConnectionReset, "");
  let err = HandshakeError::from(io_err);
  assert!(matches!(err, HandshakeError::ClientDisconnected));
}

#[test]
fn test_handshake_error_from_broken_pipe() {
  let io_err = io::Error::new(io::ErrorKind::BrokenPipe, "");
  let err = HandshakeError::from(io_err);
  assert!(matches!(err, HandshakeError::ClientDisconnected));
}

#[test]
fn test_handshake_error_from_other_io_error() {
  let io_err = io::Error::new(io::ErrorKind::TimedOut, "timeout");
  let err = HandshakeError::from(io_err);
  assert!(matches!(err, HandshakeError::IoError(_)));
}

// ========== From<SocksServerError> ==========

#[test]
fn test_handshake_error_from_socks_unsupported_version() {
  let socks_err =
    fast_socks5::server::SocksServerError::UnsupportedSocksVersion(4);
  let err = HandshakeError::from(socks_err);
  assert!(matches!(err, HandshakeError::InvalidVersion(4)));
}

#[test]
fn test_handshake_error_from_socks_auth_method_unacceptable() {
  let socks_err =
    fast_socks5::server::SocksServerError::AuthMethodUnacceptable(
      vec![0x00],
    );
  let err = HandshakeError::from(socks_err);
  assert!(
    matches!(err, HandshakeError::MethodNotAcceptable(ref m) if m == &vec![0x00])
  );
}
