//! Tests for CommandError Display and From implementations.

use std::io;

use super::command::CommandError;
use super::handshake::HandshakeError;

// ========== Display ==========

#[test]
fn test_command_error_display_command_not_supported() {
  let err = CommandError::CommandNotSupported { command: 0x02 };
  assert_eq!(err.to_string(), "command not supported: 0x02");
}

#[test]
fn test_command_error_display_unknown_command() {
  let err = CommandError::UnknownCommand { command: 0xff };
  assert_eq!(err.to_string(), "unknown command: 0xff");
}

#[test]
fn test_command_error_display_client_disconnected() {
  let err = CommandError::ClientDisconnected;
  assert_eq!(
    err.to_string(),
    "client disconnected during command processing"
  );
}

#[test]
fn test_command_error_display_io_error() {
  let io_err = io::Error::other("cmd error");
  let err = CommandError::IoError(io_err);
  assert!(
    err.to_string().contains("IO error during command processing")
  );
}

// ========== From<io::Error> ==========

#[test]
fn test_command_error_from_unexpected_eof() {
  let io_err = io::Error::new(io::ErrorKind::UnexpectedEof, "");
  let err = CommandError::from(io_err);
  assert!(matches!(err, CommandError::ClientDisconnected));
}

#[test]
fn test_command_error_from_connection_reset() {
  let io_err = io::Error::new(io::ErrorKind::ConnectionReset, "");
  let err = CommandError::from(io_err);
  assert!(matches!(err, CommandError::ClientDisconnected));
}

#[test]
fn test_command_error_from_broken_pipe() {
  let io_err = io::Error::new(io::ErrorKind::BrokenPipe, "");
  let err = CommandError::from(io_err);
  assert!(matches!(err, CommandError::ClientDisconnected));
}

#[test]
fn test_command_error_from_other_io_error() {
  let io_err = io::Error::new(io::ErrorKind::AddrInUse, "addr in use");
  let err = CommandError::from(io_err);
  assert!(matches!(err, CommandError::IoError(_)));
}

// ========== From<HandshakeError> ==========

#[test]
fn test_command_error_from_handshake_timeout() {
  let err = CommandError::from(HandshakeError::Timeout);
  assert!(matches!(err, CommandError::IoError(_)));
  assert!(err.to_string().contains("timed out"));
}

#[test]
fn test_command_error_from_handshake_invalid_version() {
  let err = CommandError::from(HandshakeError::InvalidVersion(4));
  assert!(matches!(err, CommandError::IoError(_)));
  assert!(err.to_string().contains("invalid SOCKS version"));
}

#[test]
fn test_command_error_from_handshake_method_not_acceptable() {
  let err =
    CommandError::from(HandshakeError::MethodNotAcceptable(vec![0xff]));
  assert!(matches!(err, CommandError::IoError(_)));
}

#[test]
fn test_command_error_from_handshake_client_disconnected() {
  let err = CommandError::from(HandshakeError::ClientDisconnected);
  assert!(matches!(err, CommandError::ClientDisconnected));
}

#[test]
fn test_command_error_from_handshake_io_error() {
  let io_err = io::Error::other("original");
  let err = CommandError::from(HandshakeError::IoError(io_err));
  assert!(matches!(err, CommandError::IoError(_)));
}

// ========== From<SocksServerError> ==========

#[test]
fn test_command_error_from_socks_unknown_command() {
  let socks_err =
    fast_socks5::server::SocksServerError::UnknownCommand(0x03);
  let err = CommandError::from(socks_err);
  assert!(matches!(
    err,
    CommandError::UnknownCommand { command: 0x03 }
  ));
}

#[test]
fn test_command_error_from_socks_auth_method_unacceptable() {
  let socks_err =
    fast_socks5::server::SocksServerError::AuthMethodUnacceptable(
      vec![],
    );
  let err = CommandError::from(socks_err);
  assert!(matches!(err, CommandError::IoError(_)));
}
