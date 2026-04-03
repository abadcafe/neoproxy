//! Authentication error types.

use std::fmt;

/// Authentication error types.
#[derive(Debug, Clone)]
pub enum AuthError {
  /// Invalid username or password.
  InvalidCredentials,
  /// User not found.
  UserNotFound(String),
  /// Configuration error.
  ConfigError(String),
  /// TLS client certificate verification failed.
  TlsCertError(String),
  /// Authentication type not supported by listener.
  UnsupportedAuthType(String),
}

impl fmt::Display for AuthError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::InvalidCredentials => write!(f, "invalid credentials"),
      Self::UserNotFound(user) => write!(f, "user not found: {}", user),
      Self::ConfigError(msg) => write!(f, "auth config error: {}", msg),
      Self::TlsCertError(msg) => write!(f, "TLS cert error: {}", msg),
      Self::UnsupportedAuthType(t) => {
        write!(f, "unsupported auth type: {}", t)
      }
    }
  }
}

impl std::error::Error for AuthError {}
