//! Authentication error types.

use std::fmt;

/// Authentication error types.
#[derive(Debug, Clone)]
pub enum AuthError {
  /// Invalid username or password.
  /// CR-009: All authentication failures return this variant to avoid
  /// leaking information about whether a username exists.
  InvalidCredentials,
  /// Configuration error.
  ConfigError(String),
}

impl fmt::Display for AuthError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::InvalidCredentials => write!(f, "invalid credentials"),
      Self::ConfigError(msg) => write!(f, "auth config error: {}", msg),
    }
  }
}

impl std::error::Error for AuthError {}
