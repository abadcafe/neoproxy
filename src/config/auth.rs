//! Authentication configuration types.

use serde::Deserialize;

/// User credential for password authentication.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UserCredential {
  /// Username.
  pub username: String,
  /// Password (plaintext).
  pub password: String,
}
