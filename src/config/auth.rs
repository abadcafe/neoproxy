//! Authentication configuration types.

use serde::Deserialize;

/// User credential for password authentication.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct UserCredential {
  /// Username.
  username: String,
  /// Password (plaintext).
  password: String,
}

impl UserCredential {
  #[cfg(test)]
  pub(crate) fn new(username: String, password: String) -> Self {
    Self { username, password }
  }

  pub(crate) fn username(&self) -> &str {
    &self.username
  }

  pub(crate) fn password(&self) -> &str {
    &self.password
  }
}
