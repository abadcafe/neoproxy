//! module: config::auth
//! responsibility: deserialize configured user credentials without
//! exposing passwords
//! public operations: UserCredential, username, password
//! data entities: UserCredential
//! tests: auth_tests.rs

//! Authentication configuration types.

use serde::Deserialize;

/// User credential for password authentication.
#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct UserCredential {
  /// Username.
  username: String,
  /// Password (plaintext).
  password: String,
}

impl UserCredential {
  pub(crate) fn username(&self) -> &str {
    &self.username
  }

  pub(crate) fn password(&self) -> &str {
    &self.password
  }
}

impl std::fmt::Debug for UserCredential {
  fn fmt(
    &self,
    formatter: &mut std::fmt::Formatter<'_>,
  ) -> std::fmt::Result {
    formatter
      .debug_struct("UserCredential")
      .field("username", &self.username)
      .field("password", &"*")
      .finish()
  }
}
