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

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_user_credential_deserialize() {
    let yaml = r#"
username: "admin"
password: "secret"
"#;
    let user: UserCredential = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(user.username, "admin");
    assert_eq!(user.password, "secret");
  }
}
