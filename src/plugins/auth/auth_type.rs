//! Authentication type for the auth plugin.

/// Authentication type used for the request.
/// Internal to auth plugin - written as string to RequestContext.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AuthType {
  #[default]
  None,
  Password,
}

impl std::fmt::Display for AuthType {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      AuthType::None => write!(f, "none"),
      AuthType::Password => write!(f, "password"),
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_auth_type_default_is_none() {
    let at = AuthType::default();
    assert_eq!(at, AuthType::None);
  }

  #[test]
  fn test_auth_type_to_string_none() {
    assert_eq!(AuthType::None.to_string(), "none");
  }

  #[test]
  fn test_auth_type_to_string_password() {
    assert_eq!(AuthType::Password.to_string(), "password");
  }

  #[test]
  fn test_auth_type_clone() {
    let at = AuthType::Password;
    let cloned = at;
    assert_eq!(at, cloned);
  }

  #[test]
  fn test_auth_type_display() {
    // Use Display trait (format! macro), not ToString directly
    assert_eq!(format!("{}", AuthType::None), "none");
    assert_eq!(format!("{}", AuthType::Password), "password");
  }
}
