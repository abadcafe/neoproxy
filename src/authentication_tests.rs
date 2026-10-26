use std::sync::Arc;

use crate::authentication::{Authentication, CredentialVerifier};

struct Password(&'static str);
impl CredentialVerifier for Password {
  fn accepts(&self, username: &str, password: &str) -> bool {
    username == "user" && password == self.0
  }
}

#[test]
fn test_authentication_anonymous_policy() {
  let authentication = Authentication::default();
  assert!(!authentication.requires_credentials());
  assert!(authentication.accepts("", ""));
}

#[test]
fn test_authentication_requires_every_composed_verifier() {
  let authentication =
    Authentication::default().require(Arc::new(Password("secret")));
  assert!(authentication.requires_credentials());
  assert!(authentication.accepts("user", "secret"));
  assert!(!authentication.accepts("user", "wrong"));
  let combined =
    authentication.clone().require(Arc::new(Password("different")));
  assert!(!combined.accepts("user", "secret"));
  assert!(authentication.accepts("user", "secret"));
}
