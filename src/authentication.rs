//! module: authentication
//! responsibility: compose credential requirements independently of
//! transport public operations: CredentialVerifier,
//! Authentication::{require, requires_credentials, accepts}
//! data entities: Authentication
//! tests: authentication_tests.rs

use std::sync::Arc;

pub(crate) trait CredentialVerifier: Send + Sync {
  fn accepts(&self, username: &str, password: &str) -> bool;
}

#[derive(Clone, Default)]
pub(crate) struct Authentication {
  verifiers: Arc<[Arc<dyn CredentialVerifier>]>,
}

impl Authentication {
  pub(crate) fn require(
    &self,
    verifier: Arc<dyn CredentialVerifier>,
  ) -> Self {
    let mut verifiers = self.verifiers.to_vec();
    verifiers.push(verifier);
    Self { verifiers: verifiers.into() }
  }

  pub(crate) fn requires_credentials(&self) -> bool {
    !self.verifiers.is_empty()
  }

  pub(crate) fn accepts(&self, username: &str, password: &str) -> bool {
    self
      .verifiers
      .iter()
      .all(|verifier| verifier.accepts(username, password))
  }
}
