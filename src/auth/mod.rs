//! Unified authentication module for neoproxy.

mod client_cert_auth;
mod error;
pub mod listener_auth_config;
mod password;
mod tls_cert;
mod user_password_auth;

pub use client_cert_auth::ClientCertAuth;
pub use error::AuthError;
pub use listener_auth_config::{ListenerAuthConfig, UserCredential};
pub use password::verify_password;
#[allow(unused_imports)]
pub use tls_cert::TlsClientCertVerifier;
pub use user_password_auth::UserPasswordAuth;

#[cfg(test)]
mod module_structure_tests {
  #[test]
  fn test_new_types_are_accessible() {
    let _: Option<super::ListenerAuthConfig> = None;
    let _: Option<super::UserCredential> = None;
    let _: Option<super::UserPasswordAuth> = None;
    let _: Option<super::ClientCertAuth> = None;
  }
}
