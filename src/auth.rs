//! Unified authentication module for neoproxy.

mod error;
pub mod listener_auth_config;
mod user_password_auth;

pub use error::AuthError;
pub use listener_auth_config::{ListenerAuthConfig, UserCredential};
pub use user_password_auth::UserPasswordAuth;

#[cfg(test)]
mod module_structure_tests {
  #[test]
  fn test_new_types_are_accessible() {
    let _: Option<super::ListenerAuthConfig> = None;
    let _: Option<super::UserCredential> = None;
    let _: Option<super::UserPasswordAuth> = None;
  }
}
