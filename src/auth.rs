//! Unified authentication module for neoproxy.

mod error;
mod user_password_auth;

pub use error::AuthError;
pub use user_password_auth::UserPasswordAuth;
