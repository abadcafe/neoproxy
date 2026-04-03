//! Unified authentication module for neoproxy.

mod config;
mod error;
mod password;
mod tls_cert;

#[allow(unused_imports)]
pub use config::UserCredential;
pub use config::{AuthConfig, AuthType};
pub use error::AuthError;
pub use password::verify_password;
pub use tls_cert::TlsClientCertVerifier;
