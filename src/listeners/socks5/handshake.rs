//! module: listeners::socks5::handshake
//! responsibility: negotiate authenticated SOCKS5 sessions
//! public operations: DEFAULT_HANDSHAKE_TIMEOUT, HandshakeResult,
//! HandshakeError, perform_handshake
//! data entities: HandshakeResult, HandshakeError
//! tests: handshake_tests.rs

//! SOCKS5 handshake protocol handling.

use std::time::Duration;

use crate::authentication::Authentication;

/// Default handshake timeout.
pub(super) const DEFAULT_HANDSHAKE_TIMEOUT: Duration =
  Duration::from_secs(3);

/// Result of a successful SOCKS5 handshake.
///
/// Contains the completed subnegotiation and optional credentials.
/// Credentials have passed the composed service policy before success.
pub(super) struct HandshakeResult {
  /// Subnegotiation completed after credential verification.
  pub(super) proto: fast_socks5::server::Socks5ServerProtocol<
    tokio::net::TcpStream,
    fast_socks5::server::states::Authenticated,
  >,
  /// The username if password authentication was used.
  pub(super) username: Option<String>,
  /// The password if password authentication was used.
  pub(super) password: Option<String>,
}

impl std::fmt::Debug for HandshakeResult {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("HandshakeResult")
      .field("username", &self.username)
      .field("password", &"*")
      .finish_non_exhaustive()
  }
}

/// Error during SOCKS5 handshake.
///
/// This enum represents the various errors that can occur during
/// the SOCKS5 handshake process.
#[derive(Debug)]
pub(crate) enum HandshakeError {
  /// Handshake timed out.
  Timeout,

  /// Invalid SOCKS version number.
  InvalidVersion(u8),

  /// Authentication method not acceptable.
  MethodNotAcceptable(Vec<u8>),

  InvalidCredentials,

  /// Client disconnected during handshake.
  ClientDisconnected,

  /// IO error during handshake.
  IoError(std::io::Error),
}

impl std::fmt::Display for HandshakeError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Timeout => write!(f, "handshake timed out"),
      Self::InvalidVersion(v) => {
        write!(f, "invalid SOCKS version: {}", v)
      }
      Self::MethodNotAcceptable(methods) => {
        write!(f, "authentication method not acceptable: {:?}", methods)
      }
      Self::InvalidCredentials => write!(f, "invalid credentials"),
      Self::ClientDisconnected => {
        write!(f, "client disconnected during handshake")
      }
      Self::IoError(e) => write!(f, "IO error during handshake: {}", e),
    }
  }
}

impl std::error::Error for HandshakeError {}

impl From<std::io::Error> for HandshakeError {
  fn from(e: std::io::Error) -> Self {
    use std::io::ErrorKind;
    match e.kind() {
      ErrorKind::UnexpectedEof
      | ErrorKind::ConnectionReset
      | ErrorKind::BrokenPipe => Self::ClientDisconnected,
      _ => Self::IoError(e),
    }
  }
}

impl From<fast_socks5::server::SocksServerError> for HandshakeError {
  fn from(e: fast_socks5::server::SocksServerError) -> Self {
    use fast_socks5::server::SocksServerError;
    match e {
      SocksServerError::UnsupportedSocksVersion(v) => {
        Self::InvalidVersion(v)
      }
      SocksServerError::AuthMethodUnacceptable(methods) => {
        Self::MethodNotAcceptable(methods)
      }
      SocksServerError::Io { source, .. } => Self::from(source),
      _ => Self::IoError(std::io::Error::other(e.to_string())),
    }
  }
}

/// Performs SOCKS5 handshake with timeout protection.
///
/// Executes the complete SOCKS5 handshake process:
/// 1. Version negotiation
/// 2. Authentication method selection
/// 3. Credential collection and subnegotiation acknowledgement
pub(super) async fn perform_handshake(
  stream: tokio::net::TcpStream,
  timeout_duration: Duration,
  authentication: &Authentication,
) -> Result<HandshakeResult, HandshakeError> {
  let handshake_fut = async {
    let proto =
      fast_socks5::server::Socks5ServerProtocol::start(stream);

    let auth_state = proto
      .negotiate_auth(
        fast_socks5::server::StandardAuthentication::allow_no_auth(
          !authentication.requires_credentials(),
        ),
      )
      .await?;

    match auth_state {
      fast_socks5::server::StandardAuthenticationStarted::NoAuthentication(
        none_state,
      ) => {
        let authenticated =
          fast_socks5::server::Socks5ServerProtocol::finish_auth(
            none_state,
          );
        Ok(HandshakeResult {
          proto: authenticated,
          username: None,
          password: None,
        })
      }
      fast_socks5::server::StandardAuthenticationStarted::PasswordAuthentication(
        auth_state,
      ) => {
        let (username, password, auth_impl) =
          auth_state.read_username_password().await?;

        if !authentication.accepts(&username, &password) {
          auth_impl.reject().await?;
          return Err(HandshakeError::InvalidCredentials);
        }
        let finished = auth_impl.accept().await?;
        let authenticated =
          fast_socks5::server::Socks5ServerProtocol::finish_auth(
            finished,
          );

        tracing::info!(
          "SOCKS5 credentials verified for user {:?}",
          username
        );

        Ok(HandshakeResult {
          proto: authenticated,
          username: Some(username),
          password: Some(password),
        })
      }
    }
  };

  match tokio::time::timeout(timeout_duration, handshake_fut).await {
    Ok(result) => result,
    Err(_) => {
      tracing::warn!(
        "SOCKS5 handshake timed out after {:?}",
        timeout_duration
      );
      Err(HandshakeError::Timeout)
    }
  }
}
