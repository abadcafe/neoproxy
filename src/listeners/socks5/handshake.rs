//! module: listeners::socks5::handshake
//! responsibility: negotiate SOCKS5 methods and collect unverified
//! credentials public operations:
//! HandshakeResult, HandshakeError, perform_handshake
//! data entities: HandshakeResult, HandshakeError
//! tests: handshake_tests.rs

//! SOCKS5 handshake protocol handling.

use fast_socks5::server::StandardAuthentication;
use tokio::time::Instant;

/// Result of a successful SOCKS5 handshake.
///
/// Contains the completed subnegotiation and optional credentials.
/// Credentials are collected only; auth.basic_auth decides CONNECT
/// admission.
pub(super) struct HandshakeResult {
  /// Subnegotiation acknowledged receipt, without credential
  /// verification.
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

  /// Credentials cannot be represented by HTTP Basic.
  InvalidCredentialFormat(&'static str),

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
      Self::InvalidCredentialFormat(reason) => {
        write!(f, "invalid Basic credential format: {reason}")
      }
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
  deadline: Instant,
) -> Result<HandshakeResult, HandshakeError> {
  let handshake_fut = async {
    let proto =
      fast_socks5::server::Socks5ServerProtocol::start(stream);

    // PRODUCT CONTRACT: SOCKS5 and HTTP share one request middleware
    // pipeline. This listener MUST NOT verify account/password
    // correctness or inspect auth policy. Basic syntax checks are
    // protocol adaptation. Prefer password when offered to carry
    // credentials into CONNECT; otherwise accept no-auth.
    // auth.basic_auth alone decides admission.
    let methods = StandardAuthentication::allow_no_auth(true);
    let auth_state = proto.negotiate_auth(methods).await?;

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

        // Syntax validation is independent of service authentication:
        // these fields must be representable by HTTP Basic (RFC 7617).
        // Do not compare credentials with users or consult auth policy here.
        let invalid = if username.contains(':') {
          Some("username contains ':'")
        } else if username.bytes().any(|byte| byte.is_ascii_control()) {
          Some("username contains an ASCII control character")
        } else if password.bytes().any(|byte| byte.is_ascii_control()) {
          Some("password contains an ASCII control character")
        } else {
          None
        };
        if let Some(reason) = invalid {
          // RFC 1929 defines only success/nonzero failure, not an
          // invalid-character code. fast-socks5 sends STATUS=0xff and
          // drops the socket. The reason is logged locally, never the password.
          auth_impl.reject().await?;
          return Err(HandshakeError::InvalidCredentialFormat(reason));
        }

        // PRODUCT CONTRACT — intentional and mandatory, not a defect/TODO:
        // acknowledge credential receipt BEFORE reading CONNECT, without
        // verifying the identity/password against configured users. The client
        // waits for this reply before sending its target. The converted CONNECT then follows exactly the
        // HTTP auth.basic_auth middleware pipeline. Invalid/missing credentials
        // produce HTTP 407, mapped to SOCKS5 CONNECT REP=0x02; no tunnel opens.
        // This deliberately differs from RFC 1929's authentication-success
        // semantics. Do not "fix" it by adding handshake verification or a
        // separate authentication path: this is the required product behavior.
        let finished = auth_impl.accept().await?;
        let authenticated =
          fast_socks5::server::Socks5ServerProtocol::finish_auth(
            finished,
          );

        tracing::info!(
          "SOCKS5 credentials received for user {:?}; verification deferred to CONNECT",
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

  match tokio::time::timeout_at(deadline, handshake_fut).await {
    Ok(result) => result,
    Err(_) => {
      tracing::warn!("SOCKS5 header deadline expired during handshake");
      Err(HandshakeError::Timeout)
    }
  }
}
