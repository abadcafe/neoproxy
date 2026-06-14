//! SOCKS5 command processing.

use super::handshake::HandshakeError;

/// Error during SOCKS5 command processing.
#[derive(Debug)]
pub(crate) enum CommandError {
  /// Command not supported (BIND or UDP ASSOCIATE).
  CommandNotSupported { command: u8 },

  /// Unknown command code.
  UnknownCommand { command: u8 },

  /// Client disconnected during command processing.
  ClientDisconnected,

  /// IO error during command processing.
  IoError(std::io::Error),
}

impl std::fmt::Display for CommandError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::CommandNotSupported { command } => {
        write!(f, "command not supported: 0x{:02x}", command)
      }
      Self::UnknownCommand { command } => {
        write!(f, "unknown command: 0x{:02x}", command)
      }
      Self::ClientDisconnected => {
        write!(f, "client disconnected during command processing")
      }
      Self::IoError(e) => {
        write!(f, "IO error during command processing: {}", e)
      }
    }
  }
}

impl std::error::Error for CommandError {}

impl From<std::io::Error> for CommandError {
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

impl From<HandshakeError> for CommandError {
  fn from(e: HandshakeError) -> Self {
    match e {
      HandshakeError::Timeout => Self::IoError(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "handshake timed out",
      )),
      HandshakeError::InvalidVersion(v) => {
        Self::IoError(std::io::Error::new(
          std::io::ErrorKind::InvalidData,
          format!("invalid SOCKS version: {}", v),
        ))
      }
      HandshakeError::MethodNotAcceptable(_) => Self::IoError(
        std::io::Error::other("authentication method not acceptable"),
      ),
      HandshakeError::ClientDisconnected => Self::ClientDisconnected,
      HandshakeError::IoError(e) => Self::from(e),
    }
  }
}

impl From<fast_socks5::server::SocksServerError> for CommandError {
  fn from(e: fast_socks5::server::SocksServerError) -> Self {
    use fast_socks5::server::SocksServerError;
    match e {
      SocksServerError::UnknownCommand(cmd) => {
        Self::UnknownCommand { command: cmd }
      }
      SocksServerError::AuthMethodUnacceptable(_) => {
        Self::IoError(std::io::Error::other(
          "unexpected auth error during command processing",
        ))
      }
      SocksServerError::Io { source, .. } => Self::from(source),
      _ => Self::IoError(std::io::Error::other(e.to_string())),
    }
  }
}

/// Result of a successful SOCKS5 command read.
pub(super) struct CommandResult {
  /// The protocol state after command has been read.
  pub(super) proto: fast_socks5::server::Socks5ServerProtocol<
    tokio::net::TcpStream,
    fast_socks5::server::states::CommandRead,
  >,
  /// The target address from the SOCKS5 request.
  pub(super) target_addr: fast_socks5::util::target_addr::TargetAddr,
}

impl std::fmt::Debug for CommandResult {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("CommandResult")
      .field("target_addr", &self.target_addr)
      .finish_non_exhaustive()
  }
}

/// Reads SOCKS5 command and extracts target address.
///
/// Handles:
/// - CONNECT command: Returns the target address
/// - BIND command: Sends REP=0x07 and returns error
/// - UDP ASSOCIATE command: Sends REP=0x07 and returns error
pub(super) async fn read_command_and_target(
  proto: fast_socks5::server::Socks5ServerProtocol<
    tokio::net::TcpStream,
    fast_socks5::server::states::Authenticated,
  >,
) -> Result<CommandResult, CommandError> {
  let (proto, cmd, target_addr) = proto.read_command().await?;

  match cmd {
    fast_socks5::Socks5Command::TCPConnect => {
      tracing::info!("SOCKS5 CONNECT request to {}", target_addr);
      Ok(CommandResult { proto, target_addr })
    }
    fast_socks5::Socks5Command::TCPBind => {
      proto
        .reply_error(&fast_socks5::ReplyError::CommandNotSupported)
        .await?;
      tracing::warn!(
        "SOCKS5 BIND command not supported, sent REP=0x07"
      );
      Err(CommandError::CommandNotSupported {
        command: fast_socks5::consts::SOCKS5_CMD_TCP_BIND,
      })
    }
    fast_socks5::Socks5Command::UDPAssociate => {
      proto
        .reply_error(&fast_socks5::ReplyError::CommandNotSupported)
        .await?;
      tracing::warn!(
        "SOCKS5 UDP ASSOCIATE command not supported, sent REP=0x07"
      );
      Err(CommandError::CommandNotSupported {
        command: fast_socks5::consts::SOCKS5_CMD_UDP_ASSOCIATE,
      })
    }
  }
}
