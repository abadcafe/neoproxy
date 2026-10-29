//! module: socks5::handshake
//! responsibility: negotiate a SOCKS5 CONNECT over an established byte
//! stream public operations: negotiate
//! data entities: none
//! tests: handshake_tests.rs

use std::net::IpAddr;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::config::UserCredential;
use crate::plugins::upstream::error::UpstreamError;
use crate::plugins::upstream::target_parser::ConnectTarget;

/// Does not resolve addresses or own deadlines. Exact reads preserve
/// tunnel bytes; write_all handles partial writes on every handshake
/// packet.
pub(in crate::plugins::upstream::client) async fn negotiate<
  S: AsyncRead + AsyncWrite + Unpin,
>(
  stream: &mut S,
  target: &ConnectTarget,
  user: Option<&UserCredential>,
) -> Result<(), UpstreamError> {
  let authentication = user.map(authentication_request).transpose()?;
  let uri = target.uri();
  let authority = uri.authority().expect("validated CONNECT authority");
  let host =
    authority.host().trim_start_matches('[').trim_end_matches(']');
  let port = authority.port_u16().expect("validated CONNECT port");
  let mut command = vec![5, 1, 0];
  match host.parse::<IpAddr>() {
    Ok(IpAddr::V4(ip)) => {
      command.push(1);
      command.extend_from_slice(&ip.octets());
    }
    Ok(IpAddr::V6(ip)) => {
      command.push(4);
      command.extend_from_slice(&ip.octets());
    }
    Err(_) => {
      let length = u8::try_from(host.len())
        .map_err(|_| rejected(http::StatusCode::BAD_REQUEST))?;
      command.extend_from_slice(&[3, length]);
      command.extend_from_slice(host.as_bytes());
    }
  }
  command.extend_from_slice(&port.to_be_bytes());
  stream
    .write_all(if user.is_some() { &[5, 2, 0, 2] } else { &[5, 1, 0] })
    .await
    .map_err(io_error)?;
  let mut choice = [0; 2];
  stream.read_exact(&mut choice).await.map_err(io_error)?;
  if choice[0] != 5 {
    return Err(invalid("invalid SOCKS5 greeting version"));
  }
  match choice[1] {
    0 => {}
    2 => {
      let packet = authentication.as_deref().ok_or_else(|| {
        invalid("SOCKS5 selected an unoffered authentication method")
      })?;
      authenticate(stream, packet).await?;
    }
    255 => {
      return Err(rejected(
        http::StatusCode::PROXY_AUTHENTICATION_REQUIRED,
      ));
    }
    _ => {
      return Err(invalid(
        "SOCKS5 selected an unoffered authentication method",
      ));
    }
  }
  stream.write_all(&command).await.map_err(io_error)?;
  let mut header = [0; 4];
  stream.read_exact(&mut header).await.map_err(io_error)?;
  if header[0] != 5 || header[2] != 0 || header[1] > 8 {
    return Err(invalid("invalid SOCKS5 CONNECT response"));
  }
  let length = match header[3] {
    1 => 4,
    4 => 16,
    3 => {
      let length = stream.read_u8().await.map_err(io_error)?;
      if length == 0 {
        return Err(invalid("empty SOCKS5 bound domain"));
      }
      usize::from(length)
    }
    _ => return Err(invalid("invalid SOCKS5 bound address type")),
  };
  let mut bound = vec![0; length + 2];
  stream.read_exact(&mut bound).await.map_err(io_error)?;
  match header[1] {
    0 => Ok(()),
    2 => Err(rejected(http::StatusCode::FORBIDDEN)),
    6 => Err(rejected(http::StatusCode::GATEWAY_TIMEOUT)),
    7 => Err(rejected(http::StatusCode::NOT_IMPLEMENTED)),
    _ => Err(rejected(http::StatusCode::BAD_GATEWAY)),
  }
}

fn authentication_request(
  user: &UserCredential,
) -> Result<Vec<u8>, UpstreamError> {
  let username = user.username().as_bytes();
  let password = user.password().as_bytes();
  let length = |bytes: &[u8]| {
    u8::try_from(bytes.len())
      .ok()
      .filter(|length| *length != 0)
      .ok_or_else(|| {
        UpstreamError::ProxyInternalError(
          "SOCKS5 credentials must each contain 1..=255 bytes".into(),
        )
      })
  };
  let mut packet = vec![1, length(username)?];
  packet.extend_from_slice(username);
  packet.push(length(password)?);
  packet.extend_from_slice(password);
  Ok(packet)
}

async fn authenticate<S: AsyncRead + AsyncWrite + Unpin>(
  stream: &mut S,
  packet: &[u8],
) -> Result<(), UpstreamError> {
  stream.write_all(packet).await.map_err(io_error)?;
  let mut response = [0; 2];
  stream.read_exact(&mut response).await.map_err(io_error)?;
  if response[0] != 1 {
    return Err(invalid("invalid SOCKS5 password response version"));
  }
  if response[1] != 0 {
    return Err(rejected(
      http::StatusCode::PROXY_AUTHENTICATION_REQUIRED,
    ));
  }
  Ok(())
}

fn rejected(status: http::StatusCode) -> UpstreamError {
  UpstreamError::UpstreamConnectError {
    status,
    upstream_proxy_status: None,
  }
}

fn invalid(message: &str) -> UpstreamError {
  UpstreamError::InvalidResponse(message.into())
}

fn io_error(error: std::io::Error) -> UpstreamError {
  if error.kind() == std::io::ErrorKind::TimedOut {
    UpstreamError::ConnectionTimeout(error.to_string())
  } else {
    UpstreamError::ConnectionTerminated(error.to_string())
  }
}
