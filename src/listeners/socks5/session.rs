//! module: listeners::socks5::session
//! responsibility: translate a SOCKS5 session into the CONNECT service
//! contract public operations: serve
//! data entities: none
//! tests: session_tests.rs; tests/integration/test_socks5*.py

use base64::Engine;
use tokio::time::Instant;

use super::command::{CommandError, read_command_and_target};
use super::handshake::{HandshakeError, perform_handshake};
use super::upgrade::{
  Socks5UpgradeTrigger, http_status_to_socks5_error,
};
use crate::http_message::{BytesBufBodyWrapper, RequestBody};
use crate::listeners::http_service::HttpService;
use crate::listeners::tcp_listener_base::TcpConnection;
use crate::server::ServerRouter;

pub(super) async fn serve(
  connection: TcpConnection,
  server_router: ServerRouter,
  deadline: Instant,
) {
  let TcpConnection { stream, peer_addr, local_addr, .. } = connection;
  tracing::info!("SOCKS5 connection established from {peer_addr}");
  // Negotiation, credential receipt/reply and command decoding are one
  // request-header read. The accept callback supplies one absolute
  // deadline; neither phase changes nor partial reads renew it.
  let handshake_result = match perform_handshake(stream, deadline).await
  {
    Ok(result) => result,
    Err(e) => {
      // Handle handshake errors
      match e {
        HandshakeError::Timeout => {
          // Timeout - do not send response, just close
          // connection
          tracing::warn!("SOCKS5 handshake timeout from {}", peer_addr);
        }
        HandshakeError::InvalidVersion(v) => {
          // Invalid version - do not send response
          tracing::warn!(
            "SOCKS5 invalid version {} from {}",
            v,
            peer_addr
          );
        }
        HandshakeError::MethodNotAcceptable(_) => {
          // METHOD=0xFF was already sent
          tracing::warn!(
            "SOCKS5 method not acceptable from {}",
            peer_addr
          );
        }
        HandshakeError::InvalidCredentialFormat(reason) => {
          tracing::warn!(
            "SOCKS5 invalid credential format from {peer_addr}: \
             {reason}"
          );
        }
        HandshakeError::ClientDisconnected => {
          tracing::info!(
            "SOCKS5 connection disconnected from {}",
            peer_addr
          );
        }
        HandshakeError::IoError(e) => {
          tracing::warn!(
            "SOCKS5 handshake IO error from {}: {}",
            peer_addr,
            e
          );
        }
      }
      // Connection is already closed by the error handler
      return;
    }
  };

  // Reuse the accept-time deadline. Shared auth and upstream dialing
  // run only after the request is decoded and are outside this timeout.
  let command = match tokio::time::timeout_at(
    deadline,
    read_command_and_target(handshake_result.proto),
  )
  .await
  {
    Ok(result) => result,
    Err(_) => {
      tracing::warn!("SOCKS5 command timed out from {peer_addr}");
      return;
    }
  };
  let command_result = match command {
    Ok(result) => result,
    Err(e) => {
      // Command error responses are already sent
      match e {
        CommandError::CommandNotSupported { command } => {
          tracing::warn!(
            "SOCKS5 command {} not supported from {}",
            command,
            peer_addr
          );
        }
        CommandError::UnknownCommand { command } => {
          tracing::warn!(
            "SOCKS5 unknown command {} from {}",
            command,
            peer_addr
          );
        }
        CommandError::ClientDisconnected => {
          tracing::warn!(
            "SOCKS5 client disconnected during command processing \
             from {}",
            peer_addr
          );
        }
        CommandError::IoError(e) => {
          tracing::warn!(
            "SOCKS5 command read error from {}: {}",
            peer_addr,
            e
          );
        }
      }
      return;
    }
  };

  // Step 3: Create upgrade pair
  let (trigger, on_upgrade) =
    Socks5UpgradeTrigger::pair(command_result.proto);

  // Step 4: Build HTTP CONNECT request with on_upgrade in
  // extensions
  let (host, port) = extract_host_port(&command_result.target_addr);
  let uri = format_connect_uri(&host, port);

  let request = http::Request::builder()
    .method(http::Method::CONNECT)
    .uri(&uri)
    .version(http::Version::HTTP_11)
    .header(http::header::HOST, &uri)
    .body(RequestBody::new(BytesBufBodyWrapper::new(
      http_body_util::Empty::<bytes::Bytes>::new(),
    )));
  let mut request = match request {
    Ok(request) => request,
    Err(error) => {
      tracing::warn!("invalid SOCKS5 target: {error}");
      let _ = trigger
        .send_error(fast_socks5::ReplyError::AddressTypeNotSupported)
        .await;
      return;
    }
  };

  // PRODUCT CONTRACT: construct the same Proxy-Authorization header as
  // an HTTP CONNECT client. auth.basic_auth is the sole verifier; the
  // SOCKS5 handshake only acknowledged receipt of credentials.
  if let (Some(username), Some(password)) =
    (handshake_result.username, handshake_result.password)
  {
    let encoded = base64::engine::general_purpose::STANDARD
      .encode(format!("{username}:{password}"));
    let mut header =
      http::HeaderValue::from_str(&format!("Basic {encoded}"))
        .expect("Base64 is a valid HTTP header value");
    header.set_sensitive(true);
    request
      .headers_mut()
      .insert(http::header::PROXY_AUTHORIZATION, header);
  }

  request.extensions_mut().insert(on_upgrade);

  // All listeners enter the same request dispatcher. SOCKS5 has
  // already decoded its wire protocol into an HTTP/1.1 CONNECT;
  // validation, routing, request identity and layers are shared.
  let result =
    HttpService::new_http(server_router, peer_addr, local_addr)
      .dispatch(request)
      .await;

  // Step 6: Based on Response, send SOCKS5 reply via
  // trigger
  match result {
    Ok(resp) => {
      if resp.status() == http::StatusCode::OK {
        if let Err(e) = trigger.send_success().await {
          tracing::warn!(
            "SOCKS5 failed to send success reply to {}: {}",
            peer_addr,
            e
          );
        }
      } else {
        let error = http_status_to_socks5_error(resp.status());
        if let Err(e) = trigger.send_error(error).await {
          tracing::warn!(
            "SOCKS5 failed to send error reply to {}: {}",
            peer_addr,
            e
          );
        }
      }
    }
    Err(e) => {
      tracing::warn!(
        "connection from {} on {}: {}",
        peer_addr,
        local_addr,
        e
      );
      if let Err(send_err) = trigger
        .send_error(fast_socks5::ReplyError::GeneralFailure)
        .await
      {
        tracing::warn!(
          "SOCKS5 failed to send error reply to {}: {}",
          peer_addr,
          send_err
        );
      }
    }
  }
}

/// Formats a host and port for HTTP CONNECT URI.
fn format_connect_uri(host: &str, port: u16) -> String {
  if host.starts_with('[') {
    return format!("{}:{}", host, port);
  }
  if let Ok(addr) = host.parse::<std::net::IpAddr>() {
    match addr {
      std::net::IpAddr::V4(_) => format!("{}:{}", host, port),
      std::net::IpAddr::V6(_) => format!("[{}]:{}", host, port),
    }
  } else {
    format!("{}:{}", host, port)
  }
}

/// Extracts host and port from TargetAddr.
fn extract_host_port(
  target_addr: &fast_socks5::util::target_addr::TargetAddr,
) -> (String, u16) {
  match target_addr {
    fast_socks5::util::target_addr::TargetAddr::Ip(addr) => {
      (addr.ip().to_string(), addr.port())
    }
    fast_socks5::util::target_addr::TargetAddr::Domain(
      domain,
      port,
    ) => (domain.clone(), *port),
  }
}
