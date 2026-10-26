//! module: listeners::socks5::session
//! responsibility: translate a SOCKS5 session into the CONNECT service
//! contract public operations: serve
//! data entities: none
//! tests: session_tests.rs; tests/integration/test_socks5*.py

use std::time::Duration;

use super::command::{CommandError, read_command_and_target};
use super::handshake::{HandshakeError, perform_handshake};
use super::upgrade::{
  Socks5UpgradeTrigger, http_status_to_socks5_error,
};
use crate::http_message::{BytesBufBodyWrapper, RequestBody};
use crate::listeners::tcp_listener_base::TcpConnection;
use crate::service::Service as RuntimeService;

pub(super) async fn serve(
  connection: TcpConnection,
  service: RuntimeService,
  handshake_timeout: Duration,
  service_name: String,
) {
  let TcpConnection { stream, peer_addr, local_addr, .. } = connection;
  tracing::info!("SOCKS5 connection established from {peer_addr}");
  // Step 1: Perform SOCKS5 handshake with timeout
  // protection
  let handshake_result = match perform_handshake(
    stream,
    handshake_timeout,
    &service.authentication(),
  )
  .await
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
        HandshakeError::InvalidCredentials => {
          tracing::warn!(
            "SOCKS5 authentication rejected from {peer_addr}"
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

  // Bound the command phase as well as authentication.
  let command = match tokio::time::timeout(
    handshake_timeout,
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

  // Carry verified credentials into the HTTP middleware.
  // Typed fields
  // also preserve SOCKS5 usernames containing
  // ':' that HTTP Basic cannot encode without
  // changing the username/password boundary.
  if let (Some(username), Some(password)) =
    (handshake_result.username, handshake_result.password)
  {
    request
      .extensions_mut()
      .insert(crate::auth::ProxyCredentials::new(username, password));
  }

  request.extensions_mut().insert(on_upgrade);

  // Build RequestContext with connection-level keys and
  // insert into request extensions. Auth and
  // access logging are now handled by the
  // plugin layer in the service pipeline.
  let ctx = crate::context::build_request_context(
    &peer_addr,
    &local_addr,
    &service_name,
  );
  let id = match crate::request_id::RequestId::read_or_generate(
    request.headers(),
  ) {
    Ok(id) => id,
    Err(error) => {
      tracing::error!("generating SOCKS5 request ID: {error}");
      let _ = trigger
        .send_error(fast_socks5::ReplyError::GeneralFailure)
        .await;
      return;
    }
  };
  let ctx = ctx.with_request_id(id);
  request.extensions_mut().insert(ctx);

  // Step 5: Call the associated Service
  let result = tower::ServiceExt::oneshot(service, request).await;

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
