//! module: establish
//! responsibility: create and drive an HTTP/3 transport on its owning
//! runtime public operations: establish, Settings
//! data entities: Settings
//! tests: session_tests.rs, quic_connect_tests.rs
use std::sync::Arc;
use std::time::Duration;

use h3::client as h3_cli;

use super::super::observation::ConnectionObservation;
use super::io_progress::SendBuffer;
use super::quic_connect;
use crate::plugins::upstream::client::protocol::QuicConfig;
use crate::plugins::upstream::error::UpstreamError;
#[derive(Clone)]
pub(super) struct Settings {
  pub(super) limits: crate::header_limits::Limits,
  pub(super) address: std::net::SocketAddr,
  pub(super) hostname: Option<String>,
  pub(super) quic: QuicConfig,
  pub(super) handshake_timeout: Duration,
}
pub(super) async fn establish(
  pool: &Settings,
  tls_config: &rustls::ClientConfig,
  observation: &ConnectionObservation,
  registry: super::read_progress::Registry,
  tasks: &Arc<crate::task_tracker::TaskTracker>,
) -> Result<
  (
    quinn::Connection,
    h3_cli::SendRequest<super::read_progress::Opener, SendBuffer>,
    tokio::sync::watch::Receiver<Option<bool>>,
  ),
  UpstreamError,
> {
  let address = &pool.address;
  let quinn_conn =
    create_quic_connection(pool, tls_config, observation).await?;
  let (mut h3_conn, send_request) = h3::client::builder()
    .enable_extended_connect(true)
    .enable_datagram(pool.quic.datagram.http3_enable_datagram)
    .max_field_section_size(u64::from(pool.limits.bytes()))
    .build(super::read_progress::Connection::new(
      quinn_conn.clone(),
      registry,
    ))
    .await
    .map_err(|e| {
      UpstreamError::ConnectionTerminated(format!(
        "H3 connection setup to {address} failed: {e}"
      ))
    })?;

  let (settings_tx, settings_rx) = tokio::sync::watch::channel(None);
  let shutdown = tasks.shutdown_handle();
  let connection = quinn_conn.clone();
  tasks.register_on(&tokio::runtime::Handle::current(), async move {
    use h3::ConnectionState;
    let driver = std::future::poll_fn(|cx| {
      let result = h3_conn.poll_close(cx);
      if let std::borrow::Cow::Borrowed(settings) = h3_conn.settings() {
        settings_tx.send_if_modified(|value| {
          if value.is_none() {
            *value = Some(settings.enable_extended_connect());
            true
          } else {
            false
          }
        });
      }
      result
    });
    tokio::pin!(driver);
    tokio::select! {
      _ = &mut driver => {},
      _ = shutdown.notified() => {
        connection.close(0x100u32.into(), b"pool shutdown");
        let _ = driver.await;
      }
    }
  });

  Ok((quinn_conn, send_request, settings_rx))
}

async fn create_quic_connection(
  pool: &Settings,
  tls_config: &rustls::ClientConfig,
  observation: &ConnectionObservation,
) -> Result<quinn::Connection, UpstreamError> {
  let address = &pool.address;
  let hostname = pool.hostname.as_deref();
  let quic = &pool.quic;
  let tls_handshake_timeout = pool.handshake_timeout;
  let mut tls_config = tls_config.clone();
  tls_config.enable_early_data = true;
  tls_config.alpn_protocols = vec![b"h3".to_vec()];

  let mut cli_config = quinn::ClientConfig::new(Arc::new(
    quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
      .map_err(|e| {
        UpstreamError::TlsProtocolError(format!(
          "QUIC TLS config error: {e}"
        ))
      })?,
  ));

  let mut transport = quinn::TransportConfig::default();
  transport.keep_alive_interval(Some(quic.keep_alive_interval));
  if let Some(idle) = quic.max_idle_timeout {
    let ms = u64::try_from(idle.as_millis()).map_err(|_| {
      UpstreamError::ProxyInternalError(
        "quic max_idle_timeout too large".into(),
      )
    })?;
    transport.max_idle_timeout(Some(
      quinn::VarInt::from_u64(ms)
        .map_err(|_| {
          UpstreamError::ProxyInternalError(
            "quic max_idle_timeout overflow".into(),
          )
        })?
        .into(),
    ));
  }
  if let Some(v) = quic.max_concurrent_bidi_streams {
    transport.max_concurrent_bidi_streams(
      quinn::VarInt::from_u64(v).map_err(|_| {
        UpstreamError::ProxyInternalError(
          "max_concurrent_bidi_streams overflow".into(),
        )
      })?,
    );
  }
  if let Some(v) = quic.initial_mtu {
    transport.initial_mtu(v);
  }
  if let Some(v) = quic.send_window {
    transport.send_window(v);
  }
  if let Some(v) = quic.stream_receive_window {
    transport.stream_receive_window(
      quinn::VarInt::from_u64(v).map_err(|_| {
        UpstreamError::ProxyInternalError(
          "stream_receive_window overflow".into(),
        )
      })?,
    );
  }
  if let Some(v) = quic.receive_window {
    transport.receive_window(quinn::VarInt::from_u64(v).map_err(
      |_| {
        UpstreamError::ProxyInternalError(
          "receive_window overflow".into(),
        )
      },
    )?);
  }
  quic.datagram.apply(&mut transport);
  cli_config.transport_config(Arc::new(transport));

  let host = hostname
    .map(str::to_owned)
    .unwrap_or_else(|| address.ip().to_string());
  let tls_started = std::time::Instant::now();
  let result = quic_connect::connect(
    *address,
    &host,
    cli_config,
    tls_handshake_timeout,
  )
  .await;
  observation.tls(tls_started.elapsed());
  let conn = result?;
  observation.endpoint(Some(conn.remote_address()), None);
  Ok(conn)
}
