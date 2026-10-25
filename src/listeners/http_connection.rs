//! module: http_connection
//! responsibilities: serve an HTTP connection with header deadlines and
//! graceful shutdown public operations: HeaderDeadline, serve
//! data entities: HeaderDeadline, DurationValue, LocalExecutor
//! tests: http_connection_tests.rs; test_http_shutdown.py;
//! process protocol regressions

use std::future::Future;
use std::time::Duration;

use anyhow::{Result, ensure};
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncWrite};

use super::http_service::HttpServiceAdaptor;
use crate::shutdown::ShutdownHandle;

const DEFAULT_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(try_from = "DurationValue")]
pub(crate) struct HeaderDeadline(Duration);
#[derive(Deserialize)]
struct DurationValue(#[serde(with = "humantime_serde")] Duration);
impl TryFrom<DurationValue> for HeaderDeadline {
  type Error = anyhow::Error;

  fn try_from(value: DurationValue) -> Result<Self> {
    ensure!(
      !value.0.is_zero()
        && std::time::Instant::now().checked_add(value.0).is_some(),
      "header_read_timeout must be positive and representable"
    );
    Ok(Self(value.0))
  }
}
impl Default for HeaderDeadline {
  fn default() -> Self {
    Self(DEFAULT_HEADER_READ_TIMEOUT)
  }
}

#[derive(Clone)]
struct LocalExecutor;
impl<F: Future + 'static> hyper::rt::Executor<F> for LocalExecutor {
  fn execute(&self, future: F) {
    tokio::task::spawn_local(future);
  }
}

pub(crate) async fn serve<I>(
  io: I,
  service: HttpServiceAdaptor,
  deadline: HeaderDeadline,
  shutdown: ShutdownHandle,
) -> Result<()>
where
  I: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
  let mut builder =
    hyper_util::server::conn::auto::Builder::new(LocalExecutor);
  builder
    .http1()
    .timer(hyper_util::rt::TokioTimer::new())
    .header_read_timeout(deadline.0);
  let connection = builder.serve_connection_with_upgrades(
    hyper_util::rt::TokioIo::new(io),
    service,
  );
  tokio::pin!(connection);
  tokio::select! {
    result = &mut connection => return result.map_err(|error| anyhow::anyhow!("{error}")),
    _ = shutdown.notified() => connection.as_mut().graceful_shutdown(),
  }
  // Hyper owns ordinary HTTP I/O, including response bodies after the
  // Service has returned. Graceful shutdown closes idle connections and
  // disables reuse while allowing the current exchange to finish. The
  // caller enforces the shutdown budget and cancels stalled
  // connections. Successful CONNECT upgrades hand I/O to the plugin's
  // tunnel task; this HTTP connection future then completes instead
  // of driving it.
  connection.await.map_err(|error| anyhow::anyhow!("{error}"))
}
