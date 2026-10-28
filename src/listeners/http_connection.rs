//! module: http_connection
//! responsibilities: serve an HTTP connection with header deadlines and
//! graceful shutdown public operations: serve
//! data entities: LocalExecutor
//! tests: test_http_shutdown.py;
//! process protocol regressions

use std::future::Future;

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite};

use super::header_deadline::HeaderDeadline;
use super::http_service::HttpService;
use crate::shutdown::ShutdownHandle;

#[derive(Clone)]
struct LocalExecutor;
impl<F: Future + 'static> hyper::rt::Executor<F> for LocalExecutor {
  fn execute(&self, future: F) {
    tokio::task::spawn_local(future);
  }
}

pub(crate) async fn serve<I>(
  io: I,
  service: HttpService,
  deadline: HeaderDeadline,
  keep_alive: bool,
  shutdown: ShutdownHandle,
) -> Result<()>
where
  I: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
  let mut builder =
    hyper_util::server::conn::auto::Builder::new(LocalExecutor);
  builder
    .http1()
    .keep_alive(keep_alive)
    .timer(hyper_util::rt::TokioTimer::new())
    .header_read_timeout(deadline.duration());
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

pub(super) fn default_keep_alive() -> bool {
  true
}
