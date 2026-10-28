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
  policy: super::http_policy::HttpPolicy,
  keep_alive: bool,
  shutdown: ShutdownHandle,
) -> Result<()>
where
  I: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
  let first_deadline =
    tokio::time::Instant::now() + deadline.duration();
  let (protocol, io) = tokio::select! {
    _ = shutdown.notified() => return Ok(()),
    result = tokio::time::timeout(deadline.duration(), super::http_protocol::detect(io)) => result??,
  };
  let limits = policy.request_limits.limits();
  let control = super::write_deadline::Control::default();
  let reads = crate::io_progress::Progress::default();
  let io = hyper_util::rt::TokioIo::new(
    super::write_deadline::TimedIo::new(
      io,
      policy.write_timeout.duration(),
      control.clone(),
    )
    .with_reads(reads.clone()),
  );
  let service = service.with_policy(policy).with_write_control(control);
  match protocol {
    super::http_protocol::Protocol::Http1 => {
      let (first_header, mut received) =
        tokio::sync::oneshot::channel();
      let service =
        service.with_reads(reads).with_first_header(first_header);
      let mut builder = hyper::server::conn::http1::Builder::new();
      builder
        .keep_alive(keep_alive)
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(deadline.duration())
        .max_header_size(limits.bytes() as usize)
        .max_buf_size((limits.bytes() as usize).max(8192 + 4096 * 100));
      if limits.count() != 100 {
        builder.max_headers(limits.count());
      }
      let connection =
        builder.serve_connection(io, service).with_upgrades();
      tokio::pin!(connection);
      let mut first_received = false;
      loop {
        tokio::select! {
          result = &mut connection => return result.map_err(Into::into),
          _ = &mut received, if !first_received => first_received = true,
          _ = tokio::time::sleep_until(first_deadline), if !first_received => return Err(anyhow::anyhow!("request header deadline exceeded")),
          _ = shutdown.notified() => { connection.as_mut().graceful_shutdown(); break; }
        }
      }
      connection.await.map_err(Into::into)
    }
    super::http_protocol::Protocol::Http2 => {
      let mut builder =
        hyper::server::conn::http2::Builder::new(LocalExecutor);
      builder
        .max_header_list_size(limits.bytes())
        .timer(hyper_util::rt::TokioTimer::new());
      let connection = builder.serve_connection(io, service);
      tokio::pin!(connection);
      tokio::select! {
        result = &mut connection => return result.map_err(Into::into),
        _ = shutdown.notified() => connection.as_mut().graceful_shutdown(),
      }
      connection.await.map_err(Into::into)
    }
  }
}

pub(super) fn default_keep_alive() -> bool {
  true
}
