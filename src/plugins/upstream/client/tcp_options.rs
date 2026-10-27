//! module: tcp_options
//! responsibility: apply configured TCP keepalive policy to connected
//! sockets public operations: TcpOptions::apply
//! data entities: TcpOptions
//! tests: tcp_options_tests.rs
use std::time::Duration;
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct TcpOptions {
  pub(super) time: Option<Duration>,
  pub(super) interval: Option<Duration>,
  pub(super) retries: Option<u32>,
}
impl TcpOptions {
  pub(super) fn apply(
    &self,
    stream: &tokio::net::TcpStream,
  ) -> std::io::Result<()> {
    stream.set_nodelay(true)?;
    if self.time.is_none()
      && self.interval.is_none()
      && self.retries.is_none()
    {
      return Ok(());
    }
    let socket = socket2::SockRef::from(stream);
    let mut options = socket2::TcpKeepalive::new();
    if let Some(time) = self.time {
      options = options.with_time(time);
    }
    if let Some(interval) = self.interval {
      options = options.with_interval(interval);
    }
    if let Some(retries) = self.retries {
      options = options.with_retries(retries);
    }
    socket.set_tcp_keepalive(&options)
  }
}
