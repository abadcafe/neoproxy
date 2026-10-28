//! module: tcp_options
//! responsibility: apply configured TCP keepalive policy to connected
//! sockets public operations: TcpOptions::apply, Deserialize
//! data entities: TcpOptions, RawOptions
//! tests: tcp_options_tests.rs
use std::time::Duration;
#[derive(Clone, Copy, Debug, Default, serde::Deserialize)]
#[serde(try_from = "RawOptions")]
pub(crate) struct TcpOptions {
  pub(crate) time: Option<Duration>,
  pub(crate) interval: Option<Duration>,
  pub(crate) retries: Option<u32>,
}
impl TcpOptions {
  pub(crate) fn apply(
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

#[derive(serde::Deserialize)]
struct RawOptions {
  #[serde(with = "humantime_serde", default)]
  tcp_keep_alive_time: Option<Duration>,
  #[serde(with = "humantime_serde", default)]
  tcp_keep_alive_interval: Option<Duration>,
  #[serde(default)]
  tcp_keep_alive_retries: Option<u32>,
}
impl TryFrom<RawOptions> for TcpOptions {
  type Error = anyhow::Error;

  fn try_from(raw: RawOptions) -> Result<Self, Self::Error> {
    for (name, duration) in [
      ("tcp_keep_alive_time", raw.tcp_keep_alive_time),
      ("tcp_keep_alive_interval", raw.tcp_keep_alive_interval),
    ] {
      anyhow::ensure!(
        duration.is_none_or(|value| value.as_secs() > 0
          && value.as_secs() <= u64::from(u32::MAX)),
        "{name} must fit a positive u32 number of seconds"
      );
    }
    anyhow::ensure!(
      raw.tcp_keep_alive_retries != Some(0),
      "tcp_keep_alive_retries must be positive"
    );
    Ok(Self {
      time: raw.tcp_keep_alive_time,
      interval: raw.tcp_keep_alive_interval,
      retries: raw.tcp_keep_alive_retries,
    })
  }
}
