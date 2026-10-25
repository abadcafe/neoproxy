//! module: stream
//! responsibilities: expose protocol upgrade and tunnel transport
//! operations public operations: Io, upgrade types, extract_upgrade,
//! run_tunnel, http_status_to_socks5_error data entities: none
//! tests: stream_tests.rs

mod idle;
#[cfg(test)]
mod idle_tests;
mod tunnel;
mod upgrade;
#[cfg(test)]
mod upgrade_tests;

use tokio::io::{AsyncRead, AsyncWrite};
pub(crate) trait Io:
  AsyncRead + AsyncWrite + Unpin + Send
{
}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

pub(crate) use tunnel::run_tunnel;
pub(crate) use upgrade::{
  H3UpgradeTrigger, Socks5UpgradeTrigger, UpgradeFuture,
  extract_upgrade, http_status_to_socks5_error,
};
