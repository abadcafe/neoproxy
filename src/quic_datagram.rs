//! module: quic_datagram
//! responsibility: configure connection-scoped HTTP/3 datagram capacity
//! public operations: Config::{validate,apply}
//! data entities: Config
//! tests: quic_datagram_tests.rs and chain matrix UDP tests
use byte_unit::Byte;
use serde::Deserialize;
#[derive(Clone, Debug, Deserialize)]
pub(crate) struct Config {
  #[serde(default = "enabled")]
  pub(crate) http3_enable_datagram: bool,
  #[serde(default = "buffer")]
  pub(crate) quic_connection_datagram_receive_buffer_size: Byte,
  #[serde(default = "buffer")]
  pub(crate) quic_connection_datagram_send_buffer_size: Byte,
}
fn enabled() -> bool {
  true
}
fn buffer() -> Byte {
  Byte::from_u64(1024 * 1024)
}
impl Default for Config {
  fn default() -> Self {
    Self {
      http3_enable_datagram: true,
      quic_connection_datagram_receive_buffer_size: buffer(),
      quic_connection_datagram_send_buffer_size: buffer(),
    }
  }
}
impl Config {
  pub(crate) fn validate(&self) -> anyhow::Result<()> {
    for (name, value) in [
      (
        "quic_connection_datagram_receive_buffer_size",
        self.quic_connection_datagram_receive_buffer_size,
      ),
      (
        "quic_connection_datagram_send_buffer_size",
        self.quic_connection_datagram_send_buffer_size,
      ),
    ] {
      anyhow::ensure!(
        value.as_u64() > 0 && usize::try_from(value.as_u64()).is_ok(),
        "{name} must be positive and fit usize"
      );
    }
    Ok(())
  }

  pub(crate) fn apply(&self, transport: &mut quinn::TransportConfig) {
    transport
      .datagram_receive_buffer_size(self.http3_enable_datagram.then(
        || {
          usize::try_from(
            self.quic_connection_datagram_receive_buffer_size.as_u64(),
          )
          .expect("validated datagram capacity")
        },
      ))
      .datagram_send_buffer_size(
        usize::try_from(
          self.quic_connection_datagram_send_buffer_size.as_u64(),
        )
        .expect("validated datagram capacity"),
      );
  }
}
