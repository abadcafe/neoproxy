//! module: io_stream
//! responsibility: define the transport contract for bidirectional I/O
//! public operations: Io
//! data entities: none
//! tests: stream and upgraded transport behavior contracts

use tokio::io::{AsyncRead, AsyncWrite};
pub(crate) trait Io:
  AsyncRead + AsyncWrite + Unpin + Send
{
}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
