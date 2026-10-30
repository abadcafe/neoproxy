//! module: capsule
//! responsibility: incrementally frame RFC 9297 DATAGRAM capsules
//! public operations: Reader::{new,receive}, encode, varint,
//! decode_varint data entities: Reader
//! tests: connect_udp_tests.rs
use std::io;

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt};

pub(crate) const MAX_UDP_PAYLOAD: usize = 65527;

pub(crate) fn varint(value: u64, out: &mut Vec<u8>) {
  let size = if value < 64 {
    1
  } else if value < 16384 {
    2
  } else if value < 1 << 30 {
    4
  } else {
    8
  };
  let bits = match size {
    1 => 0,
    2 => 1,
    4 => 2,
    _ => 3,
  };
  let encoded = value | (bits << (size * 8 - 2));
  out.extend_from_slice(&encoded.to_be_bytes()[8 - size..]);
}
pub(crate) fn decode_varint(data: &[u8]) -> Option<(u64, usize)> {
  let first = *data.first()?;
  let size = 1 << (first >> 6);
  if data.len() < size {
    return None;
  }
  let mut value = u64::from(first & 63);
  for byte in &data[1..size] {
    value = (value << 8) | u64::from(*byte);
  }
  Some((value, size))
}
pub(crate) fn encode(payload: &[u8]) -> Vec<u8> {
  let mut result = vec![0];
  varint(payload.len() as u64 + 1, &mut result);
  result.push(0);
  result.extend_from_slice(payload);
  result
}
pub(crate) struct Reader<R> {
  inner: R,
  buffer: BytesMut,
  skip: u64,
}
impl<R: AsyncRead + Unpin> Reader<R> {
  pub(crate) fn new(inner: R) -> Self {
    Self { inner, buffer: BytesMut::new(), skip: 0 }
  }

  // Buffer and skip state live across cancellation by select!.
  pub(crate) async fn receive(
    &mut self,
  ) -> io::Result<Option<bytes::Bytes>> {
    loop {
      if self.skip > 0 {
        let count = self.skip.min(self.buffer.len() as u64) as usize;
        self.buffer.advance(count);
        self.skip -= count as u64;
      }
      if self.skip == 0
        && let Some((kind, first)) = decode_varint(&self.buffer)
        && let Some((length, second)) =
          decode_varint(&self.buffer[first..])
      {
        let header = first + second;
        if kind != 0 {
          self.buffer.advance(header);
          self.skip = length;
          continue;
        }
        // Parse the context before buffering the value. Unknown
        // contexts can have arbitrarily large capsules; context zero
        // is a UDP payload and RFC 9298 §5 caps it at 65527 bytes.
        let available = self.buffer.len() - header;
        let prefix =
          &self.buffer[header..header + available.min(length as usize)];
        if let Some((context, size)) = decode_varint(prefix) {
          if context != 0 {
            self.buffer.advance(header);
            self.skip = length;
            continue;
          }
          if length - size as u64 > MAX_UDP_PAYLOAD as u64 {
            return Err(io::Error::new(
              io::ErrorKind::InvalidData,
              "UDP payload exceeds 65527 bytes",
            ));
          }
        } else if available as u64 >= length {
          return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing context ID",
          ));
        }
        if self.buffer.len() >= header + length as usize {
          self.buffer.advance(header);
          let mut data = self.buffer.split_to(length as usize);
          let Some((context, size)) = decode_varint(&data) else {
            return Err(io::Error::new(
              io::ErrorKind::InvalidData,
              "missing context ID",
            ));
          };
          if context != 0 {
            continue;
          }
          data.advance(size);
          return Ok(Some(data.freeze()));
        }
      }
      let mut chunk = [0; 8192];
      let count = self.inner.read(&mut chunk).await?;
      if count == 0 {
        if self.buffer.is_empty() && self.skip == 0 {
          return Ok(None);
        }
        return Err(io::Error::new(
          io::ErrorKind::UnexpectedEof,
          "truncated capsule",
        ));
      }
      self.buffer.extend_from_slice(&chunk[..count]);
    }
  }
}
