//! module: request_id
//! responsibility: preserve or generate one opaque request correlation
//! ID public operations: RequestId::{read_or_generate,apply}, Display
//! data entities: RequestId, Generator
//! tests: request_id_tests.rs
use std::cell::RefCell;
use std::hash::Hasher;

use http::{HeaderMap, HeaderValue};
use siphasher::sip::SipHasher24;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RequestId(HeaderValue);
struct Generator {
  key: [u64; 2],
  counter: u64,
}
impl Generator {
  fn new() -> Result<Self, getrandom::Error> {
    let mut seed = [0_u8; 16];
    getrandom::fill(&mut seed)?;
    Ok(Self {
      key: [
        u64::from_le_bytes(seed[..8].try_into().expect("eight bytes")),
        u64::from_le_bytes(seed[8..].try_into().expect("eight bytes")),
      ],
      counter: 0,
    })
  }

  fn next(&mut self) -> RequestId {
    let mut bytes = [0_u8; 32];
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for half in bytes.as_chunks_mut::<16>().0 {
      self.counter += 1;
      let mut hash =
        SipHasher24::new_with_keys(self.key[0], self.key[1]);
      hash.write(&self.counter.to_le_bytes());
      for (pair, byte) in half
        .as_chunks_mut::<2>()
        .0
        .iter_mut()
        .zip(hash.finish().to_le_bytes())
      {
        pair[0] = HEX[usize::from(byte >> 4)];
        pair[1] = HEX[usize::from(byte & 15)];
      }
    }
    RequestId(
      HeaderValue::from_bytes(&bytes).expect("hex is a header value"),
    )
  }
}
thread_local! { static GENERATOR: RefCell<Option<Generator>> = const { RefCell::new(None) }; }
impl RequestId {
  pub(crate) fn read_or_generate(
    headers: &HeaderMap,
  ) -> Result<Self, getrandom::Error> {
    if let Some(value) = headers.get("x-request-id") {
      return Ok(Self(value.clone()));
    }
    GENERATOR.with(|generator| {
      let mut generator = generator.borrow_mut();
      if generator
        .as_ref()
        .is_none_or(|current| current.counter > u64::MAX - 2)
      {
        *generator = Some(Generator::new()?);
      }
      Ok(generator.as_mut().expect("initialized generator").next())
    })
  }

  pub(crate) fn apply(&self, headers: &mut HeaderMap) {
    headers.insert("x-request-id", self.0.clone());
  }
}
impl std::fmt::Display for RequestId {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self.0.to_str() {
      Ok(value) => f.write_str(value),
      Err(_) => {
        for byte in self.0.as_bytes().escape_ascii() {
          write!(f, "{}", char::from(byte))?;
        }
        Ok(())
      }
    }
  }
}
