//! module: value
//! responsibility: retain native context values until output
//! serialization public operations: ContextValue, ContextType, From,
//! Display, Serialize data entities: ContextValue, Kind
//! tests: value_tests.rs
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use serde::{Serialize, Serializer};
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ContextValue(Kind);
#[derive(Clone, Debug, PartialEq)]
enum Kind {
  Text(Arc<str>),
  Unsigned(u64),
  Signed(i64),
  Boolean(bool),
  Elapsed(Duration),
  Ip(IpAddr),
  Address(SocketAddr),
  Addresses(Arc<[IpAddr]>),
  Identity(crate::request_id::RequestId),
}
mod sealed {
  pub trait Sealed {}
}
pub(crate) trait ContextType: sealed::Sealed + Clone {
  fn into_value(self) -> ContextValue;
  fn from_value(value: &ContextValue) -> Option<Self>;
}
macro_rules! native {
  ($type:ty, $variant:ident) => {
    impl sealed::Sealed for $type {}
    impl ContextType for $type {
      fn into_value(self) -> ContextValue {
        ContextValue(Kind::$variant(self))
      }

      fn from_value(value: &ContextValue) -> Option<Self> {
        if let Kind::$variant(value) = &value.0 {
          Some(value.clone())
        } else {
          None
        }
      }
    }
    impl From<$type> for ContextValue {
      fn from(value: $type) -> Self {
        value.into_value()
      }
    }
  };
}
native!(Arc<str>, Text);
native!(u64, Unsigned);
native!(i64, Signed);
native!(bool, Boolean);
native!(Duration, Elapsed);
native!(IpAddr, Ip);
native!(SocketAddr, Address);
native!(Arc<[IpAddr]>, Addresses);
native!(crate::request_id::RequestId, Identity);
impl From<&str> for ContextValue {
  fn from(value: &str) -> Self {
    Self::from(Arc::<str>::from(value))
  }
}
impl From<String> for ContextValue {
  fn from(value: String) -> Self {
    Self::from(Arc::<str>::from(value))
  }
}
impl Serialize for ContextValue {
  fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
    match &self.0 {
      Kind::Text(v) => s.serialize_str(v),
      Kind::Unsigned(v) => s.serialize_u64(*v),
      Kind::Signed(v) => s.serialize_i64(*v),
      Kind::Boolean(v) => s.serialize_bool(*v),
      Kind::Elapsed(v) => s.serialize_u128(v.as_millis()),
      Kind::Ip(v) => s.collect_str(v),
      Kind::Address(v) => s.collect_str(v),
      Kind::Addresses(v) => {
        s.collect_seq(v.iter().map(ToString::to_string))
      }
      Kind::Identity(v) => s.collect_str(v),
    }
  }
}
impl std::fmt::Display for ContextValue {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match &self.0 {
      Kind::Text(v) => f.write_str(v),
      Kind::Unsigned(v) => write!(f, "{v}"),
      Kind::Signed(v) => write!(f, "{v}"),
      Kind::Boolean(v) => write!(f, "{v}"),
      Kind::Elapsed(v) => write!(f, "{}", v.as_millis()),
      Kind::Ip(v) => write!(f, "{v}"),
      Kind::Address(v) => write!(f, "{v}"),
      Kind::Identity(v) => write!(f, "{v}"),
      Kind::Addresses(v) => {
        for (index, value) in v.iter().enumerate() {
          if index != 0 {
            f.write_str(",")?;
          }
          write!(f, "{value}")?;
        }
        Ok(())
      }
    }
  }
}
