//! module: redaction
//! responsibility: format diagnostic parameters with secret values
//! masked public operations: Redacted Debug adapter
//! data entities: Redacted, YamlKey
//! tests: redaction_tests.rs

use std::collections::HashMap;
use std::fmt::{self, Debug};

use serde_yaml::Value;

/// A borrowed formatting view; it never changes the underlying values.
/// Only password/token fields (including underscore/hyphen prefixes)
/// are masked. Every other field keeps its normal Debug representation.
pub(crate) struct Redacted<'a, T: ?Sized>(pub(crate) &'a T);

fn is_secret(key: &str) -> bool {
  let field = key.rsplit(['_', '-']).next().unwrap_or(key);
  field.eq_ignore_ascii_case("password")
    || field.eq_ignore_ascii_case("token")
}

impl Debug for Redacted<'_, Value> {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self.0 {
      Value::Mapping(mapping) => {
        formatter.write_str("Mapping ")?;
        let mut debug = formatter.debug_map();
        for (key, value) in mapping {
          if key.as_str().is_some_and(is_secret) {
            debug.entry(&YamlKey(key), &"*");
          } else {
            debug.entry(&YamlKey(key), &Redacted(value));
          }
        }
        debug.finish()
      }
      Value::Sequence(sequence) => {
        formatter.write_str("Sequence ")?;
        formatter
          .debug_list()
          .entries(sequence.iter().map(Redacted))
          .finish()
      }
      Value::Tagged(tagged) => formatter
        .debug_struct("TaggedValue")
        .field("tag", &tagged.tag)
        .field("value", &Redacted(&tagged.value))
        .finish(),
      value => value.fmt(formatter),
    }
  }
}

// Preserve serde_yaml's scalar map-key representation while also
// visiting composite keys, which can themselves contain mappings.
struct YamlKey<'a>(&'a Value);

impl Debug for YamlKey<'_> {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self.0 {
      Value::String(value) => value.fmt(formatter),
      Value::Bool(value) => value.fmt(formatter),
      Value::Number(value) => fmt::Display::fmt(value, formatter),
      value => Redacted(value).fmt(formatter),
    }
  }
}

impl Debug for Redacted<'_, HashMap<String, Value>> {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_map()
      .entries(self.0.iter().map(|(key, value)| (key, Redacted(value))))
      .finish()
  }
}

impl Debug for Redacted<'_, HashMap<String, String>> {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    // This map's values are passwords, regardless of each username.
    formatter
      .debug_map()
      .entries(self.0.keys().map(|key| (key, "*")))
      .finish()
  }
}
