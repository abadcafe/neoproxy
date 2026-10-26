//! module: alt_svc
//! responsibility: cache authenticated origin alternative-service
//! advertisements public operations: AltServices::{observe,routes};
//! data entities: AltServices, Entry tests: alt_svc_tests.rs

use std::collections::HashMap;
use std::time::Duration;

use http::HeaderMap;
use tokio::time::Instant;

use super::origin::{Origin, Route, WireProtocol};

#[derive(Default)]
pub(super) struct AltServices {
  entries: HashMap<Origin, Vec<Entry>>,
}
struct Entry {
  route: Route,
  expires: Instant,
}

impl AltServices {
  pub(super) fn invalidate(&mut self, origin: &Origin) {
    self.entries.remove(origin);
  }

  pub(super) fn routes(
    &mut self,
    origin: &Origin,
    now: Instant,
  ) -> Vec<Route> {
    let Some(entries) = self.entries.get_mut(origin) else {
      return Vec::new();
    };
    entries.retain(|entry| entry.expires > now);
    let routes =
      entries.iter().map(|entry| entry.route.clone()).collect();
    if entries.is_empty() {
      self.entries.remove(origin);
    }
    routes
  }

  pub(super) fn observe(
    &mut self,
    origin: &Origin,
    headers: &HeaderMap,
    now: Instant,
  ) {
    if !origin.is_https()
      || !headers.contains_key("alt-svc")
      || headers
        .get_all("connection")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|v| v.trim().eq_ignore_ascii_case("alt-svc"))
    {
      return;
    }
    let Some(value) = headers
      .get_all("alt-svc")
      .iter()
      .map(|v| v.to_str().ok())
      .collect::<Option<Vec<_>>>()
      .map(|v| v.join(","))
    else {
      return;
    };
    if value.trim() == "clear" {
      self.entries.remove(origin);
      return;
    }
    let age = headers
      .get("age")
      .and_then(|v| v.to_str().ok())
      .and_then(decimal_seconds)
      .unwrap_or(0);
    let Some(advertisements) = split(&value, ',') else {
      return;
    };
    if advertisements.iter().any(|value| value.trim() == "clear") {
      self.entries.remove(origin);
      return;
    }
    let mut entries = Vec::new();
    for advertisement in advertisements {
      let Some((route, lifetime)) = parse(advertisement, origin) else {
        continue;
      };
      let Some(expires) = now
        .checked_add(Duration::from_secs(lifetime.saturating_sub(age)))
      else {
        continue;
      };
      if expires > now {
        entries.push(Entry { route, expires });
      }
    }
    // A new field replaces the origin's previous advertisement set.
    if entries.is_empty() {
      self.entries.remove(origin);
      return;
    }
    if self.entries.len() >= 1024 && !self.entries.contains_key(origin)
    {
      // Maintenance is paid only when admitting another origin at
      // capacity, never by every request or by an in-place refresh.
      self.entries.retain(|_, entries| {
        entries.iter().any(|entry| entry.expires > now)
      });
      if self.entries.len() >= 1024
        && let Some(oldest) = self
          .entries
          .iter()
          .min_by_key(|(_, entries)| {
            entries.iter().map(|entry| entry.expires).max()
          })
          .map(|(origin, _)| origin.clone())
      {
        self.entries.remove(&oldest);
      }
    }
    self.entries.insert(origin.clone(), entries);
  }
}

fn parse(value: &str, origin: &Origin) -> Option<(Route, u64)> {
  let mut fields = split(value, ';')?.into_iter();
  let (protocol, address) = fields.next()?.trim().split_once('=')?;
  let protocol = match protocol.trim() {
    "h3" => WireProtocol::Http3,
    "h2" => WireProtocol::Http2,
    "http%2F1.1" | "http/1.1" => WireProtocol::Http1,
    _ => return None,
  };
  let address = quoted(address.trim())?;
  let address = if address.starts_with(':') {
    format!(
      "{}{}",
      if origin.host().contains(':') {
        format!("[{}]", origin.host())
      } else {
        origin.host().to_owned()
      },
      address
    )
  } else {
    address
  };
  if address.contains('@') {
    return None;
  }
  let authority: http::uri::Authority = address.parse().ok()?;
  let port = authority.port_u16().filter(|port| *port != 0)?;
  let host = authority
    .host()
    .trim_start_matches('[')
    .trim_end_matches(']')
    .to_ascii_lowercase();
  if host.is_empty() {
    return None;
  }
  let mut lifetime = None;
  for field in fields {
    let (name, value) = field.trim().split_once('=')?;
    if name.trim().eq_ignore_ascii_case("ma") {
      if lifetime.is_some() {
        return None;
      }
      let value = value.trim();
      let value = if value.starts_with('"') {
        quoted(value)?
      } else {
        value.to_owned()
      };
      if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
      {
        return None;
      }
      lifetime = Some(decimal_seconds(&value)?);
    }
  }
  Some((Route { host, port, protocol }, lifetime.unwrap_or(86400)))
}

// HTTP delta-seconds have no integer-width limit. RFC 9111 §1.2.2
// permits saturation at 2^31 for overflow; use the same bounded domain
// for Age and ma so an enormous Age cannot become zero and an enormous
// lifetime cannot overflow Instant and discard a valid advertisement.
fn decimal_seconds(value: &str) -> Option<u64> {
  if value.is_empty()
    || !value.bytes().all(|byte| byte.is_ascii_digit())
  {
    return None;
  }
  Some(value.bytes().fold(0_u64, |seconds, digit| {
    (seconds * 10 + u64::from(digit - b'0')).min(1 << 31)
  }))
}

fn quoted(value: &str) -> Option<String> {
  let value = value.strip_prefix('"')?.strip_suffix('"')?;
  let mut output = String::new();
  let mut escaped = false;
  for character in value.chars() {
    if escaped {
      output.push(character);
      escaped = false;
    } else if character == '\\' {
      escaped = true;
    } else if character == '"' {
      return None;
    } else {
      output.push(character);
    }
  }
  if escaped { None } else { Some(output) }
}

fn split(value: &str, separator: char) -> Option<Vec<&str>> {
  let (mut quoted, mut escaped, mut start) = (false, false, 0);
  let mut parts = Vec::new();
  for (index, character) in value.char_indices() {
    if escaped {
      escaped = false;
      continue;
    }
    if quoted && character == '\\' {
      escaped = true;
    } else if character == '"' {
      quoted = !quoted;
    } else if !quoted && character == separator {
      parts.push(&value[start..index]);
      start = index + 1;
    }
  }
  if quoted || escaped {
    return None;
  }
  parts.push(&value[start..]);
  Some(parts)
}
