//! module: proxy_status
//! responsibilities: serialize Proxy-Status fields at a proxy boundary
//! public operations: build_proxy_status_error,
//! build_proxy_status_with_status, append_proxy_status,
//! take_proxy_status data entities: none tests: proxy_status_tests.rs

/// Build a Proxy-Status header value with an error parameter.
pub(crate) fn build_proxy_status_error(
  identifier: &str,
  error: &str,
) -> http::HeaderValue {
  let error = if is_token(error) { error } else { "unknown" };
  let val = format!("{}; error={error}", identifier_value(identifier));
  http::HeaderValue::from_str(&val).unwrap_or_else(|_| {
    http::HeaderValue::from_static("neoproxy; error=unknown")
  })
}

/// Build a Proxy-Status header value with received-status only (no
/// error).
pub(crate) fn build_proxy_status_with_status(
  identifier: &str,
  status: u16,
) -> http::HeaderValue {
  let val = format!(
    "{}; received-status={status}",
    identifier_value(identifier)
  );
  http::HeaderValue::from_str(&val)
    .unwrap_or_else(|_| http::HeaderValue::from_static("neoproxy"))
}

/// Append a new entry to an existing Proxy-Status Structured Fields
/// List value.
///
/// Per RFC 9209 Section 2, intermediaries SHOULD preserve existing
/// members of the Proxy-Status field to allow debugging of the entire
/// chain.  This function combines the existing value (e.g. from the
/// upstream proxy) with the current proxy's entry by comma-separating
/// them as required by the Structured Fields List format.
pub(crate) fn append_proxy_status(
  existing: Option<&http::HeaderValue>,
  new_entry: &http::HeaderValue,
) -> http::HeaderValue {
  match existing {
    Some(existing_val)
      if existing_val.to_str().is_ok_and(|value| !value.is_empty()) =>
    {
      let combined = format!(
        "{}, {}",
        existing_val.to_str().unwrap_or(""),
        new_entry.to_str().unwrap_or("")
      );
      http::HeaderValue::from_str(&combined)
        .unwrap_or_else(|_| new_entry.clone())
    }
    _ => new_entry.clone(),
  }
}

/// Consume every field line as one ordered Structured Fields list.
pub(crate) fn take_proxy_status(
  headers: &mut http::HeaderMap,
) -> Option<http::HeaderValue> {
  let mut combined = Vec::new();
  for field in headers.get_all("proxy-status") {
    if field.as_bytes().is_empty() {
      continue;
    }
    if !combined.is_empty() {
      combined.extend_from_slice(b", ");
    }
    combined.extend_from_slice(field.as_bytes());
  }
  headers.remove("proxy-status");
  if combined.is_empty() {
    None
  } else {
    Some(
      http::HeaderValue::from_bytes(&combined).expect(
        "joining valid field lines preserves field value syntax",
      ),
    )
  }
}

fn identifier_value(identifier: &str) -> String {
  if is_token(identifier) {
    return identifier.to_owned();
  }
  if identifier.bytes().all(|byte| (0x20..=0x7e).contains(&byte)) {
    format!(
      "\"{}\"",
      identifier.replace('\\', "\\\\").replace('"', "\\\"")
    )
  } else {
    "neoproxy".into()
  }
}

fn is_token(value: &str) -> bool {
  value
    .as_bytes()
    .first()
    .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'*')
    && value.bytes().all(|byte| {
      byte.is_ascii_alphanumeric()
        || b"!#$%&'*+-.^_`|~:/".contains(&byte)
    })
}
