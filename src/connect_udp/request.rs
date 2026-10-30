//! module: request
//! responsibility: validate and construct the default RFC 9298 URI
//! template public operations: Udp, recognize, target, apply
//! data entities: Udp
//! tests: connect_udp_tests.rs
#[derive(Clone, Debug)]
pub(crate) struct Udp {
  pub(crate) authority: String,
  pub(crate) path: String,
  pub(crate) http1: bool,
}
fn token(headers: &http::HeaderMap, name: &str, token: &str) -> bool {
  headers
    .get_all(name)
    .iter()
    .filter_map(|v| v.to_str().ok())
    .flat_map(|v| v.split(','))
    .any(|v| v.trim().eq_ignore_ascii_case(token))
}
pub(crate) fn recognize(
  parts: &http::request::Parts,
) -> anyhow::Result<Option<Udp>> {
  let h3 = parts
    .extensions
    .get::<h3::ext::Protocol>()
    .is_some_and(|p| p.as_str() == "connect-udp");
  let h1 = token(&parts.headers, "upgrade", "connect-udp");
  if !h3 && !h1 {
    return Ok(None);
  }
  anyhow::ensure!(
    (h3
      && parts.method == http::Method::CONNECT
      && parts.version == http::Version::HTTP_3)
      || (h1
        && parts.method == http::Method::GET
        && parts.version == http::Version::HTTP_11
        && token(&parts.headers, "connection", "upgrade")),
    "invalid CONNECT-UDP negotiation"
  );
  super::negotiation::validate_headers(&parts.headers)?;
  target(parts.uri.path())?;
  Ok(Some(Udp {
    authority: parts
      .uri
      .authority()
      .map(|a| a.as_str())
      .or_else(|| {
        parts.headers.get("host").and_then(|v| v.to_str().ok())
      })
      .unwrap_or("")
      .to_owned(),
    path: parts.uri.path().to_owned(),
    http1: h1,
  }))
}
pub(crate) fn target(path: &str) -> anyhow::Result<String> {
  let rest = path
    .strip_prefix("/.well-known/masque/udp/")
    .and_then(|v| v.strip_suffix('/'))
    .ok_or_else(|| anyhow::anyhow!("invalid UDP template"))?;
  let (host, port) = rest
    .split_once('/')
    .ok_or_else(|| anyhow::anyhow!("missing UDP port"))?;
  let mut decoded = Vec::new();
  let mut it = host.bytes();
  while let Some(byte) = it.next() {
    if byte == b'%' {
      let a = it.next().and_then(|b| (b as char).to_digit(16));
      let b = it.next().and_then(|b| (b as char).to_digit(16));
      decoded.push(match (a, b) {
        (Some(a), Some(b)) => (a * 16 + b) as u8,
        _ => anyhow::bail!("invalid percent escape"),
      });
    } else {
      decoded.push(byte);
    }
  }
  let host = String::from_utf8(decoded)?;
  anyhow::ensure!(
    !host.is_empty()
      && host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b".-:_".contains(&b)),
    "invalid UDP host"
  );
  if host.contains(':') {
    host.parse::<std::net::Ipv6Addr>()?;
  }
  anyhow::ensure!(
    !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()),
    "invalid UDP port"
  );
  let port = port.parse::<u16>()?;
  anyhow::ensure!(port != 0, "UDP port is zero");
  Ok(if host.contains(':') {
    format!("[{host}]:{port}")
  } else {
    format!("{host}:{port}")
  })
}
pub(crate) fn apply(req: &mut http::Request<()>, udp: &Udp, h3: bool) {
  *req.uri_mut() = format!("https://{}{}", udp.authority, udp.path)
    .parse()
    .expect("validated UDP URI");
  req.headers_mut().insert(
    "host",
    udp.authority.parse().expect("validated proxy authority"),
  );
  req
    .headers_mut()
    .insert("capsule-protocol", http::HeaderValue::from_static("?1"));
  if h3 {
    *req.method_mut() = http::Method::CONNECT;
    req.extensions_mut().insert(h3::ext::Protocol::CONNECT_UDP);
  } else {
    *req.method_mut() = http::Method::GET;
    req
      .headers_mut()
      .insert("connection", http::HeaderValue::from_static("Upgrade"));
    req
      .headers_mut()
      .insert("upgrade", http::HeaderValue::from_static("connect-udp"));
  }
}
