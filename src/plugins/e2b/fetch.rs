//! module: fetch
//! responsibility: implement the conditional HTTP sandbox policy API
//! contract public operations: Api::new, Source::fetch, decode
//! data entities: Api, Envelope
//! tests: fetch_tests.rs, test_e2b_policy.py
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use http_body_util::{BodyExt, Empty, Limited};
use hyper_util::rt::TokioIo;

use super::cache::{Source, Update};
use super::policy::Policy;

pub(super) struct Api {
  uri: http::Uri,
  timeout: Duration,
  tls: Arc<rustls::ClientConfig>,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
  sandbox_id: String,
  policy: serde_json::Value,
}
impl Api {
  pub(super) fn new(url: &str, timeout: Duration) -> Result<Self> {
    let uri: http::Uri = url.parse()?;
    ensure!(
      matches!(uri.scheme_str(), Some("http" | "https"))
        && uri.authority().is_some(),
      "policy_api_url must be an absolute HTTP(S) URL"
    );
    let _ = crate::http_authority::normalize(
      uri.authority().expect("checked authority"),
    )
    .map_err(|_| anyhow::anyhow!("invalid policy API authority"))?;
    ensure!(!timeout.is_zero(), "policy_api_timeout must be positive");
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
      roots.add(cert)?;
    }
    let mut tls = rustls::ClientConfig::builder()
      .with_root_certificates(roots)
      .with_no_client_auth();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Self { uri, timeout, tls: Arc::new(tls) })
  }

  async fn request(
    &self,
    id: &str,
    version: Option<u64>,
  ) -> Result<Update> {
    let host = self
      .uri
      .host()
      .expect("validated API host")
      .trim_start_matches('[')
      .trim_end_matches(']');
    let port = self.uri.port_u16().unwrap_or(
      if self.uri.scheme_str() == Some("https") { 443 } else { 80 },
    );
    let tcp = tokio::net::TcpStream::connect((host, port)).await?;
    let io: Box<dyn crate::stream::Io> =
      if self.uri.scheme_str() == Some("https") {
        let name =
          rustls::pki_types::ServerName::try_from(host.to_owned())?;
        Box::new(
          tokio_rustls::TlsConnector::from(self.tls.clone())
            .connect(name, tcp)
            .await?,
        )
      } else {
        Box::new(tcp)
      };
    let (mut sender, connection) =
      hyper::client::conn::http1::handshake(TokioIo::new(io)).await?;
    let path =
      self.uri.path_and_query().map_or("/", |value| value.as_str());
    let encoded: String = id
      .bytes()
      .map(|b| {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
          char::from(b).to_string()
        } else {
          format!("%{b:02X}")
        }
      })
      .collect();
    let target = format!(
      "{path}{}sandbox_id={encoded}",
      if self.uri.query().is_some() { "&" } else { "?" }
    );
    let mut builder = http::Request::builder()
      .uri(target)
      .header(
        "host",
        self.uri.authority().expect("API authority").as_str(),
      )
      .header("accept", "application/json")
      .header("connection", "close");
    if let Some(version) = version {
      builder =
        builder.header("if-none-match", format!("\"{version}\""));
    }
    let exchange = async {
      let response = sender
        .send_request(builder.body(Empty::<bytes::Bytes>::new())?)
        .await?;
      let (parts, body) = response.into_parts();
      let body = Limited::new(body, 1024 * 1024)
        .collect()
        .await
        .map_err(anyhow::Error::from_boxed)?
        .to_bytes();
      decode(parts.status, &parts.headers, &body, id, version)
    };
    tokio::pin!(exchange);
    tokio::pin!(connection);
    tokio::select! {
      result = &mut exchange => result,
      result = &mut connection => { result?; exchange.await },
    }
  }
}
impl Source for Api {
  fn fetch<'a>(
    &'a self,
    id: &'a str,
    version: Option<u64>,
  ) -> Pin<Box<dyn Future<Output = Result<Update>> + Send + 'a>> {
    Box::pin(async move {
      tokio::time::timeout(self.timeout, self.request(id, version))
        .await
        .context("policy API request timed out")?
    })
  }
}
pub(super) fn decode(
  status: http::StatusCode,
  headers: &http::HeaderMap,
  body: &[u8],
  id: &str,
  current: Option<u64>,
) -> Result<Update> {
  ensure!(
    status == http::StatusCode::OK
      || status == http::StatusCode::NOT_MODIFIED,
    "policy API returned {status}"
  );
  let field = |name: &'static str| -> Result<&str> {
    let mut values = headers.get_all(name).iter();
    let value =
      values.next().context("missing policy response header")?;
    ensure!(
      values.next().is_none(),
      "duplicate policy response header"
    );
    Ok(value.to_str()?)
  };
  let etag = field("etag")?;
  let version = etag
    .strip_prefix('"')
    .and_then(|v| v.strip_suffix('"'))
    .context("ETag must be a quoted decimal version")?
    .parse::<u64>()?;
  ensure!(
    version > 0 && etag == format!("\"{version}\""),
    "invalid policy ETag"
  );
  let ttl = field("x-policy-ttl")?.parse::<u32>()?;
  ensure!(ttl > 0, "policy TTL must be positive");
  let ttl = Duration::from_secs(u64::from(ttl));
  if status == http::StatusCode::NOT_MODIFIED {
    ensure!(
      current == Some(version) && body.is_empty(),
      "304 must match a cached policy and have no body"
    );
    return Ok(Update::Unmodified { version, ttl });
  }
  let envelope: Envelope = serde_json::from_slice(body)?;
  ensure!(envelope.sandbox_id == id, "policy sandbox_id mismatch");
  Ok(Update::Modified {
    version,
    ttl,
    policy: Arc::new(Policy::parse(envelope.policy)?),
  })
}
