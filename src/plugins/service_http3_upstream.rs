use std::collections::HashMap;
use std::net as std_net;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{Result, anyhow};
use h3_quinn::quinn;
use rustls::pki_types::CertificateDer;
use rustls_native_certs::CertificateResult;
use tokio::net;
use tracing::{error, info, log};

use crate::plugin;

static ALPN: &[u8] = b"h3";

struct Upstream {
  addresses: Vec<std_net::SocketAddr>,
  ca_path: PathBuf,
}

impl Upstream {
  fn new(
    ca_path: PathBuf,
    addresses: Vec<std_net::SocketAddr>,
  ) -> Self {
    Self { addresses, ca_path }
  }

  async fn get_connection(&self) -> Result<h3_quinn::Connection> {
    let mut roots = rustls::RootCertStore::empty();
    let CertificateResult { certs, errors, .. } =
      rustls_native_certs::load_native_certs();
    for cert in certs {
      if let Err(e) = roots.add(cert) {
        error!("failed to parse trust anchor: {}", e);
      }
    }
    for e in errors {
      error!("couldn't load default trust roots: {}", e);
    }

    // load certificate of CA who issues the server certificate
    // NOTE that this should be used for dev only
    if let Err(e) = roots
      .add(CertificateDer::from(std::fs::read(self.ca_path.as_path())?))
    {
      error!("failed to parse trust anchor: {}", e);
    }

    let mut tls_config = rustls::ClientConfig::builder()
      .with_root_certificates(roots)
      .with_no_client_auth();

    tls_config.enable_early_data = true;
    tls_config.alpn_protocols = vec![ALPN.into()];

    // Write all Keys to a file if SSLKEYLOGFILE is set
    // WARNING, we enable this for the example, you should think
    // carefully about enabling in your own code
    tls_config.key_log = Arc::new(rustls::KeyLogFile::new());

    let mut client_endpoint =
      h3_quinn::quinn::Endpoint::client("[::]:0".parse().unwrap())?;

    let client_config = quinn::ClientConfig::new(Arc::new(
      quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)?,
    ));
    client_endpoint.set_default_client_config(client_config);

    let conn = client_endpoint
      .connect(
        self.addresses[0],
        self.addresses[0].to_string().as_str(),
      )?
      .await?;

    info!("QUIC connection established");

    // create h3 client

    // h3 is designed to work with different QUIC implementations via
    // a generic interface, that is, the [`quic::Connection`] trait.
    // h3_quinn implements the trait w/ quinn to make it work with h3.
    let quinn_conn = h3_quinn::Connection::new(conn);
    Ok(quinn_conn)
  }
}

struct Http3UpstreamService {
  upstream: Upstream,
}

fn build_empty_response(
  status_code: http::status::StatusCode,
) -> plugin::Response {
  let empty = http_body_util::Empty::new();
  let bytes_buf = plugin::BytesBufBodyWrapper::new(empty);
  let body = plugin::ResponseBody::new(bytes_buf);
  let mut resp = plugin::Response::new(body);
  *resp.status_mut() = status_code;
  resp
}

impl tower::Service<plugin::Request> for Http3UpstreamService {
  type Error = anyhow::Error;
  type Future = Pin<Box<dyn Future<Output = Result<plugin::Response>>>>;
  type Response = plugin::Response;

  fn poll_ready(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<Result<(), Self::Error>> {
    Poll::Ready(Ok(()))
  }

  fn call(&mut self, req: plugin::Request) -> Self::Future {
    Box::pin(async move {
      if !req.method().as_str().eq_ignore_ascii_case("CONNECT") {
        return Ok(build_empty_response(http::StatusCode::BAD_REQUEST));
      }

      let (dest_host, dest_port) = {
        let dest = match req.uri().authority() {
          None => {
            return Ok(build_empty_response(
              http::StatusCode::BAD_REQUEST,
            ));
          }
          Some(dest) => dest,
        };

        let port = match dest.port_u16() {
          None => {
            return Ok(build_empty_response(
              http::StatusCode::BAD_REQUEST,
            ));
          }
          Some(port) => port,
        };

        if port < 1 {
          return Ok(build_empty_response(
            http::StatusCode::BAD_REQUEST,
          ));
        }

        (dest.host(), port)
      };

      let dest_addr = net::lookup_host((dest_host, dest_port))
        .await?
        .next()
        .ok_or(anyhow!("dns found no addresses"))?;

      Err(anyhow!("todo!"))
    })
  }
}

struct Http3UpstreamPlugin {}

impl<'a> plugin::Plugin<'a> for Http3UpstreamPlugin {
  fn name(&self) -> &'a str {
    "http3_upstream"
  }

  fn service_factories(
    &self,
  ) -> HashMap<&'a str, Box<dyn plugin::ServiceFactory>> {
    HashMap::new()
  }
}

pub fn create_plugin() -> Box<dyn plugin::Plugin<'static>> {
  Box::new(Http3UpstreamPlugin {})
}
