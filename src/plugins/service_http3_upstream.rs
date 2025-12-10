use std::collections::HashMap;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::net;

use anyhow::{Result, anyhow};

use crate::plugin;

struct Http3UpstreamService {}

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

      let addr = net::lookup_host((dest_host, dest_port))
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
