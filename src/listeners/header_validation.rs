//! module: header_validation
//! responsibilities: select a validated routing authority for incoming
//! HTTP requests public operations: authority_host_mismatch,
//! validate_and_route data entities: none
//! tests: header_validation_tests.rs

use std::rc::Rc;

use crate::http_authority;
use crate::http_message::{Response, build_error_response};
use crate::server::{Server, ServerRouter};

pub(crate) fn authority_host_mismatch(
  authority: &str,
  host: &str,
) -> bool {
  let Ok(authority) = authority.parse::<http::uri::Authority>() else {
    return true;
  };
  let Ok(host) = host.parse::<http::uri::Authority>() else {
    return true;
  };
  crate::hostname::normalize(authority.host())
    != crate::hostname::normalize(host.host())
    || authority.port_u16() != host.port_u16()
}

pub(crate) fn validate_and_route<B>(
  req: &http::Request<B>,
  router: &ServerRouter,
) -> Result<Rc<Server>, Box<Response>> {
  let bad_request = || {
    Box::new(build_error_response(
      http::StatusCode::BAD_REQUEST,
      "Bad Request: invalid authority or Host",
    ))
  };
  let mut hosts = req.headers().get_all(http::header::HOST).iter();
  let host = hosts
    .next()
    .map(|value| value.to_str().map_err(|_| bad_request()))
    .transpose()?;
  if hosts.next().is_some() {
    return Err(bad_request());
  }
  let host_authority = host
    .map(|host| {
      let authority = host
        .parse::<http::uri::Authority>()
        .map_err(|_| bad_request())?;
      http_authority::normalize(&authority).map_err(|_| bad_request())
    })
    .transpose()?;
  // HTTP/1.1 requires a Host field even for absolute-form requests.
  if req.version() == http::Version::HTTP_11 && host.is_none() {
    return Err(bad_request());
  }
  let authority = req.uri().authority();
  if let Some(authority) = authority
    && req.version() == http::Version::HTTP_3
    && host.is_some_and(|host| {
      authority_host_mismatch(authority.as_str(), host)
    })
  {
    return Err(bad_request());
  }
  let normalized_authority = authority
    .map(http_authority::normalize)
    .transpose()
    .map_err(|_| bad_request())?;
  // RFC 9112 §3.2.2: absolute-form target replaces the supplied Host.
  let authority =
    normalized_authority.as_ref().or(host_authority.as_ref());
  if authority.is_none() {
    return Err(bad_request());
  }
  router.route(authority.map(http::uri::Authority::host)).ok_or_else(
    || Box::new(super::error_response::build_404_response()),
  )
}
