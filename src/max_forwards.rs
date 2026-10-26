//! module: max_forwards
//! responsibility: enforce the TRACE/OPTIONS forwarding boundary
//! public operations: apply
//! data entities: none
//! tests: max_forwards_tests.rs

use crate::http_message::{
  Response, build_empty_response, build_error_response,
};

/// RFC 9110 §7.6.2: zero makes this proxy the final recipient.
/// Decimal input has no protocol integer width limit. Saturating at
/// 256 permits decrementing/capping without rejecting large values.
pub(crate) fn apply<B>(
  request: &mut http::Request<B>,
) -> Option<Response> {
  if request.method() != http::Method::TRACE
    && request.method() != http::Method::OPTIONS
  {
    return None;
  }
  let mut fields =
    request.headers().get_all(http::header::MAX_FORWARDS).iter();
  let field = fields.next()?;
  let bytes = field.as_bytes();
  if fields.next().is_some()
    || bytes.is_empty()
    || !bytes.iter().all(u8::is_ascii_digit)
  {
    return Some(build_error_response(
      http::StatusCode::BAD_REQUEST,
      "Invalid Max-Forwards",
    ));
  }
  let value = bytes.iter().fold(0_u16, |value, digit| {
    (value * 10 + u16::from(digit - b'0')).min(256)
  });
  if value == 0 {
    return Some(if request.method() == http::Method::OPTIONS {
      build_empty_response(http::StatusCode::NO_CONTENT)
    } else {
      let mut response =
        build_empty_response(http::StatusCode::METHOD_NOT_ALLOWED);
      response.headers_mut().insert(
        http::header::ALLOW,
        http::HeaderValue::from_static("OPTIONS"),
      );
      response
    });
  }
  request.headers_mut().insert(
    http::header::MAX_FORWARDS,
    (value - 1).to_string().parse().expect("decimal forwarding limit"),
  );
  None
}
