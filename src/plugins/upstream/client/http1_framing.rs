//! module: http1_framing
//! responsibility: preserve streaming content at HTTP/1 egress
//! public operations: prepare_request, prepare_response
//! data entities: none
//! tests: http1_framing_tests.rs, forward_tests.rs

use http_body::Body;

use crate::http_message::{Request, Response};

/// Hyper assumes an unknown-length GET/HEAD has no content unless its
/// framing is explicit. Normalized H3/H2 bodies and decoded HTTP/1
/// chunked bodies must retain their content when converted to HTTP/1.
/// H3 never passes through this HTTP/1 client adapter.
pub(super) fn prepare_request(request: &mut Request) {
  *request.version_mut() = http::Version::HTTP_11;
  if !request.body().is_end_stream()
    && (request.headers().contains_key(http::header::TRAILER)
      || (!request
        .headers()
        .contains_key(http::header::CONTENT_LENGTH)
        && request.body().size_hint().exact().is_none()))
  {
    request.headers_mut().remove(http::header::CONTENT_LENGTH);
    request.headers_mut().insert(
      http::header::TRANSFER_ENCODING,
      http::HeaderValue::from_static("chunked"),
    );
  }
}

/// A declared trailer section needs chunked HTTP/1 framing even when
/// the body has an exact size hint. Removing Content-Length alone lets
/// Hyper select a length encoder again and silently discard trailers.
pub(super) fn prepare_response(response: &mut Response) {
  if !response.body().is_end_stream()
    && response.headers().contains_key(http::header::TRAILER)
    && !response.status().is_informational()
    && !matches!(
      response.status(),
      http::StatusCode::NO_CONTENT
        | http::StatusCode::RESET_CONTENT
        | http::StatusCode::NOT_MODIFIED
    )
  {
    response.headers_mut().remove(http::header::CONTENT_LENGTH);
    response.headers_mut().insert(
      http::header::TRANSFER_ENCODING,
      http::HeaderValue::from_static("chunked"),
    );
  }
}
