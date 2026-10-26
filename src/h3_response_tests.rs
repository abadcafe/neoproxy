//! Black-box contracts for streaming HTTP/3 responses.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body::Frame;
use http_body_util::{BodyExt, StreamBody};

use crate::h3_response::{ResponseSink, ResponseWriter};
use crate::http_message::{
  BytesBufBodyWrapper, Response, ResponseBody,
};

#[derive(Clone, Default)]
struct RecordingSink {
  events: Arc<Mutex<Vec<String>>>,
}

impl ResponseSink for RecordingSink {
  async fn headers(
    &mut self,
    response: http::Response<()>,
  ) -> anyhow::Result<()> {
    self
      .events
      .lock()
      .unwrap()
      .push(format!("status:{}", response.status().as_u16()));
    assert!(!response.headers().contains_key("connection"));
    Ok(())
  }

  async fn data(&mut self, data: Bytes) -> anyhow::Result<()> {
    self
      .events
      .lock()
      .unwrap()
      .push(String::from_utf8(data.to_vec()).unwrap());
    Ok(())
  }

  async fn trailers(
    &mut self,
    trailers: http::HeaderMap,
  ) -> anyhow::Result<()> {
    assert!(!trailers.contains_key("content-length"));
    self.events.lock().unwrap().push("trailers".into());
    Ok(())
  }

  async fn finish(&mut self) -> anyhow::Result<()> {
    self.events.lock().unwrap().push("finish".into());
    Ok(())
  }

  fn cancel(&mut self) {
    self.events.lock().unwrap().push("cancel".into());
  }
}

#[tokio::test]
async fn test_send_streams_error_response_before_polling_next_body_frame()
 {
  let sink = RecordingSink::default();
  let events = sink.events.clone();
  let observation = events.clone();
  let frames = futures::stream::unfold(0, move |step| {
    let observation = observation.clone();
    async move {
      match step {
        0 => Some((
          Ok::<_, std::io::Error>(Frame::data(Bytes::from_static(
            b"first",
          ))),
          1,
        )),
        1 => {
          assert_eq!(
            &*observation.lock().unwrap(),
            &["status:502", "first"]
          );
          Some((Ok(Frame::data(Bytes::from_static(b"second"))), 2))
        }
        _ => None,
      }
    }
  });
  let mut response = Response::new(ResponseBody::new(
    BytesBufBodyWrapper::new(StreamBody::new(frames)),
  ));
  *response.status_mut() = http::StatusCode::BAD_GATEWAY;
  response.headers_mut().insert("connection", "close".parse().unwrap());
  ResponseWriter::new(sink)
    .send(response, &http::Method::CONNECT)
    .await
    .unwrap();
  assert_eq!(
    &*events.lock().unwrap(),
    &["status:502", "first", "second", "finish"]
  );
}

#[tokio::test]
async fn test_send_suppresses_forbidden_payloads_without_polling_body()
{
  for (method, status) in [
    (http::Method::HEAD, http::StatusCode::OK),
    (http::Method::GET, http::StatusCode::NO_CONTENT),
    (http::Method::GET, http::StatusCode::RESET_CONTENT),
    (http::Method::GET, http::StatusCode::NOT_MODIFIED),
  ] {
    let sink = RecordingSink::default();
    let events = sink.events.clone();
    let body = futures::stream::pending::<
      Result<Frame<Bytes>, std::io::Error>,
    >();
    let mut response = Response::new(ResponseBody::new(
      BytesBufBodyWrapper::new(StreamBody::new(body)),
    ));
    *response.status_mut() = status;
    tokio::time::timeout(
      std::time::Duration::from_secs(1),
      ResponseWriter::new(sink).send(response, &method),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
      &*events.lock().unwrap(),
      &[format!("status:{}", status.as_u16()), "finish".into()]
    );
  }
}

#[tokio::test]
async fn test_send_cancels_response_on_body_failure() {
  let sink = RecordingSink::default();
  let events = sink.events.clone();
  let body =
    StreamBody::new(futures::stream::iter([Err::<Frame<Bytes>, _>(
      std::io::Error::other("body failed"),
    )]))
    .boxed_unsync();
  let response =
    Response::new(ResponseBody::new(BytesBufBodyWrapper::new(body)));
  assert!(
    ResponseWriter::new(sink)
      .send(response, &http::Method::GET)
      .await
      .is_err()
  );
  assert_eq!(&*events.lock().unwrap(), &["status:200", "cancel"]);
}
