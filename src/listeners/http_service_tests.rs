//! Public dispatch contracts shared by all HTTP listener transports.

use std::future::Future;
use std::pin::Pin;

use anyhow::Result;
use http::{StatusCode, Version};

use super::http_service::HttpService;
use crate::context::RequestContext;
use crate::http_message::{
  Request, RequestBody, Response, build_error_response,
};
use crate::server::{Server, ServerRouter};
use crate::service::Service;

fn router(require_cert: bool) -> ServerRouter {
  let service = Service::new(tower::service_fn(|request: Request| {
    Box::pin(async move {
      let context =
        request.extensions().get::<RequestContext>().unwrap();
      assert_eq!(
        context.client_addr().unwrap().to_string(),
        "127.0.0.1:1234"
      );
      assert_eq!(
        context.server_addr().unwrap().to_string(),
        "127.0.0.1:8080"
      );
      assert_eq!(context.service_name(), Some("routed"));
      assert_eq!(request.headers()["cookie"], "first=1; second=2");
      assert_eq!(request.extensions().get::<u32>(), Some(&42));
      Ok(build_error_response(StatusCode::OK, "dispatched"))
    }) as Pin<Box<dyn Future<Output = Result<Response>>>>
  }));
  ServerRouter::build(vec![Server {
    hostnames: vec!["example.test".into()],
    service,
    service_name: "routed".into(),
    tls: require_cert.then(|| {
      serde_yaml::from_str(
        "certificates: []\nclient_ca_certs: \
         [unused-for-presence-policy.pem]\n",
      )
      .unwrap()
    }),
  }])
}

fn request(version: Version) -> Request {
  let mut request = http::Request::builder()
    .uri("http://example.test/resource")
    .version(version)
    .header("host", "example.test")
    .header("cookie", "first=1")
    .header("cookie", "second=2")
    .body(RequestBody::new(
      crate::http_message::BytesBufBodyWrapper::new(
        http_body_util::Empty::<bytes::Bytes>::new(),
      ),
    ))
    .unwrap();
  request.extensions_mut().insert(42_u32);
  request
}

#[tokio::test]
async fn test_dispatch_routes_injects_context_and_normalizes_cookies_for_all_versions()
 {
  for version in [
    Version::HTTP_10,
    Version::HTTP_11,
    Version::HTTP_2,
    Version::HTTP_3,
  ] {
    let service = HttpService::new_http(
      router(false),
      "127.0.0.1:1234".parse().unwrap(),
      "127.0.0.1:8080".parse().unwrap(),
    );
    assert_eq!(
      service.dispatch(request(version)).await.unwrap().status(),
      StatusCode::OK
    );
  }
}

#[tokio::test]
async fn test_dispatch_missing_host_rejected_before_service() {
  let service = HttpService::new_http(
    router(false),
    "127.0.0.1:1234".parse().unwrap(),
    "127.0.0.1:8080".parse().unwrap(),
  );
  let mut request = request(Version::HTTP_11);
  request.headers_mut().remove("host");
  assert_eq!(
    service.dispatch(request).await.unwrap().status(),
    StatusCode::BAD_REQUEST
  );
}

#[tokio::test]
async fn test_dispatch_missing_route_rejected_before_service() {
  let service = HttpService::new_http(
    ServerRouter::build(vec![]),
    "127.0.0.1:1234".parse().unwrap(),
    "127.0.0.1:8080".parse().unwrap(),
  );
  assert_eq!(
    service.dispatch(request(Version::HTTP_11)).await.unwrap().status(),
    StatusCode::NOT_FOUND
  );
}

#[tokio::test]
async fn test_dispatch_tls_certificate_requirement_is_shared_by_https_and_h3()
 {
  for version in [Version::HTTP_11, Version::HTTP_3] {
    for (required, presented, expected) in [
      (true, false, StatusCode::FORBIDDEN),
      (true, true, StatusCode::OK),
      (false, false, StatusCode::OK),
    ] {
      let service = HttpService::new_tls(
        router(required),
        "127.0.0.1:1234".parse().unwrap(),
        "127.0.0.1:8080".parse().unwrap(),
        presented,
      );
      assert_eq!(
        service.dispatch(request(version)).await.unwrap().status(),
        expected
      );
    }
  }
}

#[tokio::test]
async fn test_dispatch_plain_http_does_not_apply_tls_certificate_policy()
 {
  let service = HttpService::new_http(
    router(true),
    "127.0.0.1:1234".parse().unwrap(),
    "127.0.0.1:8080".parse().unwrap(),
  );
  assert_eq!(
    service.dispatch(request(Version::HTTP_11)).await.unwrap().status(),
    StatusCode::OK
  );
}

#[tokio::test]
async fn test_dispatch_service_errors_return_identified_internal_error()
{
  let service = HttpService::new_http(
    ServerRouter::build(vec![Server {
      hostnames: vec![],
      service: crate::server::placeholder_service(),
      service_name: "failure".into(),
      tls: None,
    }]),
    "127.0.0.1:1234".parse().unwrap(),
    "127.0.0.1:8080".parse().unwrap(),
  );
  let response =
    service.dispatch(request(Version::HTTP_11)).await.unwrap();
  assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
  assert_eq!(
    response.headers()["x-request-id"].to_str().unwrap().len(),
    32
  );
}

#[tokio::test]
async fn test_dispatch_keeps_inbound_headers_and_sets_response_id_from_context()
 {
  for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
    for incoming in [None, Some("opaque-caller-id")] {
      let handler =
        Service::new(tower::service_fn(move |request: Request| {
          Box::pin(async move {
            assert_eq!(
              request
                .headers()
                .get("x-request-id")
                .map(|value| value.to_str().unwrap()),
              incoming
            );
            let id = request
              .extensions()
              .get::<RequestContext>()
              .unwrap()
              .request_id()
              .unwrap();
            let mut response =
              build_error_response(StatusCode::OK, &id.to_string());
            response.headers_mut().append(
              "x-request-id",
              "untrusted-upstream".parse().unwrap(),
            );
            response
              .headers_mut()
              .append("x-request-id", "duplicate".parse().unwrap());
            Ok(response)
          })
            as Pin<Box<dyn Future<Output = Result<Response>>>>
        }));
      let service = HttpService::new_http(
        ServerRouter::build(vec![Server {
          hostnames: vec![],
          service: handler,
          service_name: "identity".into(),
          tls: None,
        }]),
        "127.0.0.1:1234".parse().unwrap(),
        "127.0.0.1:8080".parse().unwrap(),
      );
      let mut request = request(version);
      if let Some(value) = incoming {
        request
          .headers_mut()
          .insert("x-request-id", value.parse().unwrap());
      }
      let response = service.dispatch(request).await.unwrap();
      let id =
        response.headers()["x-request-id"].to_str().unwrap().to_owned();
      assert_eq!(
        response.headers().get_all("x-request-id").iter().count(),
        1
      );
      if let Some(incoming) = incoming {
        assert_eq!(id, incoming);
      } else {
        assert_eq!(id.len(), 32);
      }
      use http_body_util::BodyExt;
      assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        id
      );
    }
  }
}

#[tokio::test]
async fn test_dispatch_routing_errors_include_incoming_request_id() {
  let service = HttpService::new_http(
    ServerRouter::build(vec![]),
    "127.0.0.1:1234".parse().unwrap(),
    "127.0.0.1:8080".parse().unwrap(),
  );
  let mut request = request(Version::HTTP_11);
  request
    .headers_mut()
    .insert("x-request-id", "error-id".parse().unwrap());
  let response = service.dispatch(request).await.unwrap();
  assert_eq!(response.status(), StatusCode::NOT_FOUND);
  assert_eq!(response.headers()["x-request-id"], "error-id");
}
