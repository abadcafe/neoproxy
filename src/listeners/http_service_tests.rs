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
async fn test_dispatch_preserves_service_errors() {
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
  assert_eq!(
    service
      .dispatch(request(Version::HTTP_11))
      .await
      .unwrap_err()
      .to_string(),
    "placeholder"
  );
}
