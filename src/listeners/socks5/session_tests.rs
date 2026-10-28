//! Black-box contracts for SOCKS5 session adaptation.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::session;
use crate::context::RequestContext;
use crate::http_message::{Request, Response, build_error_response};
use crate::listeners::tcp_listener_base::TcpConnection;
use crate::service::Service;
use crate::shutdown::ShutdownHandle;

async fn connection_pair() -> (TcpConnection, TcpStream) {
  let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let client =
    TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
  let (stream, peer_addr) = listener.accept().await.unwrap();
  let local_addr = stream.local_addr().unwrap();
  (
    TcpConnection {
      stream,
      peer_addr,
      local_addr,
      shutdown: ShutdownHandle::new(),
    },
    client,
  )
}

#[tokio::test]
async fn test_serve_translates_targets_and_metadata_then_maps_denied_response()
 {
  let cases = [
    (vec![1, 127, 0, 0, 1, 1, 187], "127.0.0.1:443"),
    (
      vec![4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 187],
      "[::1]:443",
    ),
    (
      vec![
        3, 12, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b't',
        b'e', b's', b't', 1, 187,
      ],
      "example.test:443",
    ),
  ];
  for (target, authority) in cases {
    let (connection, mut client) = connection_pair().await;
    let peer = connection.peer_addr;
    let local = connection.local_addr;
    let service =
      Service::new(tower::service_fn(move |request: Request| {
        Box::pin(async move {
          assert_eq!(request.method(), http::Method::CONNECT);
          assert_eq!(request.uri().to_string(), authority);
          assert!(
            request
              .extensions()
              .get::<crate::stream::OnUpgrade>()
              .is_some()
          );
          let context =
            request.extensions().get::<RequestContext>().unwrap();
          assert_eq!(context.client_addr(), Some(peer));
          assert_eq!(context.server_addr(), Some(local));
          assert_eq!(context.service_name(), Some("session-test"));
          Ok(build_error_response(
            http::StatusCode::FORBIDDEN,
            "denied",
          ))
        }) as Pin<Box<dyn Future<Output = Result<Response>>>>
      }));
    tokio::join!(
      session::serve(
        connection,
        service,
        tokio::time::Instant::now() + Duration::from_secs(1),
        "session-test".into()
      ),
      async {
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);
        let mut command = vec![5, 1, 0];
        command.extend(target);
        client.write_all(&command).await.unwrap();
        let mut reply = [0; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply[..4], &[5, 2, 0, 1]);
      },
    );
  }
}

#[tokio::test]
async fn test_serve_invalid_handshake_closes_without_connect_reply() {
  let (connection, mut client) = connection_pair().await;
  tokio::join!(
    session::serve(
      connection,
      crate::server::placeholder_service(),
      tokio::time::Instant::now() + Duration::from_secs(1),
      "session-test".into()
    ),
    async {
      client.write_all(&[4, 1, 0]).await.unwrap();
      match client.read(&mut [0]).await {
        Ok(count) => assert_eq!(count, 0),
        Err(error) => {
          assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset)
        }
      }
    },
  );
}

#[tokio::test(start_paused = true)]
async fn test_serve_handshake_timeout_closes_idle_client() {
  let (connection, mut client) = connection_pair().await;
  let start = tokio::time::Instant::now();
  tokio::join!(
    session::serve(
      connection,
      crate::server::placeholder_service(),
      tokio::time::Instant::now() + Duration::from_secs(1),
      "session-test".into()
    ),
    async {
      assert_eq!(client.read(&mut [0]).await.unwrap(), 0);
    },
  );
  assert_eq!(start.elapsed(), Duration::from_secs(1));
}

#[tokio::test]
async fn test_serve_injects_basic_header_for_connect_authentication() {
  let (username, password) = ("user", "pass:word");
  let (connection, mut client) = connection_pair().await;
  let service =
    Service::new(tower::service_fn(move |request: Request| {
      Box::pin(async move {
        assert_eq!(request.method(), http::Method::CONNECT);
        let header =
          request.headers().get(http::header::PROXY_AUTHORIZATION);
        let header = header.unwrap();
        assert_eq!(header, "Basic dXNlcjpwYXNzOndvcmQ=");
        assert!(header.is_sensitive());
        assert_eq!(
          crate::auth::UserPasswordAuth::parse_basic_auth(header)
            .unwrap(),
          (username.into(), password.into())
        );
        Ok(build_error_response(
          http::StatusCode::PROXY_AUTHENTICATION_REQUIRED,
          "denied",
        ))
      }) as Pin<Box<dyn Future<Output = Result<Response>>>>
    }));
  tokio::join!(
    session::serve(
      connection,
      service,
      tokio::time::Instant::now() + Duration::from_secs(1),
      "session-test".into()
    ),
    async {
      client.write_all(&[5, 1, 2]).await.unwrap();
      let mut reply = [0; 2];
      client.read_exact(&mut reply).await.unwrap();
      assert_eq!(reply, [5, 2]);
      let mut credentials =
        vec![1, u8::try_from(username.len()).unwrap()];
      credentials.extend_from_slice(username.as_bytes());
      credentials.push(u8::try_from(password.len()).unwrap());
      credentials.extend_from_slice(password.as_bytes());
      client.write_all(&credentials).await.unwrap();
      client.read_exact(&mut reply).await.unwrap();
      assert_eq!(reply, [1, 0]);
      client
        .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 1, 187])
        .await
        .unwrap();
      let mut command_reply = [0; 10];
      client.read_exact(&mut command_reply).await.unwrap();
      assert_eq!(command_reply[1], 2);
    }
  );
}

#[tokio::test]
async fn test_serve_header_deadline_excludes_service_execution() {
  let (connection, mut client) = connection_pair().await;
  let service = Service::new(tower::service_fn(|_: Request| {
    Box::pin(async {
      tokio::time::sleep(Duration::from_millis(1100)).await;
      Ok(build_error_response(http::StatusCode::FORBIDDEN, "denied"))
    }) as Pin<Box<dyn Future<Output = Result<Response>>>>
  }));
  tokio::join!(
    session::serve(
      connection,
      service,
      tokio::time::Instant::now() + Duration::from_secs(1),
      "session-test".into()
    ),
    async {
      client.write_all(&[5, 1, 0]).await.unwrap();
      let mut method = [0; 2];
      client.read_exact(&mut method).await.unwrap();
      assert_eq!(method, [5, 0]);
      client
        .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 80])
        .await
        .unwrap();
      let mut reply = [0; 10];
      client.read_exact(&mut reply).await.unwrap();
      assert_eq!(reply[1], 2);
    }
  );
}
