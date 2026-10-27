//! Wire contracts exercised through the SOCKS5 handshake interface.
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::handshake::negotiate;
use crate::plugins::upstream::error::UpstreamError;
use crate::plugins::upstream::target_parser::parse_connect_target;

#[tokio::test]
async fn test_negotiate_addresses_authentication_and_short_writes() {
  for (authority, encoded) in [
    ("origin.test:443", b"\x03\x0borigin.test\x01\xbb".to_vec()),
    ("127.0.0.1:80", b"\x01\x7f\x00\x00\x01\x00\x50".to_vec()),
    (
      "[::1]:443",
      [
        vec![4],
        std::net::Ipv6Addr::LOCALHOST.octets().to_vec(),
        vec![1, 187],
      ]
      .concat(),
    ),
  ] {
    for method in [0, 2] {
      let (mut client, mut server) = tokio::io::duplex(1);
      let request = http::Request::builder()
        .method("CONNECT")
        .uri(authority)
        .body(())
        .unwrap();
      let target =
        parse_connect_target(&request.into_parts().0).unwrap();
      let user =
        serde_yaml::from_str("username: alice\npassword: secret")
          .unwrap();
      let peer = async {
        let mut greeting = [0; 4];
        server.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 2, 0, 2]);
        server.write_all(&[5, method]).await.unwrap();
        if method == 2 {
          let mut auth = [0; 14];
          server.read_exact(&mut auth).await.unwrap();
          assert_eq!(&auth, b"\x01\x05alice\x06secret");
          server.write_all(&[1, 0]).await.unwrap();
        }
        let mut packet = vec![0; 3 + encoded.len()];
        server.read_exact(&mut packet).await.unwrap();
        assert_eq!(&packet[..3], &[5, 1, 0]);
        assert_eq!(&packet[3..], encoded);
        server
          .write_all(
            &[vec![5, 0, 0], encoded.clone(), b"hello".to_vec()]
              .concat(),
          )
          .await
          .unwrap();
      };
      let connect = async {
        negotiate(&mut client, &target, Some(&user)).await.unwrap();
        let mut payload = [0; 5];
        client.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"hello");
      };
      tokio::join!(peer, connect);
    }
  }
}

#[tokio::test]
async fn test_negotiate_replies_map_to_http_connect_errors() {
  for (reply, status) in [
    (1, 502),
    (2, 403),
    (3, 502),
    (4, 502),
    (5, 502),
    (6, 504),
    (7, 501),
    (8, 502),
  ] {
    let (mut client, mut server) = tokio::io::duplex(64);
    let request = http::Request::builder()
      .method("CONNECT")
      .uri("127.0.0.1:80")
      .body(())
      .unwrap();
    let target = parse_connect_target(&request.into_parts().0).unwrap();
    let peer = async {
      let mut greeting = [0; 3];
      server.read_exact(&mut greeting).await.unwrap();
      assert_eq!(greeting, [5, 1, 0]);
      server.write_all(&[5, 0]).await.unwrap();
      let mut command = [0; 10];
      server.read_exact(&mut command).await.unwrap();
      server
        .write_all(&[5, reply, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    };
    let ((), result) =
      tokio::join!(peer, negotiate(&mut client, &target, None));
    assert!(
      matches!(result, Err(UpstreamError::UpstreamConnectError {status: actual,..}) if actual.as_u16() == status)
    );
  }
}

#[tokio::test]
async fn test_negotiate_rejects_auth_failure_invalid_version_and_unoffered_method()
 {
  for response in [[5, 255], [4, 0], [5, 2], [5, 3]] {
    let (mut client, mut server) = tokio::io::duplex(64);
    let request = http::Request::builder()
      .method("CONNECT")
      .uri("origin.test:80")
      .body(())
      .unwrap();
    let target = parse_connect_target(&request.into_parts().0).unwrap();
    let peer = async {
      let mut greeting = [0; 3];
      server.read_exact(&mut greeting).await.unwrap();
      server.write_all(&response).await.unwrap();
    };
    let ((), result) =
      tokio::join!(peer, negotiate(&mut client, &target, None));
    if response == [5, 255] {
      assert!(matches!(
        result,
        Err(UpstreamError::UpstreamConnectError {
          status: http::StatusCode::PROXY_AUTHENTICATION_REQUIRED,
          ..
        })
      ));
    } else {
      assert!(matches!(result, Err(UpstreamError::InvalidResponse(_))));
    }
  }
}

#[tokio::test]
async fn test_negotiate_validates_credentials_without_caller_preconditions()
 {
  for (username, password) in [
    (String::new(), "secret".to_owned()),
    ("alice".to_owned(), String::new()),
    ("a".repeat(256), "secret".to_owned()),
    ("alice".to_owned(), "p".repeat(256)),
  ] {
    let user = serde_yaml::from_str(&format!(
      "username: '{username}'\npassword: '{password}'"
    ))
    .unwrap();
    let request = http::Request::builder()
      .method("CONNECT")
      .uri("origin.test:80")
      .body(())
      .unwrap();
    let target = parse_connect_target(&request.into_parts().0).unwrap();
    let (mut client, _server) = tokio::io::duplex(64);
    let result = tokio::time::timeout(
      std::time::Duration::from_millis(50),
      negotiate(&mut client, &target, Some(&user)),
    )
    .await
    .expect("invalid credentials must fail before network I/O");
    assert!(matches!(
      result,
      Err(UpstreamError::ProxyInternalError(_))
    ));
  }
}

#[tokio::test]
async fn test_negotiate_rejects_malformed_and_truncated_responses() {
  for (response, truncated) in [
    (vec![4, 0, 0, 1], false),
    (vec![5, 0, 1, 1], false),
    (vec![5, 9, 0, 1], false),
    (vec![5, 0, 0, 9], false),
    (vec![5, 0, 0, 3, 0], false),
    (vec![5, 0], true),
    (vec![5, 0, 0, 1, 127], true),
  ] {
    let (mut client, mut server) = tokio::io::duplex(64);
    let request = http::Request::builder()
      .method("CONNECT")
      .uri("127.0.0.1:80")
      .body(())
      .unwrap();
    let target = parse_connect_target(&request.into_parts().0).unwrap();
    let peer = async move {
      let mut greeting = [0; 3];
      server.read_exact(&mut greeting).await.unwrap();
      server.write_all(&[5, 0]).await.unwrap();
      let mut command = [0; 10];
      server.read_exact(&mut command).await.unwrap();
      server.write_all(&response).await.unwrap();
    };
    let ((), result) =
      tokio::join!(peer, negotiate(&mut client, &target, None));
    if truncated {
      assert!(matches!(
        result,
        Err(UpstreamError::ConnectionTerminated(_))
      ));
    } else {
      assert!(matches!(result, Err(UpstreamError::InvalidResponse(_))));
    }
  }
}
