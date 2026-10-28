use std::time::Duration;

use crate::tcp_options::TcpOptions;
#[tokio::test]
async fn test_tcp_options_apply_all_keepalive_fields() {
  let listener =
    tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let stream =
    tokio::net::TcpStream::connect(listener.local_addr().unwrap())
      .await
      .unwrap();
  TcpOptions {
    time: Some(Duration::from_secs(31)),
    interval: Some(Duration::from_secs(7)),
    retries: Some(4),
  }
  .apply(&stream)
  .unwrap();
  let socket = socket2::SockRef::from(&stream);
  assert!(socket.keepalive().unwrap());
  assert_eq!(
    socket.tcp_keepalive_time().unwrap(),
    Duration::from_secs(31)
  );
  assert_eq!(
    socket.tcp_keepalive_interval().unwrap(),
    Duration::from_secs(7)
  );
  assert_eq!(socket.tcp_keepalive_retries().unwrap(), 4);
  assert!(stream.nodelay().unwrap());
}

#[test]
fn test_tcp_options_parse_flat_fields_and_validate_ranges() {
  for yaml in [
    "tcp_keep_alive_time: 0s",
    "tcp_keep_alive_interval: 1ms",
    "tcp_keep_alive_retries: 0",
  ] {
    assert!(serde_yaml::from_str::<TcpOptions>(yaml).is_err());
  }
  let options: TcpOptions = serde_yaml::from_str(
    "tcp_keep_alive_time: 31s\ntcp_keep_alive_interval: \
     7s\ntcp_keep_alive_retries: 4",
  )
  .unwrap();
  assert_eq!(options.time, Some(Duration::from_secs(31)));
  assert_eq!(options.interval, Some(Duration::from_secs(7)));
  assert_eq!(options.retries, Some(4));
}
