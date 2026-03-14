use std::cell::RefCell;
use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::{Result, anyhow};
use futures_core::Stream;
use local_channel::mpsc as local_mpsc;
use tokio::{io, task};
use tokio_util::io as tokio_util_io;
use tracing::{info, warn};

use crate::plugin;

/// CONNECT 目标地址解析错误
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectTargetError {
  /// 非 CONNECT 方法
  NotConnectMethod,
  /// URI 中无 authority
  NoAuthority,
  /// authority 中无端口号
  NoPort,
  /// 端口号为 0
  PortZero,
}

impl fmt::Display for ConnectTargetError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      ConnectTargetError::NotConnectMethod => {
        write!(f, "not CONNECT method")
      }
      ConnectTargetError::NoAuthority => {
        write!(f, "no authority in URI")
      }
      ConnectTargetError::NoPort => {
        write!(f, "no port in authority")
      }
      ConnectTargetError::PortZero => {
        write!(f, "port is zero")
      }
    }
  }
}

impl std::error::Error for ConnectTargetError {}

/// 解析 CONNECT 请求的目标地址
///
/// # 参数
/// - `parts`: HTTP 请求的 Parts
///
/// # 返回
/// - `Ok((host, port))`: 目标主机名和端口号
/// - `Err(ConnectTargetError)`: 解析失败
pub fn parse_connect_target(
  parts: &http::request::Parts,
) -> Result<(String, u16), ConnectTargetError> {
  if parts.method != http::Method::CONNECT {
    return Err(ConnectTargetError::NotConnectMethod);
  }

  let authority =
    parts.uri.authority().ok_or(ConnectTargetError::NoAuthority)?;

  let port = authority.port_u16().ok_or(ConnectTargetError::NoPort)?;

  if port == 0 {
    return Err(ConnectTargetError::PortZero);
  }

  Ok((authority.host().to_string(), port))
}

struct Transfering {
  reader: Pin<Box<dyn io::AsyncRead>>,
  writer: Pin<Box<dyn io::AsyncWrite>>,
  shutdown: plugin::ShutdownHandle,
}

impl Transfering {
  fn new(
    r: Pin<Box<dyn io::AsyncRead>>,
    w: Pin<Box<dyn io::AsyncWrite>>,
    shutdown: plugin::ShutdownHandle,
  ) -> Self {
    Self { reader: r, writer: w, shutdown: shutdown }
  }

  async fn run(&mut self) -> Result<u64> {
    let res = tokio::select! {
      // todo: carefully handle errors.
      res = io::copy(&mut self.reader, &mut self.writer) => {
        res.map_err(|e| e.into())
      }
      _ = self.shutdown.notified() => {
        Err(anyhow!("interrupted"))
      }
    };

    res
  }
}

pub struct TransferingSet {
  shutdown_handle: plugin::ShutdownHandle,
  transfering_tx: Option<local_mpsc::Sender<Transfering>>,
  join_handle: Option<task::JoinHandle<()>>,
}

impl TransferingSet {
  pub fn new() -> Self {
    Self {
      shutdown_handle: plugin::ShutdownHandle::new(),
      transfering_tx: None,
      join_handle: None,
    }
  }

  pub fn new_transfering<R, W>(&self, r: R, w: W) -> Result<()>
  where
    R: io::AsyncRead + Unpin + 'static,
    W: io::AsyncWrite + Unpin + 'static,
  {
    let trans = Transfering::new(
      Box::pin(r),
      Box::pin(w),
      self.shutdown_handle.clone(),
    );
    self.transfering_tx.as_ref().unwrap().send(trans).map_err(|e| {
      anyhow!(
        "transfering created but sending for spawn task failed: {e}"
      )
    })
  }

  pub fn shutdown_handle(&self) -> plugin::ShutdownHandle {
    self.shutdown_handle.clone()
  }

  pub async fn stop(&mut self) -> Result<()> {
    self.transfering_tx.as_mut().unwrap().close();
    self.shutdown_handle.shutdown();
    self.join_handle.as_mut().unwrap().await?;
    info!("transfering set finished");
    Ok(())
  }

  async fn serving(mut rx: local_mpsc::Receiver<Transfering>) {
    let mut join_set = task::JoinSet::<Result<u64>>::new();
    let mut channel_closed = false;
    loop {
      tokio::select! {
        ret = rx.recv(), if !channel_closed => {
          if let None = ret {
            channel_closed = true;
            continue;
          }

          let mut trans = ret.unwrap();
          join_set.spawn_local(async move { trans.run().await });
        }
        ret = join_set.join_next_with_id(), if !join_set.is_empty() => {
          let res = ret.unwrap();
          if let Err(e) = res {
            let id = e.id();
            warn!("transfering '{id}' join error: {e}");
            continue;
          }

          let (id, res) = res.unwrap();
          if let Err(e) = res {
            warn!("transfering '{id}' stopped with error: {e}");
            continue;
          }

          let total = res.unwrap();
          info!("transfering '{id}' done {total} bytes");
        }
        else => {
          break;
        }
      }
    }
  }

  pub fn start(&mut self) {
    let (tx, rx) = local_mpsc::channel();
    let handle = task::spawn_local(TransferingSet::serving(rx));
    let _ = self.transfering_tx.insert(tx);
    let _ = self.join_handle.insert(handle);
  }
}

pub struct FramingReaderStream<R> {
  rs: tokio_util_io::ReaderStream<R>,
}

impl<R> FramingReaderStream<R>
where
  R: io::AsyncRead + Unpin,
{
  pub fn new(rs: tokio_util_io::ReaderStream<R>) -> Self {
    Self { rs }
  }
}

impl<R> Stream for FramingReaderStream<R>
where
  R: io::AsyncRead + Unpin,
{
  type Item = Result<http_body::Frame<bytes::Bytes>>;

  fn poll_next(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Self::Item>> {
    Pin::new(&mut self.rs)
      .poll_next(cx)
      .map_ok(|b| http_body::Frame::data(b))
      .map_err(|e| e.into())
  }

  fn size_hint(&self) -> (usize, Option<usize>) {
    self.rs.size_hint()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn make_request_parts(
    method: http::Method,
    uri: &str,
  ) -> http::request::Parts {
    http::Request::builder()
      .method(method)
      .uri(uri)
      .body(())
      .unwrap()
      .into_parts()
      .0
  }

  #[test]
  fn test_parse_connect_target_valid() {
    let parts =
      make_request_parts(http::Method::CONNECT, "example.com:443");
    let result = parse_connect_target(&parts);
    assert_eq!(result, Ok(("example.com".to_string(), 443)));
  }

  #[test]
  fn test_parse_connect_target_not_connect_method() {
    let parts =
      make_request_parts(http::Method::GET, "http://example.com/");
    let result = parse_connect_target(&parts);
    assert_eq!(result, Err(ConnectTargetError::NotConnectMethod));
  }

  #[test]
  fn test_parse_connect_target_no_authority() {
    let parts = make_request_parts(http::Method::CONNECT, "/");
    let result = parse_connect_target(&parts);
    assert_eq!(result, Err(ConnectTargetError::NoAuthority));
  }

  #[test]
  fn test_parse_connect_target_no_port() {
    let parts =
      make_request_parts(http::Method::CONNECT, "example.com");
    let result = parse_connect_target(&parts);
    assert_eq!(result, Err(ConnectTargetError::NoPort));
  }

  #[test]
  fn test_parse_connect_target_port_zero() {
    let parts =
      make_request_parts(http::Method::CONNECT, "example.com:0");
    let result = parse_connect_target(&parts);
    assert_eq!(result, Err(ConnectTargetError::PortZero));
  }

  #[test]
  fn test_parse_connect_target_ipv6_address() {
    let parts = make_request_parts(http::Method::CONNECT, "[::1]:8080");
    let result = parse_connect_target(&parts);
    assert_eq!(result, Ok(("[::1]".to_string(), 8080)));
  }

  #[test]
  fn test_parse_connect_target_ipv4_address() {
    let parts =
      make_request_parts(http::Method::CONNECT, "192.168.1.1:80");
    let result = parse_connect_target(&parts);
    assert_eq!(result, Ok(("192.168.1.1".to_string(), 80)));
  }

  #[test]
  fn test_connect_target_error_display() {
    assert_eq!(
      format!("{}", ConnectTargetError::NotConnectMethod),
      "not CONNECT method"
    );
    assert_eq!(
      format!("{}", ConnectTargetError::NoAuthority),
      "no authority in URI"
    );
    assert_eq!(
      format!("{}", ConnectTargetError::NoPort),
      "no port in authority"
    );
    assert_eq!(
      format!("{}", ConnectTargetError::PortZero),
      "port is zero"
    );
  }

  #[test]
  fn test_connect_target_error_is_error() {
    let err = ConnectTargetError::NotConnectMethod;
    let _err: &dyn std::error::Error = &err;
  }
}
