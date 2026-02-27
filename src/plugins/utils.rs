use std::cell::RefCell;
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::{Result, anyhow};
use futures_core::Stream;
use local_channel::mpsc as local_mpsc;
use tokio::{io, task};
use tokio_util::io as tokio_util_io;
use tracing::{info, warn};

use crate::plugin;

/// todo: use tower::Layer instead.
pub fn is_connect_method(
  req: &http::request::Parts,
) -> Result<(String, u16)> {
  if !req.method.as_str().eq_ignore_ascii_case("CONNECT") {
    return Err(anyhow!("unknown http method"));
  }

  let dest = match req.uri.authority() {
    None => {
      return Err(anyhow!("unknown authority"));
    }
    Some(dest) => dest,
  };

  let port = match dest.port_u16() {
    None => {
      return Err(anyhow!("unknwon port"));
    }
    Some(port) => port,
  };

  if port < 1 {
    return Err(anyhow!("invalid port number 0"));
  }

  Ok((dest.host().to_string(), port))
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
