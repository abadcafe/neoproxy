use super::upgrade::OnUpgrade;

#[tokio::test]
async fn test_on_upgrade_resolves_with_error_on_cancel() {
  let (trigger, upgrade) = OnUpgrade::pair();
  drop(trigger); // Drop trigger to cancel

  let result = upgrade.await;
  assert!(result.is_err(), "Upgrade should resolve with Err on cancel");
}

#[tokio::test]
async fn test_upgrade_trigger_send_success() {
  let listener =
    tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let addr = listener.local_addr().unwrap();
  let client_fut = tokio::net::TcpStream::connect(addr);
  let (client, server_res) =
    tokio::join!(client_fut, listener.accept());
  let client = client.unwrap();
  let (server, _) = server_res.unwrap();

  let (trigger, upgrade) = OnUpgrade::pair();
  trigger.send(Ok(Box::new(client))).unwrap();

  let result = upgrade.await;
  assert!(result.is_ok(), "Upgrade should resolve with Ok");

  drop(server);
}

#[tokio::test]
async fn test_upgrade_trigger_send_error() {
  let (trigger, upgrade) = OnUpgrade::pair();
  trigger.send(Err(anyhow::anyhow!("test error"))).unwrap();

  let result = upgrade.await;
  assert!(result.is_err(), "Upgrade should resolve with Err");
}

#[tokio::test]
async fn test_on_upgrade_pending_clone_drop_keeps_receiver_available() {
  let (trigger, upgrade) = OnUpgrade::pair();
  let mut clone = upgrade.clone();
  let mut context = Context::from_waker(Waker::noop());
  assert!(Pin::new(&mut clone).poll(&mut context).is_pending());
  drop(clone);

  trigger.send(Ok(Box::new(tokio::io::duplex(64).0))).unwrap();
  assert!(upgrade.await.is_ok());
}

#[tokio::test]
#[should_panic]
async fn test_on_upgrade_duplicate_consumption_panics() {
  let (trigger, upgrade) = OnUpgrade::pair();
  let clone = upgrade.clone();
  trigger.send(Ok(Box::new(tokio::io::duplex(64).0))).unwrap();
  let _stream = upgrade.await.unwrap();

  // Clones share one receiver, as in Hyper. Consuming it twice is a
  // programming error; it must not be disguised as a business error.
  let _ = clone.await;
}
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Waker};

#[tokio::test]
async fn test_on_upgrade_new_preserves_stream_and_extension_contract() {
  use tokio::io::{AsyncReadExt, AsyncWriteExt};
  let (trigger, source) = OnUpgrade::pair();
  let upgrade = OnUpgrade::new(source);
  let mut extensions = http::Extensions::new();
  extensions.insert(upgrade);
  let (stream, mut peer) = tokio::io::duplex(64);
  trigger.send(Ok(Box::new(stream))).unwrap();
  let mut stream =
    extensions.remove::<OnUpgrade>().unwrap().await.unwrap();
  peer.write_all(b"payload").await.unwrap();
  let mut bytes = [0; 7];
  stream.read_exact(&mut bytes).await.unwrap();
  assert_eq!(&bytes, b"payload");
}

struct CloneProbe(std::sync::Arc<std::sync::atomic::AtomicUsize>);
impl Clone for CloneProbe {
  fn clone(&self) -> Self {
    self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    Self(self.0.clone())
  }
}
impl Future for CloneProbe {
  type Output = anyhow::Result<Box<dyn crate::stream::Io>>;

  fn poll(
    self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
  ) -> std::task::Poll<Self::Output> {
    std::task::Poll::Ready(Err(anyhow::anyhow!("source error")))
  }
}

#[tokio::test]
async fn test_on_upgrade_clone_delegates_to_source_and_preserves_error()
{
  let clones =
    std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
  let upgrade = OnUpgrade::new(CloneProbe(clones.clone()));
  let clone = upgrade.clone();
  assert_eq!(clones.load(std::sync::atomic::Ordering::SeqCst), 1);
  drop(upgrade);
  assert_eq!(clone.await.err().unwrap().to_string(), "source error");
}

#[tokio::test]
async fn test_upgrade_trigger_reports_dropped_receiver() {
  let (trigger, upgrade) = OnUpgrade::pair();
  drop(upgrade);
  assert!(trigger.send(Ok(Box::new(tokio::io::duplex(64).0))).is_err());
}
