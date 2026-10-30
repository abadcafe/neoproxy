//! module: direct
//! responsibility: exchange capsules with one connected UDP destination
//! public operations: connect
//! data entities: none
//! tests: CONNECT-UDP integration contracts
use tokio::io::AsyncWriteExt;
pub(crate) async fn connect(
  peer: std::net::SocketAddr,
  tracker: &crate::task_tracker::TaskTracker,
) -> std::io::Result<Box<dyn crate::stream::Io>> {
  let socket = super::socket::Socket::new(peer).await?;
  Ok(super::bridge::spawn(
    tracker,
    move |transport, shutdown| async move {
      let (read, mut write) = tokio::io::split(transport);
      let mut reader = super::capsule::Reader::new(read);
      loop {
        tokio::select! {
         biased;
         _ = shutdown.notified() => break,
         data=reader.receive()=>match data {Ok(Some(data))=>{if socket.send(&data).await.is_err(){break;}},_=>break},
         result=socket.receive()=>match result {
           Ok(packets)=>{ for data in packets.iter() { if write.write_all(&super::capsule::encode(data)).await.is_err(){return;} } },
           Err(_)=>break
         },
        }
      }
      let _ = write.shutdown().await;
    },
  ))
}
