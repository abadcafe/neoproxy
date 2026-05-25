use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use crossbeam_channel::{Receiver, Sender};
use tokio::sync::oneshot;
use tracing::{debug, info};

use crate::plugins::js_sandbox::cpu_sandbox;
use crate::plugins::js_sandbox::request::{
  IncomingRequest, OutgoingResponse, SandboxConfig,
};
use crate::plugins::js_sandbox::sandbox::Sandbox;

struct SandboxRequest {
  config: SandboxConfig,
  request: IncomingRequest,
  response_tx: oneshot::Sender<anyhow::Result<OutgoingResponse>>,
}

pub struct SandboxPool {
  senders: Mutex<Vec<Sender<SandboxRequest>>>,
  next: AtomicUsize,
}

impl SandboxPool {
  pub fn new(worker_threads: usize) -> Self {
    cpu_sandbox::ensure_watchdog_started();

    let mut senders = Vec::with_capacity(worker_threads);
    for i in 0..worker_threads {
      let (tx, rx) = crossbeam_channel::unbounded::<SandboxRequest>();
      senders.push(tx);

      std::thread::Builder::new()
        .name(format!("sandbox-worker-{i}"))
        .spawn(move || worker_loop(i, rx))
        .expect("failed to spawn sandbox worker thread");
    }

    info!("SandboxPool started with {} worker threads", worker_threads);
    Self { senders: Mutex::new(senders), next: AtomicUsize::new(0) }
  }

  pub fn execute(
    &self,
    config: SandboxConfig,
    request: IncomingRequest,
  ) -> oneshot::Receiver<anyhow::Result<OutgoingResponse>> {
    let (tx, rx) = oneshot::channel();

    let senders = self.senders.lock().unwrap();
    let idx = self.next.fetch_add(1, Ordering::Relaxed) % senders.len();
    let sender = &senders[idx];

    if sender
      .send(SandboxRequest { config, request, response_tx: tx })
      .is_err()
    {
      // Worker thread has died; return error via oneshot
      let _ = rx;
    }

    rx
  }

  pub fn shutdown(&self) {
    let mut senders = self.senders.lock().unwrap();
    senders.clear();
  }
}

fn worker_loop(worker_id: usize, rx: Receiver<SandboxRequest>) {
  debug!("sandbox worker {worker_id} started");
  while let Ok(req) = rx.recv() {
    let result = execute_sandbox(req.config, req.request);
    let _ = req.response_tx.send(result);
  }
  debug!("sandbox worker {worker_id} stopped");
}

fn execute_sandbox(
  config: SandboxConfig,
  request: IncomingRequest,
) -> anyhow::Result<OutgoingResponse> {
  let sandbox = Sandbox::new(config)?;
  sandbox.execute(request)
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::plugins::js_sandbox::request::{
    IncomingRequest, SandboxConfig,
  };

  #[test]
  fn test_pool_worker_starts() {
    let pool = SandboxPool::new(1);

    let config = SandboxConfig {
            sandbox_id: "test".to_string(),
            heap_limit_bytes: 128 * 1024 * 1024,
            cpu_limit_us: 5000 * 1000,
            source_code: r#"export default { async fetch(req) { return new Response("ok", { status: 200 }); } };"#.to_string(),
        };
    let request = IncomingRequest {
      method: "GET".to_string(),
      url: "/".to_string(),
      headers: vec![],
      body: vec![],
    };

    let rx = pool.execute(config, request);

    let result = rx.blocking_recv().expect("channel closed");
    let resp = result.expect("sandbox execute failed");
    assert_eq!(resp.status, 200);

    pool.shutdown();
  }
}
