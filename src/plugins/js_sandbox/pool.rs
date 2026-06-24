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

pub(crate) struct SandboxPool {
  senders: Mutex<Vec<Sender<SandboxRequest>>>,
  next: AtomicUsize,
}

impl SandboxPool {
  pub(crate) fn new(worker_threads: usize) -> Self {
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

  pub(crate) fn execute(
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
      // Worker thread has died; dropped sender closes the returned
      // receiver.
    }

    rx
  }

  pub(crate) fn shutdown(&self) {
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
