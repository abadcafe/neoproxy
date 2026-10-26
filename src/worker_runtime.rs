//! module: worker_runtime
//! responsibility: own a worker's local executor through bounded
//! teardown public operations: run
//! data entities: RuntimeOwner
//! tests: worker_runtime_tests.rs

use std::future::Future;

struct RuntimeOwner(Option<tokio::runtime::Runtime>);

impl Drop for RuntimeOwner {
  fn drop(&mut self) {
    if let Some(runtime) = self.0.take() {
      // System getaddrinfo cannot be cancelled. It retains its DNS
      // capacity permit until completion, but must not hold a finished
      // worker (or a panicking worker) inside Runtime::drop forever.
      // Local async tasks and transports are dropped before this owner.
      runtime.shutdown_background();
    }
  }
}

pub(crate) fn run<F: Future>(future: F) -> std::io::Result<F::Output> {
  let runtime = RuntimeOwner(Some(
    tokio::runtime::Builder::new_current_thread()
      .enable_all()
      .thread_name("neoproxy-blocking")
      .build()?,
  ));
  let local = tokio::task::LocalSet::new();
  Ok(
    runtime
      .0
      .as_ref()
      .expect("runtime exists until owner drop")
      .block_on(local.run_until(future)),
  )
}
