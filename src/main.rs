use std::pin::Pin;
use std::sync::Arc;
use std::thread;

use anyhow::Result;
use tokio::signal::unix as signal;
use tokio::{runtime, sync, task};
use tracing::{info, warn};
use {tracing_appender, tracing_subscriber};

use crate::config::Config;

mod config;
mod plugin;
mod plugins;
mod server;

fn run_server_threads(
  closer: Arc<sync::Notify>,
) -> Vec<thread::JoinHandle<Result<()>>> {
  let mut server_thread_handles = vec![];
  for i in 0..Config::global().worker_threads {
    let closer = closer.clone();
    let name = format!("neoproxy server thread {i}");
    server_thread_handles.push(
      thread::Builder::new()
        .name(name.clone())
        .spawn(move || -> Result<()> {
          server::server_thread(name.as_str(), closer.clone())
        })
        .unwrap(),
    );
  }

  server_thread_handles
}

fn init_log() -> tracing_appender::non_blocking::WorkerGuard {
  let log_appender = tracing_appender::rolling::daily(
    Config::global().log_directory.as_str(),
    "neoproxy.log",
  );

  let (writer, guard) = tracing_appender::non_blocking(log_appender);
  let filter = tracing_subscriber::EnvFilter::builder()
    .with_default_directive(
      tracing_subscriber::filter::LevelFilter::INFO.into(),
    )
    .with_env_var("NEOPROXY_LOG")
    .from_env_lossy();

  tracing_subscriber::fmt()
    .with_writer(writer)
    .with_max_level(tracing::Level::TRACE)
    .with_env_filter(filter)
    .compact()
    .with_ansi(true)
    .with_file(true)
    .with_line_number(true)
    .with_thread_names(true)
    .with_level(true)
    .init();

  guard
}

fn main() -> Result<()> {
  let _guard = init_log();
  info!("server started with config:\n{:#?}\n", &Config::global());

  let closer = Arc::new(sync::Notify::new());
  let handles = run_server_threads(closer.clone());
  let waiting_signal: Pin<Box<dyn Future<Output = Result<()>>>> =
    Box::pin(async move {
      let mut stream = signal::signal(signal::SignalKind::interrupt())?;
      stream.recv().await;
      info!("shutting down...");
      closer.notify_waiters();
      Ok(())
    });

  let local_set = task::LocalSet::new();
  let rt = runtime::Builder::new_current_thread()
    .enable_all()
    .thread_name("neoproxy main thread")
    .build()?;
  rt.block_on(local_set.run_until(waiting_signal))?;

  handles.into_iter().for_each(|h| {
    let thread_name =
      h.thread().name().unwrap_or("unknown").to_string();
    match h.join() {
      Err(e) => {
        warn!("join server thread '{thread_name}' failed: '{e:?}'");
      }
      Ok(res) => match res {
        Err(e) => {
          warn!("server thread '{thread_name}' error: '{e:?}'");
        }
        Ok(_) => {}
      },
    }
  });

  info!("bye bye!!!!!");
  Ok(())
}
