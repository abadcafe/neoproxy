//! module: logging
//! responsibilities: initialize the process's asynchronous diagnostic
//! log writer public operations: init
//! data entities: none
//! tests: process startup/shutdown and secret-redaction integration
//! tests
use anyhow::Result;

pub(crate) fn init(
  directory: &str,
) -> Result<tracing_appender::non_blocking::WorkerGuard> {
  let appender = tracing_appender::rolling::Builder::new()
    .rotation(tracing_appender::rolling::Rotation::DAILY)
    .filename_prefix("neoproxy.log")
    .build(directory)?;
  let (writer, guard) =
    tracing_appender::non_blocking::NonBlockingBuilder::default()
      .buffered_lines_limit(8192)
      .finish(appender);
  let filter = tracing_subscriber::EnvFilter::builder()
    .with_default_directive(
      tracing_subscriber::filter::LevelFilter::INFO.into(),
    )
    .with_env_var("NEOPROXY_LOG")
    .from_env_lossy();
  tracing_subscriber::fmt()
    .with_writer(writer)
    .with_env_filter(filter)
    .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
    .compact()
    .with_ansi(false)
    .with_file(true)
    .with_line_number(true)
    .with_thread_names(true)
    .with_level(true)
    .try_init()
    .map_err(|error| {
      anyhow::anyhow!("initializing diagnostic logging: {error}")
    })?;
  Ok(guard)
}
