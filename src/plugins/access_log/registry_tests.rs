use std::path::Path;
use std::time::{Duration, Instant};

use super::config::{AccessLogPluginConfig, AccessLogWriterConfig};
use super::context::{AccessLogEntry, LogFormat};
use super::registry::WriterRegistry;

fn config(
  directory: &tempfile::TempDir,
  format: LogFormat,
) -> AccessLogPluginConfig {
  AccessLogPluginConfig {
    writers: vec![AccessLogWriterConfig {
      path_prefix: directory
        .path()
        .join("access")
        .to_str()
        .unwrap()
        .into(),
      rotate_daily: false,
      format,
      ..Default::default()
    }],
  }
}

#[test]
fn test_new_rejects_writer_paths_with_the_same_canonical_parent_and_name()
 {
  let directory = tempfile::tempdir().unwrap();
  let mut config = config(&directory, LogFormat::Text);
  let mut alias = config.writers[0].clone();
  alias.path_prefix =
    directory.path().join(".").join("access").to_str().unwrap().into();
  config.writers.push(alias);
  assert!(
    WriterRegistry::new(&config).is_err(),
    "multiple writer threads would own one log path"
  );
}

#[test]
fn test_new_rejects_writers_following_the_same_file_symlink() {
  let directory = tempfile::tempdir().unwrap();
  let mut configuration = config(&directory, LogFormat::Text);
  let original = directory.path().join("access");
  std::fs::write(&original, "").unwrap();
  let alias = directory.path().join("alias");
  std::os::unix::fs::symlink(&original, &alias).unwrap();
  let mut second = configuration.writers[0].clone();
  second.path_prefix = alias.to_str().unwrap().into();
  configuration.writers.push(second);
  assert!(WriterRegistry::new(&configuration).is_err());
}

#[test]
fn test_new_rejects_writers_owning_another_writers_rotated_path() {
  let directory = tempfile::tempdir().unwrap();
  for (daily, suffix) in
    [(false, ".1"), (true, ".2026-10-26"), (true, ".2026-10-26.2")]
  {
    let mut configuration = config(&directory, LogFormat::Text);
    configuration.writers[0].rotate_daily = daily;
    let mut second = configuration.writers[0].clone();
    second.rotate_daily = false;
    second.path_prefix.push_str(suffix);
    configuration.writers.push(second);
    assert!(WriterRegistry::new(&configuration).is_err(), "{suffix}");
    configuration.writers.reverse();
    assert!(
      WriterRegistry::new(&configuration).is_err(),
      "reverse {suffix}"
    );
  }
}

fn entry() -> AccessLogEntry {
  AccessLogEntry {
    time: time::OffsetDateTime::now_utc(),
    client_ip: "127.0.0.1".into(),
    client_port: 1234,
    server_ip: "127.0.0.1".into(),
    server_port: 8080,
    method: "GET".into(),
    target: "/".into(),
    status: 200,
    duration_ms: 0,
    service: "echo".into(),
    err: None,
    extensions: Default::default(),
  }
}

fn wait_for_log(path: &Path, marker: &str, timeout: Duration) -> bool {
  let deadline = Instant::now() + timeout;
  loop {
    match std::fs::read_to_string(path) {
      Ok(content) if content.contains(marker) => return true,
      Ok(_) => {}
      Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
      Err(error) => panic!("cannot read test log: {error}"),
    }
    if Instant::now() >= deadline {
      return false;
    }
    std::thread::sleep(Duration::from_millis(2));
  }
}

#[test]
fn test_get_writer_periodic_flush_follows_size_flush_without_skipping_tick()
 {
  let directory = tempfile::tempdir().unwrap();
  let mut config = config(&directory, LogFormat::Text);
  let interval = Duration::from_secs(1);
  config.writers[0].flush_interval = interval;
  config.writers[0].buffer_capacity = byte_unit::Byte::from_u64(4096);
  let registry = WriterRegistry::new(&config).unwrap();
  let sink =
    registry.get_writer(&config.writers[0].path_prefix).unwrap();
  let path = directory.path().join("access");
  let mut first = entry();
  first.target = "/timer-anchor".into();
  sink.record(first).unwrap();
  // Synchronize on an observed periodic flush, not thread startup or
  // private state. Schedule a size flush inside the next timer period.
  assert!(wait_for_log(&path, "/timer-anchor", interval * 3));
  let anchor = Instant::now();
  std::thread::sleep(interval * 3 / 5);
  let mut large = entry();
  large.target = format!("/size-flush-{}", "x".repeat(8192));
  sink.record(large).unwrap();
  assert!(wait_for_log(&path, "/size-flush-", interval / 5));
  assert!(
    anchor.elapsed() < interval * 4 / 5,
    "missed test scheduling window"
  );
  let mut pending = entry();
  pending.target = "/pending-after-size-flush".into();
  sink.record(pending).unwrap();
  // Leave scheduling margin, while still ending before the following
  // timer tick. Neither capacity nor shutdown can flush this record.
  let flushed = wait_for_log(
    &path,
    "/pending-after-size-flush",
    interval + interval / 10,
  );
  drop(sink);
  drop(registry);
  assert!(
    flushed,
    "periodic flush skipped the tick after a size flush"
  );
}

#[test]
fn test_new_validates_duplicate_paths_and_zero_interval() {
  let directory = tempfile::tempdir().unwrap();
  let mut config = config(&directory, LogFormat::Text);
  config.writers.push(config.writers[0].clone());
  assert!(WriterRegistry::new(&config).is_err());
  config.writers.pop();
  config.writers[0].flush_interval = Duration::ZERO;
  assert!(WriterRegistry::new(&config).is_err());
}

#[test]
fn test_get_writer_flushes_while_entries_keep_arriving() {
  use std::sync::Arc;
  use std::sync::atomic::{AtomicBool, Ordering};

  let directory = tempfile::tempdir().unwrap();
  let mut config = config(&directory, LogFormat::Text);
  config.writers[0].flush_interval = Duration::from_millis(50);
  config.writers[0].buffer_capacity =
    byte_unit::Byte::from_u64(1024 * 1024);
  config.writers[0].max_buffer_size =
    byte_unit::Byte::from_u64(2 * 1024 * 1024);
  let registry = WriterRegistry::new(&config).unwrap();
  let sink =
    registry.get_writer(&config.writers[0].path_prefix).unwrap();
  let stopped = Arc::new(AtomicBool::new(false));
  let producer_stopped = stopped.clone();
  let producer = std::thread::spawn(move || {
    while !producer_stopped.load(Ordering::Acquire) {
      let mut log = entry();
      log.target = "/continuous-marker".into();
      sink.record(log).unwrap();
      std::thread::sleep(Duration::from_millis(5));
    }
  });
  let flushed = wait_for_log(
    &directory.path().join("access"),
    "/continuous-marker",
    Duration::from_millis(500),
  );
  stopped.store(true, Ordering::Release);
  producer.join().unwrap();
  drop(registry);
  assert!(flushed, "incoming entries prevented periodic flush");
}

#[test]
fn test_get_writer_reports_missing_name() {
  let registry =
    WriterRegistry::new(&AccessLogPluginConfig::default()).unwrap();
  assert!(registry.get_writer("absent").is_err());
}

#[test]
fn test_drop_flushes_all_buffered_entries() {
  let directory = tempfile::tempdir().unwrap();
  let config = config(&directory, LogFormat::Text);
  let registry = WriterRegistry::new(&config).unwrap();
  let sender =
    registry.get_writer(&config.writers[0].path_prefix).unwrap();
  for _ in 0..100 {
    sender.record(entry()).unwrap();
  }
  drop(sender);
  drop(registry);
  assert_eq!(
    std::fs::read_to_string(directory.path().join("access"))
      .unwrap()
      .lines()
      .count(),
    100
  );
}

#[test]
fn test_new_keeps_independent_registry_configurations_isolated() {
  let first = tempfile::tempdir().unwrap();
  let second = tempfile::tempdir().unwrap();
  let first_config = config(&first, LogFormat::Text);
  let second_config = config(&second, LogFormat::Json);
  let registry_one = WriterRegistry::new(&first_config).unwrap();
  let registry_two = WriterRegistry::new(&second_config).unwrap();
  registry_one
    .get_writer(&first_config.writers[0].path_prefix)
    .unwrap()
    .record(entry())
    .unwrap();
  registry_two
    .get_writer(&second_config.writers[0].path_prefix)
    .unwrap()
    .record(entry())
    .unwrap();
  drop(registry_one);
  drop(registry_two);
  assert!(
    std::fs::read_to_string(first.path().join("access"))
      .unwrap()
      .starts_with('[')
  );
  assert!(
    std::fs::read_to_string(second.path().join("access"))
      .unwrap()
      .starts_with('{')
  );
}

#[test]
fn test_new_rejects_unwritable_destination() {
  let file = tempfile::NamedTempFile::new().unwrap();
  let config = AccessLogPluginConfig {
    writers: vec![AccessLogWriterConfig {
      path_prefix: format!("{}/child/access", file.path().display()),
      ..Default::default()
    }],
  };
  assert!(WriterRegistry::new(&config).is_err());
}

#[test]
fn test_new_rejects_unrepresentable_flush_deadline() {
  let directory = tempfile::tempdir().unwrap();
  let mut config = config(&directory, LogFormat::Text);
  config.writers[0].flush_interval = Duration::MAX;
  assert!(WriterRegistry::new(&config).is_err());
}

#[test]
fn test_new_rejects_unrepresentable_buffer_capacity() {
  let directory = tempfile::tempdir().unwrap();
  let mut config = config(&directory, LogFormat::Text);
  config.writers[0].buffer_capacity =
    byte_unit::Byte::from_u64(u64::MAX);
  config.writers[0].max_buffer_size =
    byte_unit::Byte::from_u64(u64::MAX);
  assert!(WriterRegistry::new(&config).is_err());
}
