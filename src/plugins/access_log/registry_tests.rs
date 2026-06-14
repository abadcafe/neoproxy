use serial_test::serial;

use super::test_utils::TracingCapture;
use super::{
  LogEntry, config, context, create_plugin, get_writer,
  init_writer_registry, reset_writer_registry,
};

#[test]
#[serial]
fn test_writer_registry_initializes_from_config() {
  reset_writer_registry();

  let dir1 = tempfile::tempdir().unwrap();
  let dir2 = tempfile::tempdir().unwrap();
  let prefix1 =
    dir1.path().join("test_writer1").to_string_lossy().to_string();
  let prefix2 =
    dir2.path().join("test_writer2").to_string_lossy().to_string();

  let plugin_config = config::AccessLogPluginConfig {
    writers: vec![
      config::AccessLogWriterConfig {
        path_prefix: prefix1.clone(),
        ..Default::default()
      },
      config::AccessLogWriterConfig {
        path_prefix: prefix2.clone(),
        format: context::LogFormat::Json,
        ..Default::default()
      },
    ],
  };
  let config_value = serde_yaml::to_value(&plugin_config).unwrap();
  let _plugin = create_plugin(Some(&config_value)).unwrap();

  let writer1 = get_writer(&prefix1);
  assert!(writer1.is_ok());
  let writer2 = get_writer(&prefix2);
  assert!(writer2.is_ok());
}

#[test]
#[serial]
fn test_writer_registry_path_creation_error() {
  reset_writer_registry();

  let block_file = tempfile::NamedTempFile::new().unwrap();
  let block_path = block_file.path().to_string_lossy().to_string();

  let plugin_config = config::AccessLogPluginConfig {
    writers: vec![config::AccessLogWriterConfig {
      path_prefix: format!("{}/subdir/log", block_path),
      ..Default::default()
    }],
  };
  let result = init_writer_registry(&plugin_config);
  assert!(result.is_err(), "Should fail when path cannot be created");
}

#[test]
#[serial]
fn test_writer_registry_duplicate_path_prefix_rejected() {
  reset_writer_registry();

  let dir = tempfile::tempdir().unwrap();
  let prefix =
    dir.path().join("dup_writer").to_string_lossy().to_string();

  let plugin_config = config::AccessLogPluginConfig {
    writers: vec![
      config::AccessLogWriterConfig {
        path_prefix: prefix.clone(),
        ..Default::default()
      },
      config::AccessLogWriterConfig {
        path_prefix: prefix.clone(),
        format: context::LogFormat::Json,
        ..Default::default()
      },
    ],
  };

  let result = init_writer_registry(&plugin_config);
  assert!(result.is_err(), "Should reject duplicate path_prefix");
  assert!(
    result.unwrap_err().to_string().contains("duplicate"),
    "Error message should mention 'duplicate'"
  );
}

#[test]
#[serial]
fn test_reset_writer_registry_joins_writer_threads() {
  // CR-007: reset_writer_registry() must join writer threads before
  // returning, so that file handles are released and the next test
  // starts with a clean state.
  reset_writer_registry();

  let dir = tempfile::tempdir().unwrap();
  let prefix =
    dir.path().join("reset_join").to_string_lossy().to_string();

  let plugin_config = config::AccessLogPluginConfig {
    writers: vec![config::AccessLogWriterConfig {
      path_prefix: prefix.clone(),
      rotate_daily: false,
      ..Default::default()
    }],
  };
  let config_value = serde_yaml::to_value(&plugin_config).unwrap();
  let _plugin = create_plugin(Some(&config_value)).unwrap();

  let sender = get_writer(&prefix).unwrap();
  let entry = LogEntry {
    entry: context::AccessLogEntry {
      time: time::OffsetDateTime::now_utc(),
      client_ip: "127.0.0.1".to_string(),
      client_port: 12345,
      server_ip: "0.0.0.0".to_string(),
      server_port: 8080,
      method: "GET".to_string(),
      target: "http://example.com/".to_string(),
      status: 200,
      duration_ms: 42,
      service: "echo".to_string(),
      err: None,
      extensions: std::collections::HashMap::new(),
    },
  };
  sender.try_send(entry).unwrap();
  drop(sender);

  reset_writer_registry();

  let log_path = std::path::PathBuf::from(&prefix);
  let deadline =
    std::time::Instant::now() + std::time::Duration::from_secs(3);
  let mut content = String::new();
  loop {
    if log_path.exists() {
      if let Ok(c) = std::fs::read_to_string(&log_path) {
        if !c.is_empty() {
          content = c;
          break;
        }
      }
    }
    if std::time::Instant::now() > deadline {
      break;
    }
    std::thread::sleep(std::time::Duration::from_millis(50));
  }
  assert!(
    !content.is_empty(),
    "Log file should contain the written entry"
  );
  assert!(
    content.contains("127.0.0.1"),
    "Log file should contain entry data"
  );
}

#[test]
#[serial]
fn test_writer_thread_buffers_entries_not_flushed_per_entry() {
  // CR-009: Writer thread must NOT flush after every single log entry.
  reset_writer_registry();

  let dir = tempfile::tempdir().unwrap();
  let prefix =
    dir.path().join("buffered").to_string_lossy().to_string();

  let plugin_config = config::AccessLogPluginConfig {
    writers: vec![config::AccessLogWriterConfig {
      path_prefix: prefix.clone(),
      buffer_capacity: byte_unit::Byte::from_u64(1024 * 1024),
      flush_interval: std::time::Duration::from_secs(3600),
      rotate_daily: false,
      ..Default::default()
    }],
  };
  let config_value = serde_yaml::to_value(&plugin_config).unwrap();
  let _plugin = create_plugin(Some(&config_value)).unwrap();

  let sender = get_writer(&prefix).unwrap();
  let entry = LogEntry {
    entry: context::AccessLogEntry {
      time: time::OffsetDateTime::now_utc(),
      client_ip: "127.0.0.1".to_string(),
      client_port: 12345,
      server_ip: "0.0.0.0".to_string(),
      server_port: 8080,
      method: "GET".to_string(),
      target: "http://example.com/".to_string(),
      status: 200,
      duration_ms: 42,
      service: "echo".to_string(),
      err: None,
      extensions: std::collections::HashMap::new(),
    },
  };
  sender.try_send(entry).unwrap();
  std::thread::sleep(std::time::Duration::from_millis(100));

  let log_path = std::path::PathBuf::from(&prefix);
  if log_path.exists() {
    let content = std::fs::read_to_string(&log_path).unwrap();
    assert!(
      content.is_empty(),
      "Entry should be buffered, not flushed to disk immediately. Got \
       {} bytes: {:?}",
      content.len(),
      &content[..content.len().min(200)]
    );
  }

  drop(sender);
  reset_writer_registry();

  let deadline =
    std::time::Instant::now() + std::time::Duration::from_secs(3);
  let mut content = String::new();
  loop {
    if log_path.exists() {
      if let Ok(c) = std::fs::read_to_string(&log_path) {
        if !c.is_empty() {
          content = c;
          break;
        }
      }
    }
    if std::time::Instant::now() > deadline {
      break;
    }
    std::thread::sleep(std::time::Duration::from_millis(50));
  }
  assert!(
    !content.is_empty(),
    "Entry should be flushed after writer thread exits"
  );
  assert!(
    content.contains("127.0.0.1"),
    "Log file should contain entry data"
  );
}

#[test]
#[serial]
fn test_get_writer_not_blocked_during_reinit() {
  // CR-010: init_writer_registry must not hold the WRITER_REGISTRY
  // Mutex lock during long operations.
  reset_writer_registry();

  let dir1 = tempfile::tempdir().unwrap();
  let prefix1 =
    dir1.path().join("old_writer").to_string_lossy().to_string();

  let plugin_config = config::AccessLogPluginConfig {
    writers: vec![config::AccessLogWriterConfig {
      path_prefix: prefix1.clone(),
      ..Default::default()
    }],
  };
  let config_value = serde_yaml::to_value(&plugin_config).unwrap();
  let _plugin = create_plugin(Some(&config_value)).unwrap();

  let sender_clone = get_writer(&prefix1).unwrap();

  let dir2 = tempfile::tempdir().unwrap();
  let prefix2 =
    dir2.path().join("new_writer").to_string_lossy().to_string();
  let new_config = config::AccessLogPluginConfig {
    writers: vec![config::AccessLogWriterConfig {
      path_prefix: prefix2.clone(),
      ..Default::default()
    }],
  };

  let init_handle = std::thread::spawn(move || {
    let _ = init_writer_registry(&new_config);
  });

  std::thread::sleep(std::time::Duration::from_millis(200));

  let start = std::time::Instant::now();
  let _ = get_writer(&prefix1);
  let elapsed = start.elapsed();

  assert!(
    elapsed < std::time::Duration::from_millis(500),
    "get_writer should not block for more than 500ms during reinit, \
     took {:?} (lock likely held during thread join)",
    elapsed
  );

  drop(sender_clone);
  let _ = init_handle.join();
  reset_writer_registry();
  reset_writer_registry();
}

#[test]
#[serial]
fn test_init_writer_registry_phase5_cleanup_uses_timeout() {
  // CR-012: Phase 5 cleanup must use a timeout when joining newly
  // spawned threads.
  reset_writer_registry();

  use std::sync::{Arc, Barrier};

  let barrier = Arc::new(Barrier::new(2));
  let barrier1 = barrier.clone();
  let barrier2 = barrier.clone();

  let config_a = config::AccessLogPluginConfig { writers: vec![] };

  let dir = tempfile::tempdir().unwrap();
  let prefix_b =
    dir.path().join("phase5_writer").to_string_lossy().to_string();
  let config_b = config::AccessLogPluginConfig {
    writers: vec![config::AccessLogWriterConfig {
      path_prefix: prefix_b.clone(),
      ..Default::default()
    }],
  };

  let handle_a = std::thread::spawn(move || {
    barrier1.wait();
    let _ = init_writer_registry(&config_a);
  });

  let handle_b = std::thread::spawn(move || {
    barrier2.wait();
    let _ = init_writer_registry(&config_b);
  });

  let result_a = handle_a.join();
  let result_b = handle_b.join();
  assert!(result_a.is_ok(), "Thread A should not panic");
  assert!(result_b.is_ok(), "Thread B should not panic");

  reset_writer_registry();
}

#[test]
#[serial]
fn test_init_writer_registry_partial_failure_cleans_up_spawned_threads()
{
  // CR-015: When init_writer_registry fails partway through,
  // already-spawned writer threads must be properly cleaned up.
  reset_writer_registry();

  let dir1 = tempfile::tempdir().unwrap();
  let prefix1 =
    dir1.path().join("valid_writer").to_string_lossy().to_string();

  let block_file = tempfile::NamedTempFile::new().unwrap();
  let block_path = block_file.path().to_string_lossy().to_string();
  let prefix2 = format!("{}/subdir/log", block_path);

  let plugin_config = config::AccessLogPluginConfig {
    writers: vec![
      config::AccessLogWriterConfig {
        path_prefix: prefix1.clone(),
        ..Default::default()
      },
      config::AccessLogWriterConfig {
        path_prefix: prefix2,
        ..Default::default()
      },
    ],
  };

  let result = init_writer_registry(&plugin_config);
  assert!(
    result.is_err(),
    "init_writer_registry should fail on partial error"
  );

  let writer_result = get_writer(&prefix1);
  assert!(
    writer_result.is_err(),
    "Registry should not be set after partial failure"
  );

  let dir3 = tempfile::tempdir().unwrap();
  let prefix3 =
    dir3.path().join("reinit_writer").to_string_lossy().to_string();
  let reinit_config = config::AccessLogPluginConfig {
    writers: vec![config::AccessLogWriterConfig {
      path_prefix: prefix3.clone(),
      ..Default::default()
    }],
  };
  let reinit_result = init_writer_registry(&reinit_config);
  assert!(
    reinit_result.is_ok(),
    "Reinitialization should succeed after partial failure cleanup: \
     {:?}",
    reinit_result
  );

  let writer = get_writer(&prefix3);
  assert!(
    writer.is_ok(),
    "New writer should be accessible after reinit"
  );
}

#[test]
#[serial]
fn test_init_writer_registry_validates_paths_before_spawning() {
  // CR-015 (alternate test): All directory validations should happen
  // before any threads are spawned.
  reset_writer_registry();

  let block_file = tempfile::NamedTempFile::new().unwrap();
  let block_path = block_file.path().to_string_lossy().to_string();
  let prefix1 = format!("{}/subdir/log", block_path);

  let dir2 = tempfile::tempdir().unwrap();
  let prefix2 =
    dir2.path().join("valid_writer").to_string_lossy().to_string();

  let plugin_config = config::AccessLogPluginConfig {
    writers: vec![
      config::AccessLogWriterConfig {
        path_prefix: prefix1,
        ..Default::default()
      },
      config::AccessLogWriterConfig {
        path_prefix: prefix2.clone(),
        ..Default::default()
      },
    ],
  };

  let result = init_writer_registry(&plugin_config);
  assert!(
    result.is_err(),
    "Should fail when first writer's path is invalid"
  );

  let writer = get_writer(&prefix2);
  assert!(
    writer.is_err(),
    "Registry should not be set after validation failure"
  );
}

#[test]
#[serial]
fn test_access_log_uses_tracing_for_warnings() {
  // CR-017: The access_log module must use tracing::warn! instead of
  // eprintln! for error/warning output.
  let (capture, _guard) = TracingCapture::new();

  reset_writer_registry();

  let dir = tempfile::tempdir().unwrap();
  let prefix =
    dir.path().join("tracing_test").to_string_lossy().to_string();

  let plugin_config = config::AccessLogPluginConfig {
    writers: vec![config::AccessLogWriterConfig {
      path_prefix: prefix.clone(),
      ..Default::default()
    }],
  };
  let config_value = serde_yaml::to_value(&plugin_config).unwrap();
  let _plugin = create_plugin(Some(&config_value)).unwrap();

  let _sender = get_writer(&prefix).unwrap();

  let empty_config = config::AccessLogPluginConfig { writers: vec![] };
  let _ = init_writer_registry(&empty_config);

  let output = capture.output();
  assert!(
    output.contains("did not exit within"),
    "tracing output should contain 'did not exit within' (join \
     timeout warning), got: {:?}",
    &output[..output.len().min(500)]
  );

  drop(_sender);
  reset_writer_registry();
}
