use super::paths::LogPaths;

#[test]
fn test_log_paths_formats_active_files_and_archives() {
  let paths = LogPaths::new("access".into(), true);
  let date = time::macros::date!(2026 - 10 - 26);
  assert_eq!(
    paths.active(Some(date)),
    std::path::Path::new("access.2026-10-26")
  );
  assert_eq!(
    paths.archive(Some(date), 2),
    std::path::Path::new("access.2026-10-26.2")
  );
  let paths = LogPaths::new("access".into(), false);
  assert_eq!(paths.active(None), std::path::Path::new("access"));
  assert_eq!(paths.archive(None, 2), std::path::Path::new("access.2"));
}

#[test]
fn test_log_paths_distinguishes_independent_namespaces() {
  let paths = LogPaths::new("logs/access".into(), true);
  for other in [
    "logs/access.error",
    "other/access.2026-10-26",
    "logs/access.2026-99-99",
    "logs/access.1",
  ] {
    assert!(
      !paths.overlaps(&LogPaths::new(other.into(), false)),
      "{other}"
    );
  }
}
