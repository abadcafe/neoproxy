//! module: paths
//! responsibility: own the active and archived log filename namespace
//! public operations: LogPaths::{new, active, archive, overlaps}
//! data entities: LogPaths
//! tests: paths_tests.rs; registry_tests.rs

use std::path::PathBuf;

use time::Date;

pub(super) struct LogPaths {
  prefix: PathBuf,
  daily: bool,
}

impl LogPaths {
  pub(super) fn new(prefix: PathBuf, daily: bool) -> Self {
    Self { prefix, daily }
  }

  pub(super) fn active(&self, date: Option<Date>) -> PathBuf {
    let mut path = self.prefix.clone().into_os_string();
    if self.daily {
      let date = date.expect("daily log path requires a calendar date");
      path.push(format!(".{date}"));
    }
    path.into()
  }

  pub(super) fn archive(
    &self,
    date: Option<Date>,
    index: u64,
  ) -> PathBuf {
    let mut path = self.active(date).into_os_string();
    path.push(format!(".{index}"));
    path.into()
  }

  /// Prefixes reserve their active files and every future archive.
  /// Symmetry also covers two daily prefixes whose date ranges overlap.
  pub(super) fn overlaps(&self, other: &Self) -> bool {
    self.contains_prefix(other) || other.contains_prefix(self)
  }

  fn contains_prefix(&self, other: &Self) -> bool {
    if self.prefix == other.prefix {
      return true;
    }
    if self.prefix.parent() != other.prefix.parent() {
      return false;
    }
    let (Some(own), Some(candidate)) =
      (self.prefix.file_name(), other.prefix.file_name())
    else {
      return false;
    };
    let Some(suffix) = candidate
      .as_encoded_bytes()
      .strip_prefix(own.as_encoded_bytes())
      .and_then(|suffix| suffix.strip_prefix(b"."))
    else {
      return false;
    };
    let Ok(suffix) = std::str::from_utf8(suffix) else {
      return false;
    };
    let archive_index = |value: &str| {
      !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
    };
    if !self.daily {
      return archive_index(suffix);
    }
    let (date, archive) = suffix
      .split_once('.')
      .map_or((suffix, None), |(date, archive)| (date, Some(archive)));
    Date::parse(
      date,
      time::macros::format_description!("[year]-[month]-[day]"),
    )
    .is_ok()
      && archive.is_none_or(archive_index)
  }
}
