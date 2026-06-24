use super::cpu_sandbox::{ensure_watchdog_started, stop_watchdog};

#[test]
fn test_watchdog_start_and_stop_are_idempotent() {
  ensure_watchdog_started();
  ensure_watchdog_started();
  stop_watchdog();
  stop_watchdog();
}
