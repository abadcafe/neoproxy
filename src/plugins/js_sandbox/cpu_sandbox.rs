use std::ffi::c_void;
use std::sync::OnceLock;

use deno_core::v8;
use nix::sys::signal;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

// ---------------------------------------------------------------------------
// TimerEntry — carried through signal handler → watchdog thread
// ---------------------------------------------------------------------------

#[repr(C)]
struct TimerEntry {
  request_id: String,
  isolate_handle: v8::IsolateHandle,
}

impl TimerEntry {
  fn new(
    request_id: String,
    isolate_handle: v8::IsolateHandle,
  ) -> Self {
    Self { request_id, isolate_handle }
  }

  fn abort(&self) {
    error!(
      "CPU limit reached, terminating request {}",
      self.request_id
    );
    self.isolate_handle.terminate_execution();
  }
}

// ---------------------------------------------------------------------------
// DispatchTask — message sent from signal handler to watchdog thread
// ---------------------------------------------------------------------------

struct DispatchTask {
  timer_entry: Option<TimerEntry>,
  quit: bool,
}

impl DispatchTask {
  fn new(
    request_id: String,
    isolate_handle: v8::IsolateHandle,
  ) -> Self {
    Self {
      timer_entry: Some(TimerEntry::new(request_id, isolate_handle)),
      quit: false,
    }
  }

  fn process(&self) {
    if let Some(entry) = &self.timer_entry {
      entry.abort();
    }
  }
}

// ---------------------------------------------------------------------------
// Global channel sender — set once by WatchDog::start()
// ---------------------------------------------------------------------------

static DISPATCH_TASK_TX: OnceLock<mpsc::UnboundedSender<DispatchTask>> =
  OnceLock::new();

// ---------------------------------------------------------------------------
// SIGALRM handler — minimal work: rebuild TimerEntry, send DispatchTask
// ---------------------------------------------------------------------------

extern "C" fn timer_signal_handler(
  _: libc::c_int,
  sig_info: *mut libc::siginfo_t,
  _: *mut libc::c_void,
) {
  let timer_entry: Box<TimerEntry> = unsafe {
    let sig_val = (*sig_info).si_value();
    Box::from_raw(sig_val.sival_ptr as *mut TimerEntry)
  };

  let request_id = timer_entry.request_id.clone();
  let isolate_handle = timer_entry.isolate_handle.clone();

  // Prevent double-free: the Box was reconstructed from raw, but we
  // only need the cloned data. The original allocation is effectively
  // "consumed" by this move into the signal handler.
  std::mem::forget(timer_entry);

  let task = DispatchTask::new(request_id, isolate_handle);
  if let Some(tx) = DISPATCH_TASK_TX.get() {
    let _ = tx.send(task);
  }
}

// ---------------------------------------------------------------------------
// CPUTimer — wraps a Linux per-thread CPU timer
// ---------------------------------------------------------------------------

struct TimerId(*mut libc::c_void);

impl Drop for TimerId {
  fn drop(&mut self) {
    if !self.0.is_null() {
      unsafe {
        libc::timer_delete(self.0);
      }
    }
  }
}

struct CPUTimer {
  _timer_id: TimerId,
  timer_entry: *mut TimerEntry,
}

impl CPUTimer {
  /// Create and arm a one-shot per-thread CPU timer.
  /// `cpu_limit_us` is in microseconds.
  fn start(
    cpu_limit_us: u32,
    timer_entry: TimerEntry,
  ) -> anyhow::Result<Self> {
    let mut timerid = TimerId(std::ptr::null_mut());
    let timer_entry_ptr: *mut TimerEntry =
      Box::into_raw(Box::new(timer_entry));
    let sival_ptr: *mut c_void = timer_entry_ptr as *mut c_void;

    let mut sigev: libc::sigevent = unsafe { std::mem::zeroed() };
    sigev.sigev_notify = libc::SIGEV_SIGNAL;
    sigev.sigev_signo = libc::SIGALRM;
    sigev.sigev_value = libc::sigval { sival_ptr };

    let ret = unsafe {
      libc::timer_create(
        libc::CLOCK_THREAD_CPUTIME_ID,
        &mut sigev,
        &mut timerid.0,
      )
    };
    if ret < 0 {
      unsafe {
        let _ = Box::from_raw(timer_entry_ptr);
      }
      anyhow::bail!(std::io::Error::last_os_error());
    }

    let limit = cpu_limit_us as i64;
    let sec = limit / 1_000_000;
    let nsec = (limit % 1_000_000) * 1_000;

    let mut tmspec: libc::itimerspec = unsafe { std::mem::zeroed() };
    tmspec.it_interval.tv_sec = 0;
    tmspec.it_interval.tv_nsec = 0;
    tmspec.it_value.tv_sec = sec;
    tmspec.it_value.tv_nsec = nsec;

    // At least 1ns to avoid degenerate timer
    if tmspec.it_value.tv_sec == 0 && tmspec.it_value.tv_nsec == 0 {
      tmspec.it_value.tv_nsec = 1;
    }

    let ret = unsafe {
      libc::timer_settime(timerid.0, 0, &tmspec, std::ptr::null_mut())
    };
    if ret < 0 {
      unsafe {
        let _ = Box::from_raw(timer_entry_ptr);
        libc::timer_delete(timerid.0);
      }
      anyhow::bail!(std::io::Error::last_os_error());
    }

    debug!("CPUTimer armed: limit={}us", cpu_limit_us);

    Ok(Self { _timer_id: timerid, timer_entry: timer_entry_ptr })
  }
}

impl Drop for CPUTimer {
  fn drop(&mut self) {
    unsafe {
      let _ = Box::from_raw(self.timer_entry);
    }
  }
}

// ---------------------------------------------------------------------------
// CPUTimerScope — RAII wrapper: arms timer on create, disarms on drop
// ---------------------------------------------------------------------------

pub struct CPUTimerScope {
  _cpu_timer: CPUTimer,
}

impl CPUTimerScope {
  /// Create a new CPU timer scope. The timer will fire if the calling
  /// thread consumes more than `cpu_limit_us` microseconds of CPU
  /// time, sending a termination request to the V8 isolate via the
  /// watchdog thread.
  pub fn new(
    cpu_limit_us: u32,
    request_id: String,
    isolate_handle: v8::IsolateHandle,
  ) -> anyhow::Result<Self> {
    let timer_entry = TimerEntry::new(request_id, isolate_handle);
    let cpu_timer = CPUTimer::start(cpu_limit_us, timer_entry)?;
    Ok(Self { _cpu_timer: cpu_timer })
  }
}

// ---------------------------------------------------------------------------
// WatchDog — singleton that runs the dispatch thread
// ---------------------------------------------------------------------------

static DISPATCH_THREAD_HANDLE: OnceLock<std::thread::JoinHandle<()>> =
  OnceLock::new();

fn start_watchdog() -> bool {
  let sig_flags =
    signal::SaFlags::SA_SIGINFO | signal::SaFlags::SA_RESTART;
  let sig_handler = signal::SigHandler::SigAction(timer_signal_handler);
  let sig_action = signal::SigAction::new(
    sig_handler,
    sig_flags,
    signal::SigSet::empty(),
  );

  unsafe {
    if let Err(e) = signal::sigaction(signal::SIGALRM, &sig_action) {
      error!("Failed to install SIGALRM handler: {}", e);
      return false;
    }
  }

  let (tx, rx) = mpsc::unbounded_channel::<DispatchTask>();
  DISPATCH_TASK_TX.get_or_init(|| tx);

  let handle = std::thread::Builder::new()
    .name("cpu-watch-dog".into())
    .spawn(move || {
      info!("CPU watchdog thread started");
      let mut rx = rx;
      while let Some(task) = rx.blocking_recv() {
        if task.quit {
          break;
        }
        task.process();
      }
      info!("CPU watchdog thread stopped");
    })
    .expect("Failed to spawn CPU watchdog thread");

  DISPATCH_THREAD_HANDLE.set(handle).ok();

  true
}

/// Ensure the watchdog is initialized. Call once at plugin startup.
pub fn ensure_watchdog_started() {
  start_watchdog();
}

/// Stop the watchdog. Call at plugin shutdown.
pub fn stop_watchdog() {
  if let Some(tx) = DISPATCH_TASK_TX.get() {
    let _ = tx.send(DispatchTask { timer_entry: None, quit: true });
  }
}
