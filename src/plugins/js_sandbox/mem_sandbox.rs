use std::ffi::c_void;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use deno_core::v8;
use tracing::{debug, error};

static TRACKING_ALLOCATOR_VTABLE: &v8::RustAllocatorVtable<
  TrackingAllocator,
> = &v8::RustAllocatorVtable {
  allocate,
  allocate_uninitialized,
  free,
  drop: vtable_drop,
};

unsafe extern "C" fn allocate(
  alloc: &TrackingAllocator,
  length: usize,
) -> *mut c_void {
  alloc.allocate(length)
}

unsafe extern "C" fn allocate_uninitialized(
  alloc: &TrackingAllocator,
  length: usize,
) -> *mut c_void {
  alloc.allocate_uninitialized(length)
}

unsafe extern "C" fn free(
  alloc: &TrackingAllocator,
  data: *mut c_void,
  length: usize,
) {
  alloc.free(data, length)
}

unsafe extern "C" fn vtable_drop(alloc: *const TrackingAllocator) {
  unsafe {
    Arc::from_raw(alloc);
  }
}

/// Custom V8 ArrayBuffer allocator that tracks outstanding memory and
/// enforces a total limit. Returns NULL when limits are exceeded so V8
/// handles OOM.
pub struct TrackingAllocator {
  outstanding_size: AtomicUsize,
  null_return_count: AtomicUsize,
  total_max: usize,
}

impl TrackingAllocator {
  pub fn new(total_max: usize) -> Arc<Self> {
    Arc::new(Self {
      outstanding_size: AtomicUsize::new(0),
      null_return_count: AtomicUsize::new(0),
      total_max,
    })
  }

  pub fn get_allocator(
    self: Arc<Self>,
  ) -> v8::UniqueRef<v8::Allocator> {
    unsafe {
      v8::new_rust_allocator(
        Arc::into_raw(self),
        TRACKING_ALLOCATOR_VTABLE,
      )
    }
  }

  pub fn get_outstanding_size(&self) -> usize {
    self.outstanding_size.load(Ordering::Acquire)
  }

  fn allocate(&self, length: usize) -> *mut c_void {
    if !self.check_limit(length) {
      return std::ptr::null_mut();
    }
    self.outstanding_size.fetch_add(length, Ordering::Release);
    let mut store = vec![0u8; length].into_boxed_slice();
    let data = store.as_mut_ptr();
    std::mem::forget(store);
    data.cast::<c_void>()
  }

  fn allocate_uninitialized(&self, length: usize) -> *mut c_void {
    if !self.check_limit(length) {
      return std::ptr::null_mut();
    }
    self.outstanding_size.fetch_add(length, Ordering::Release);
    let mut store = vec![0u8; length].into_boxed_slice();
    let data = store.as_mut_ptr();
    std::mem::forget(store);
    data.cast::<c_void>()
  }

  fn free(&self, data: *mut c_void, length: usize) {
    if data.is_null() || length == 0 {
      return;
    }
    let current = self.get_outstanding_size();
    if current < length {
      error!(
        "TrackingAllocator::free underflow: current={}, free_size={}",
        current, length
      );
      self.outstanding_size.store(0, Ordering::Release);
    } else {
      self.outstanding_size.fetch_sub(length, Ordering::Release);
    }
    unsafe {
      let slice =
        std::ptr::slice_from_raw_parts_mut(data.cast::<u8>(), length);
      drop(Box::from_raw(slice));
    }
  }

  fn check_limit(&self, length: usize) -> bool {
    let current = self.get_outstanding_size();
    if current + length > self.total_max {
      self.null_return_count.fetch_add(1, Ordering::Release);
      return false;
    }
    true
  }
}

impl Drop for TrackingAllocator {
  fn drop(&mut self) {
    let outstanding = self.get_outstanding_size();
    if outstanding != 0 {
      error!(
        "TrackingAllocator dropped with {} bytes leaked",
        outstanding
      );
    } else {
      debug!("TrackingAllocator dropped cleanly");
    }
  }
}

/// Install a near-heap-limit callback on the JsRuntime that terminates
/// execution when heap exceeds `heap_limit_bytes`, and always returns
/// `current * 2` to prevent a V8 process crash.
pub fn install_heap_limit_callback(
  runtime: &mut deno_core::JsRuntime,
  heap_limit_bytes: usize,
) {
  let isolate_handle = runtime.v8_isolate().thread_safe_handle();
  runtime.add_near_heap_limit_callback(move |current, _initial| {
    if current > heap_limit_bytes {
      error!(
        "Heap limit exceeded: current={}, limit={}. Terminating.",
        current, heap_limit_bytes
      );
      isolate_handle.terminate_execution();
    }
    current * 2
  });
}
