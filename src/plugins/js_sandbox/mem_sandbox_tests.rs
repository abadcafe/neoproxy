use super::mem_sandbox::TrackingAllocator;

#[test]
fn test_tracking_allocator_new_starts_empty() {
  let allocator = TrackingAllocator::new(1024);

  assert_eq!(allocator.get_outstanding_size(), 0);
}

#[test]
fn test_tracking_allocator_can_create_v8_allocator() {
  let allocator = TrackingAllocator::new(1024);

  let _v8_allocator = allocator.get_allocator();
}
