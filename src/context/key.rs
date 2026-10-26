//! module: key
//! responsibility: bind field names to compile-time value types
//! public operations: ContextKey
//! data entities: ContextKey
//! tests: context_tests.rs
pub(crate) struct ContextKey<T> {
  pub(super) name: &'static str,
  marker: std::marker::PhantomData<fn() -> T>,
}
impl<T> Copy for ContextKey<T> {}
impl<T> Clone for ContextKey<T> {
  fn clone(&self) -> Self {
    *self
  }
}
impl<T> ContextKey<T> {
  pub(in crate::context) const fn new(name: &'static str) -> Self {
    Self { name, marker: std::marker::PhantomData }
  }
}
