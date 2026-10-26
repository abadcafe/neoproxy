//! module: plugins::http_upstream::upstream::scheduler
//! responsibility: select weighted transports with smooth round
//! robin
//! public operations: WeightedItem, new, item, select
//! data entities: WeightedItem
//! tests: scheduler_tests.rs

use std::cell::Cell;

pub(crate) struct WeightedItem<T> {
  weight: usize,
  current_weight: Cell<i128>,
  item: T,
}

impl<T> WeightedItem<T> {
  pub(crate) fn new(weight: usize, item: T) -> Self {
    Self { weight, current_weight: Cell::new(0), item }
  }

  pub(crate) fn item(&self) -> &T {
    &self.item
  }
}

pub(crate) fn select<T>(items: &[WeightedItem<T>]) -> Option<&T> {
  if items.is_empty() {
    return None;
  }

  let total =
    items.iter().map(|item| item.weight as i128).sum::<i128>();
  let mut selected_idx = 0usize;
  let mut selected_weight = i128::MIN;

  for (idx, item) in items.iter().enumerate() {
    let new_current_weight =
      item.current_weight.get() + item.weight as i128;
    item.current_weight.set(new_current_weight);
    if new_current_weight > selected_weight {
      selected_weight = new_current_weight;
      selected_idx = idx;
    }
  }

  let selected = &items[selected_idx];
  selected.current_weight.set(selected.current_weight.get() - total);
  Some(selected.item())
}
