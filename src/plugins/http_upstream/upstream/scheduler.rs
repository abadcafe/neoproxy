use std::cell::Cell;

pub(crate) struct WeightedItem<T> {
  weight: usize,
  current_weight: Cell<isize>,
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
    items.iter().fold(0, |total, item| total + item.weight) as isize;
  let mut selected_idx = 0usize;
  let mut selected_weight = 0isize;

  for (idx, item) in items.iter().enumerate() {
    let new_current_weight =
      item.current_weight.get() + item.weight as isize;
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
