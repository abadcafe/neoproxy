use super::scheduler::{WeightedItem, select};

#[test]
fn test_select_single_item() {
  let items = vec![WeightedItem::new(1, "primary")];
  assert_eq!(select(&items), Some(&"primary"));
}

#[test]
fn test_select_weighted_items() {
  let items = vec![
    WeightedItem::new(3, "primary"),
    WeightedItem::new(1, "secondary"),
  ];
  let mut primary_count = 0;
  let mut secondary_count = 0;

  for _ in 0..8 {
    match select(&items) {
      Some(&"primary") => primary_count += 1,
      Some(&"secondary") => secondary_count += 1,
      selected => panic!("unexpected selection: {selected:?}"),
    }
  }

  assert_eq!(primary_count, 6);
  assert_eq!(secondary_count, 2);
}

#[test]
fn test_select_empty_items() {
  let items: Vec<WeightedItem<&str>> = vec![];
  assert_eq!(select(&items), None);
}
