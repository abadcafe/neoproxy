use super::layer::Layer;

#[test]
fn test_layer_default() {
  let layer = Layer::default();

  assert!(layer.plugin_name().is_empty());
  assert!(layer.kind().is_empty());
}
