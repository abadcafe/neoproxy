use super::Config;

#[test]
fn test_init_global_sets_global_config() {
  let config = Config::parse_str("server_threads: 7").unwrap();

  Config::init_global(config);

  assert_eq!(Config::global().server_threads(), 7);
}
