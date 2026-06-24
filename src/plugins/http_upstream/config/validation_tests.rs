use super::validation::validate_address_format;

#[test]
fn test_validate_address_format_accepts_host_port() {
  assert!(validate_address_format("example.com:8080").is_ok());
  assert!(validate_address_format("127.0.0.1:443").is_ok());
}

#[test]
fn test_validate_address_format_rejects_missing_port() {
  assert!(validate_address_format("example.com").is_err());
}

#[test]
fn test_validate_address_format_rejects_invalid_port() {
  assert!(validate_address_format("example.com:http").is_err());
}

#[test]
fn test_validate_address_format_rejects_missing_host() {
  assert!(validate_address_format(":8080").is_err());
}
