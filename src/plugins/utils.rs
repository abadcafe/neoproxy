use std::fmt;

/// CONNECT 目标地址解析错误
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectTargetError {
  /// 非 CONNECT 方法
  NotConnectMethod,
  /// URI 中无 authority
  NoAuthority,
  /// authority 中无端口号
  NoPort,
  /// 端口号为 0
  PortZero,
}

impl fmt::Display for ConnectTargetError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      ConnectTargetError::NotConnectMethod => {
        write!(f, "not CONNECT method")
      }
      ConnectTargetError::NoAuthority => {
        write!(f, "no authority in URI")
      }
      ConnectTargetError::NoPort => {
        write!(f, "no port in authority")
      }
      ConnectTargetError::PortZero => {
        write!(f, "port is zero")
      }
    }
  }
}

impl std::error::Error for ConnectTargetError {}

/// 解析 CONNECT 请求的目标地址
///
/// # 参数
/// - `parts`: HTTP 请求的 Parts
///
/// # 返回
/// - `Ok((host, port))`: 目标主机名和端口号
/// - `Err(ConnectTargetError)`: 解析失败
pub fn parse_connect_target(
  parts: &http::request::Parts,
) -> Result<(String, u16), ConnectTargetError> {
  if parts.method != http::Method::CONNECT {
    return Err(ConnectTargetError::NotConnectMethod);
  }

  let authority =
    parts.uri.authority().ok_or(ConnectTargetError::NoAuthority)?;

  let port = authority.port_u16().ok_or(ConnectTargetError::NoPort)?;

  if port == 0 {
    return Err(ConnectTargetError::PortZero);
  }

  Ok((authority.host().to_string(), port))
}

#[cfg(test)]
mod tests {
  use super::*;

  fn make_request_parts(
    method: http::Method,
    uri: &str,
  ) -> http::request::Parts {
    http::Request::builder()
      .method(method)
      .uri(uri)
      .body(())
      .unwrap()
      .into_parts()
      .0
  }

  #[test]
  fn test_parse_connect_target_valid() {
    let parts =
      make_request_parts(http::Method::CONNECT, "example.com:443");
    let result = parse_connect_target(&parts);
    assert_eq!(result, Ok(("example.com".to_string(), 443)));
  }

  #[test]
  fn test_parse_connect_target_not_connect_method() {
    let parts =
      make_request_parts(http::Method::GET, "http://example.com/");
    let result = parse_connect_target(&parts);
    assert_eq!(result, Err(ConnectTargetError::NotConnectMethod));
  }

  #[test]
  fn test_parse_connect_target_no_authority() {
    let parts = make_request_parts(http::Method::CONNECT, "/");
    let result = parse_connect_target(&parts);
    assert_eq!(result, Err(ConnectTargetError::NoAuthority));
  }

  #[test]
  fn test_parse_connect_target_no_port() {
    let parts =
      make_request_parts(http::Method::CONNECT, "example.com");
    let result = parse_connect_target(&parts);
    assert_eq!(result, Err(ConnectTargetError::NoPort));
  }

  #[test]
  fn test_parse_connect_target_port_zero() {
    let parts =
      make_request_parts(http::Method::CONNECT, "example.com:0");
    let result = parse_connect_target(&parts);
    assert_eq!(result, Err(ConnectTargetError::PortZero));
  }

  #[test]
  fn test_parse_connect_target_ipv6_address() {
    let parts = make_request_parts(http::Method::CONNECT, "[::1]:8080");
    let result = parse_connect_target(&parts);
    assert_eq!(result, Ok(("[::1]".to_string(), 8080)));
  }

  #[test]
  fn test_parse_connect_target_ipv4_address() {
    let parts =
      make_request_parts(http::Method::CONNECT, "192.168.1.1:80");
    let result = parse_connect_target(&parts);
    assert_eq!(result, Ok(("192.168.1.1".to_string(), 80)));
  }

  #[test]
  fn test_connect_target_error_display() {
    assert_eq!(
      format!("{}", ConnectTargetError::NotConnectMethod),
      "not CONNECT method"
    );
    assert_eq!(
      format!("{}", ConnectTargetError::NoAuthority),
      "no authority in URI"
    );
    assert_eq!(
      format!("{}", ConnectTargetError::NoPort),
      "no port in authority"
    );
    assert_eq!(
      format!("{}", ConnectTargetError::PortZero),
      "port is zero"
    );
  }

  #[test]
  fn test_connect_target_error_is_error() {
    let err = ConnectTargetError::NotConnectMethod;
    let _err: &dyn std::error::Error = &err;
  }
}
