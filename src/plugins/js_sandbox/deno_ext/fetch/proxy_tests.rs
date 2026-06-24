use super::{DomainMatcher, NoProxy, Target};

fn parse_target(s: &str) -> Target {
  Target::parse(s).unwrap()
}

#[test]
fn test_proxy_target_parse_supports_http_defaults_and_auth() {
  match parse_target("http://127.0.0.1:6666") {
    Target::Http { dst, auth } => {
      assert_eq!(dst, "http://127.0.0.1:6666");
      assert!(auth.is_none());
    }
    _ => panic!("bad target"),
  }

  match parse_target("127.0.0.1:6666") {
    Target::Http { dst, auth } => {
      assert_eq!(dst, "http://127.0.0.1:6666");
      assert!(auth.is_none());
    }
    _ => panic!("bad target"),
  }

  match parse_target("user:pass@127.0.0.1:6666") {
    Target::Http { dst, auth } => {
      assert_eq!(dst, "http://127.0.0.1:6666");
      assert!(auth.unwrap().is_sensitive());
    }
    _ => panic!("bad target"),
  }

  match parse_target("us%2Fer:p%2Fass@127.0.0.1:6666") {
    Target::Http { dst, auth } => {
      assert_eq!(dst, "http://127.0.0.1:6666");
      assert_eq!(auth.unwrap().to_str().unwrap(), "Basic dXMvZXI6cC9hc3M=");
    }
    _ => panic!("bad target"),
  }
}

#[test]
fn test_proxy_target_parse_supports_socks_and_platform_transports() {
  match parse_target("socks5://user:pass@127.0.0.1:6666") {
    Target::Socks { dst, auth } => {
      assert_eq!(dst, "socks5://127.0.0.1:6666");
      assert!(auth.is_some());
    }
    _ => panic!("bad target"),
  }

  match parse_target("socks5h://localhost:6666") {
    Target::Socks { dst, auth } => {
      assert_eq!(dst, "socks5h://localhost:6666");
      assert!(auth.is_none());
    }
    _ => panic!("bad target"),
  }

  #[cfg(not(windows))]
  match parse_target("unix:foo%20bar/baz") {
    Target::Unix { path } => {
      assert_eq!(path.to_str(), Some("foo bar/baz"));
    }
    _ => panic!("bad target"),
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  match parse_target("vsock:1234:5678") {
    Target::Vsock { cid, port } => {
      assert_eq!(cid, 1234);
      assert_eq!(port, 5678);
    }
    _ => panic!("bad target"),
  }
}

#[test]
fn test_domain_matcher_matches_exact_domains_and_subdomains() {
  let matcher = DomainMatcher(vec![".foo.bar".into(), "bar.foo".into()]);

  assert!(matcher.contains("foo.bar"));
  assert!(matcher.contains("www.foo.bar"));
  assert!(matcher.contains("bar.foo"));
  assert!(matcher.contains("www.bar.foo"));
  assert!(!matcher.contains("notfoo.bar"));
  assert!(!matcher.contains("notbar.foo"));
}

#[test]
fn test_no_proxy_wildcard_matches_every_host() {
  let no_proxy = NoProxy::from_string("*").unwrap();

  assert!(no_proxy.contains("any.where"));
}

#[test]
fn test_no_proxy_matches_domains_and_ip_ranges() {
  let no_proxy = NoProxy::from_string(
    ".foo.bar, bar.baz,10.42.1.1/24,::1,10.124.7.8,2001::/17",
  )
  .unwrap();

  let should_not_match = [
    "deno.com",
    "notfoo.bar",
    "notbar.baz",
    "10.43.1.1",
    "10.124.7.7",
    "[ffff:db8:a0b:12f0::1]",
    "[2005:db8:a0b:12f0::1]",
  ];

  for host in should_not_match {
    assert!(!no_proxy.contains(host), "should not contain {host:?}");
  }

  let should_match = [
    "hello.foo.bar",
    "bar.baz",
    "foo.bar.baz",
    "foo.bar",
    "10.42.1.100",
    "[::1]",
    "[2001:db8:a0b:12f0::1]",
    "10.124.7.8",
  ];

  for host in should_match {
    assert!(no_proxy.contains(host), "should contain {host:?}");
  }
}
