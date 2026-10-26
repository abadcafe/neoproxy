//! module: address_race
//! responsibility: race network address candidates within one deadline
//! public operations: connect, RaceError
//! data entities: RaceError
//! tests: address_race_tests.rs

use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use futures_util::StreamExt;
use futures_util::stream::FuturesUnordered;
use tokio::time::{Instant, sleep_until};

const FALLBACK_DELAY: Duration = Duration::from_millis(250);

#[derive(Debug)]
pub(crate) enum RaceError<E> {
  NoAddresses,
  InvalidDeadline,
  Timeout,
  Failed(E),
}

pub(crate) async fn connect<T, E, F, Fut>(
  addresses: Vec<SocketAddr>,
  timeout: Duration,
  attempt: F,
) -> Result<T, RaceError<E>>
where
  F: Fn(SocketAddr) -> Fut,
  Fut: Future<Output = Result<T, E>>,
{
  if addresses.is_empty() {
    return Err(RaceError::NoAddresses);
  }
  let deadline = Instant::now()
    .checked_add(timeout)
    .ok_or(RaceError::InvalidDeadline)?;
  // RFC 8305 §4: try the other address family after the first
  // candidate, preserving resolver order within each family. Repeated
  // DNS answers must not consume another fallback interval/socket.
  let first_is_ipv6 = addresses[0].is_ipv6();
  let mut seen = std::collections::HashSet::new();
  let (preferred, alternate): (Vec<_>, Vec<_>) = addresses
    .into_iter()
    .filter(|address| seen.insert(*address))
    .partition(|address| address.is_ipv6() == first_is_ipv6);
  let mut preferred = preferred.into_iter();
  let mut alternate = alternate.into_iter();
  let mut ordered = Vec::new();
  loop {
    let first = preferred.next();
    let second = alternate.next();
    if first.is_none() && second.is_none() {
      break;
    }
    ordered.extend(first);
    ordered.extend(second);
  }
  let mut addresses = ordered.into_iter();
  // Poll attempts in the owning task. This supports worker-local
  // transports and cancels losing attempts immediately on drop, without
  // detached tasks or converting programming panics into JoinErrors.
  let mut attempts = FuturesUnordered::new();
  let mut next_attempt = Instant::now();
  let mut exhausted = false;
  let mut last_error = None;
  loop {
    if Instant::now() >= deadline {
      return Err(RaceError::Timeout);
    }
    if !exhausted
      && (attempts.is_empty() || Instant::now() >= next_attempt)
    {
      match addresses.next() {
        Some(address) => {
          attempts.push(Box::pin(attempt(address)));
          next_attempt = Instant::now() + FALLBACK_DELAY;
        }
        None => exhausted = true,
      }
    }
    if attempts.is_empty() && exhausted {
      return Err(RaceError::Failed(
        last_error.expect("all connection attempts failed"),
      ));
    }
    tokio::select! {
      _ = sleep_until(deadline) => {},
      _ = sleep_until(next_attempt), if !exhausted => {},
      result = attempts.next(), if !attempts.is_empty() => {
        match result.expect("connection attempt exists") {
          Ok(value) => return Ok(value),
          Err(error) => last_error = Some(error),
        }
      }
    }
  }
}
