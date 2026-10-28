//! module: stream
//! responsibilities: expose protocol upgrade and tunnel transport
//! operations public operations: Io, upgrade types,
//! run_tunnel data entities: none
//! tests: stream_tests.rs

mod idle;
#[cfg(test)]
mod idle_tests;
mod transfer;
mod tunnel;
mod upgrade;
#[cfg(test)]
mod upgrade_tests;

pub(crate) use transfer::{
  IoSide, TransferEnd, TransferProgress, TransferTotals,
};
pub(crate) use tunnel::run_tunnel;
pub(crate) use upgrade::{OnUpgrade, UpgradeTrigger};

pub(crate) use crate::io_stream::Io;
