//! Generic API for confidential payments.

#![forbid(unsafe_code)]

pub mod backend;
pub mod client;
pub mod ledger;
pub mod protocol;

pub use backend::{Backend, Commitment, Opening};
pub use client::ClientBalance;
pub use ledger::{Account, apply};
pub use protocol::{AccountId, Transaction};
