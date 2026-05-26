//! Bootstrap late validators over a dedicated engine-owned p2p channel.
//!
//! The bootstrapper has two jobs:
//! - serve the local latest finalization
//! - help a fresh validator choose an initial state-sync floor
//!
//! Target selection is intentionally small and conservative:
//! 1. ask peers for their latest finalization
//! 2. verify every finalization certificate
//! 3. resolve subscriptions as soon as `f+1` peers return the same proposal
//! 4. retry on a fixed cadence if the round does not reach the threshold
//!
//! The retry cadence is part of the protocol. Callers subscribe once and wait.
//! They do not poll the actor aggressively, which keeps outbound fanout low and
//! avoids peer rate limits.
//!
//! Reliability relies on an `f+1` assumption for peer set `0`:
//! the finalization certificate is verified independently, so the quorum
//! only ensures we have a reliable sync floor rather than trusting a
//! single peer. Because at most `f` peers can be Byzantine, `f+1` matching
//! responses guarantee at least one honest peer agrees on the proposal.
//! The actor only counts one response per peer and rejects malformed messages,
//! and invalid certificates before they can influence the vote count.

use crate::types::{EngineFinalization, EngineMarshalMailbox};

/// Initial state-sync finalization selected by the bootstrapper.
pub type InitialTarget<P, V> = EngineFinalization<P, V>;

mod actor;
pub use actor::{Actor, Config};

mod mailbox;
pub use mailbox::Mailbox;
