//! Bootstrap late validators over a dedicated engine-owned p2p channel.
//!
//! The bootstrapper has two jobs:
//! - serve the local finalized tip, including its finalization certificate
//! - help a fresh validator choose an initial state-sync target
//!
//! Target selection is intentionally small and conservative:
//! 1. ask peers for their latest finalized tip
//! 2. verify every certificate and block/certificate match
//! 3. resolve subscriptions as soon as a strict majority returns the same finalized tip
//! 4. retry on a fixed cadence if the round does not produce a majority
//!
//! The retry cadence is part of the protocol. Callers subscribe once and wait.
//! They do not poll the actor aggressively, which keeps outbound fanout low and
//! avoids peer rate limits.
//!
//! Byzantine safety relies on a strict-majority assumption for peer set `0`.
//! The actor only counts one response per peer and rejects malformed messages,
//! invalid certificates, and block/finalization mismatches before they can
//! influence the vote count.

use crate::ThresholdScheme;
use commonware_coding::ReedSolomon;
use commonware_consensus::{
    marshal::{coding::Coding, core::Mailbox as MarshalMailbox},
    simplex::types::Finalization,
    types::coding::Commitment,
};
use constantinople_primitives::{Block, Sealed};

mod actor;
pub use actor::{Actor, Config};

mod mailbox;
pub use mailbox::Mailbox;

type BootstrapBlock<H, P> = Sealed<Block<Commitment, P, H>, H>;
type BootstrapVariant<H, P> = Coding<BootstrapBlock<H, P>, ReedSolomon<H>, H, P>;
type BootstrapMarshal<H, P, V> = MarshalMailbox<ThresholdScheme<P, V>, BootstrapVariant<H, P>>;
type BootstrapFinalization<P, V> = Finalization<ThresholdScheme<P, V>, Commitment>;
