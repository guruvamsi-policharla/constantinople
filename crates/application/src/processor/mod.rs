//! In-memory transaction processing.
//!
//! This module owns the processor entrypoint that executes signed
//! transactions over a prebuilt in-memory [`State`](state::State) snapshot.
//! Processing has five stages:
//!
//! 1. Load or otherwise construct the in-memory [`State`](state::State)
//!    snapshot.
//! 2. Statically validate each transaction against the visible in-memory state.
//! 3. Greedily schedule transactions into dependency rounds from the declared
//!    access lists.
//! 4. Execute those rounds and merge the results back into committed state in
//!    transaction order.
//! 5. Export the final persistent changeset for database application.
//!
//! The processor does not mutate the backing store directly. Instead callers
//! first prepare a [`State`](state::State) from whatever source they have
//! available, then execute against that isolated in-memory overlay and export
//! a deterministic changeset once execution is complete.

use bytes::Bytes;
use commonware_parallel::Strategy;
use constantinople_primitives::Address;

pub mod executor;
pub mod frame;
pub mod keys;
pub mod state;

mod access;
mod schedule;

#[cfg(test)]
mod tests;

/// A precompile registry and executor.
///
/// Implementors register precompile addresses and provide the execution logic
/// that runs inside a [`Frame`](frame::Frame) when a transaction or nested
/// call targets a registered address.
pub trait Precompiles: Sync {
    /// Returns whether `address` is a registered precompile.
    fn is_precompile(&self, address: Address) -> bool;

    /// Executes the precompile at `address` inside `frame`.
    ///
    /// The frame provides the precompile with access to account and storage
    /// state scoped to the declared access list. On success, return the
    /// output bytes. On failure, return a [`FrameError`](frame::FrameError).
    fn execute<S>(
        &self,
        address: Address,
        frame: &mut frame::Frame<'_>,
        processor: &executor::Processor<'_, S, Self>,
    ) -> Result<Bytes, frame::FrameError>
    where
        S: Strategy,
        Self: Sized;
}
