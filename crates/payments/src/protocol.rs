//! Backend-generic protocol transaction shape.

use crate::backend::Backend;

/// Account identifier used by an integrating chain while verifying a block.
pub type AccountId = u64;

/// A private-side transaction as the chain sees it.
pub enum Transaction<B: Backend> {
    /// Move public `value` into the sender's private pending commitment.
    Fund {
        /// Funding account.
        sender: AccountId,
        /// Public amount funded.
        value: u64,
        /// Commitment added to private state.
        fund_commitment: B::Commitment,
        /// Proof binding the commitment to `value`.
        proof: B::FundProof,
    },
    /// Confidential transfer of a hidden amount.
    Transfer {
        /// Sending account.
        sender: AccountId,
        /// Receiving account.
        recipient: AccountId,
        /// Published amount commitment.
        amount_commitment: B::Commitment,
        /// Proof that amount and remaining sender balance are in range.
        proof: B::TransferProof,
    },
    /// Fully de-shield the sender's private balance back to the public side.
    Burn {
        /// Burning account.
        sender: AccountId,
        /// Revealed plaintext balance.
        value: u64,
        /// Proof that current commitment opens to `value`.
        proof: B::BurnProof,
    },
}
