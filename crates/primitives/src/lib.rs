#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

mod sealed;
pub use sealed::{Sealable, Sealed};

mod privacy;
#[cfg(feature = "privacy-backend-mock")]
pub use commonware_privacy::mocks::{
    MockBackend as MockPrivatePaymentBackend, MockCommitment, MockOpening, MockProof,
};
#[cfg(feature = "privacy-backend-simulator")]
pub use privacy::PrivatePaymentSimulatorBackend;
#[cfg(feature = "privacy-backend-zkpari")]
pub use privacy::ZkPariBn254Backend;
pub use privacy::{
    ChainPrivatePaymentBackend, PrivateAccount, PrivatePaymentBackend,
    PrivatePaymentExecutionBackend, StatePrivatePaymentBackend, to_state_burn_proof,
    to_state_commitment, to_state_fund_proof, to_state_transfer_proof,
};

mod signed;
pub use signed::{
    LazySignedTransaction, Signable, Signed, materialize_transaction_chunks,
    preload_transaction_chunks, verify_transaction_batch, verify_transaction_chunks,
};

mod account;
pub use account::{
    Account, AccountKey, DEFAULT_ACCOUNT_BALANCE, NONCE_BITMAP_CAPACITY, Nonce, StateAccount,
    from_state_account, to_state_account,
};

mod auth;
pub use auth::{TransactionBatchVerifier, TransactionPublicKey, TransactionSignature};

mod block;
pub use block::{Block, BlockCfg, Header, SealedBlock};

mod transaction;
pub use transaction::{SignedTransaction, Transaction, VerifiedTransaction};

/// Signing namespace for transaction signatures.
pub const TRANSACTION_NAMESPACE: &[u8] = b"constantinople-tx";
