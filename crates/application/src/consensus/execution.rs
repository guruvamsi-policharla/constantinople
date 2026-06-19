//! Execution and commitment checks for consensus blocks.

use super::{
    MALFORMED_TRANSACTION, Result, STATIC_INVALID_TRANSACTION,
    body::PreparedBody,
    db::{self, StateBatch, TransactionBatch, apply_changeset, apply_transaction_digests},
    history::parent_transactions_inactivity_floor,
    reject_verify,
};
use crate::executor::{self, PreparedOperation, PreparedPayload, State};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_glue::stateful::db::Merkleized as _;
use commonware_parallel::Strategy;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::{merkle::Family, mmr, qmdb::batch_chain::Bounds, translator::EightCap};
use commonware_utils::non_empty_range;
use constantinople_primitives::{Account, AccountKey, Header, SealedBlock, SignedTransaction};
use hashbrown::HashSet;
use tracing::{Instrument as _, info_span};

pub(super) struct ProposalExecution<E, H, S>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    pub(super) block: BlockExecution<E, H, S>,
    pub(super) body: Vec<SignedTransaction<H>>,
}

pub(super) struct BlockExecution<E, H, S>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    pub(super) state: db::StateMerkleized<E, H, EightCap, S>,
    pub(super) transactions: db::TransactionMerkleized<E, H, S>,
    pub(super) state_sync_range: commonware_utils::range::NonEmptyRange<u64>,
    pub(super) transactions_range: commonware_utils::range::NonEmptyRange<u64>,
    pub(super) transaction_count: usize,
}

enum LoadedState {
    Unique(Vec<(AccountKey, Account)>),
    Shared(State),
}

impl<E, H, S> BlockExecution<E, H, S>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    pub(super) fn into_merkleized(self) -> db::MerkleizedDatabases<E, H, S> {
        (self.state, self.transactions)
    }
}

pub(super) async fn execute_proposal<E, C, P, H, S>(
    state_batch: StateBatch<E, H, EightCap, S>,
    transaction_batch: TransactionBatch<E, H, S>,
    parent: &SealedBlock<C, P, H>,
    input: executor::ProposalInput<H>,
    candidate_operations: &[PreparedOperation<H>],
) -> ProposalExecution<E, H, S>
where
    E: Storage + Clock + Metrics,
    C: Digest,
    H: Hasher,
    P: PublicKey,
    S: Strategy,
{
    let state = load_state(&state_batch, candidate_operations)
        .instrument(info_span!("application.execute.load_state"))
        .await
        .expect("proposal state loading must succeed");

    let output = info_span!("application.execute.operations")
        .in_scope(|| executor::propose_prepared(&state, input));
    let (state_batch, transaction_batch) = info_span!("application.execute.apply").in_scope(|| {
        let digests = operation_digests(&output.operations);
        let state_batch = apply_changeset(state_batch, &output.changeset);
        let transaction_batch = apply_transaction_digests(transaction_batch, &digests);
        (state_batch, transaction_batch)
    });

    ProposalExecution {
        block: finalize_child(
            state_batch,
            transaction_batch,
            parent,
            output.valid.len(),
            "database merkleization must succeed",
        )
        .await,
        body: output.valid,
    }
}

pub(super) async fn execute_body<E, C, P, H, S>(
    state_batch: StateBatch<E, H, EightCap, S>,
    transaction_batch: TransactionBatch<E, H, S>,
    parent: &SealedBlock<C, P, H>,
    body: PreparedBody<H>,
) -> Result<BlockExecution<E, H, S>>
where
    E: Storage + Clock + Metrics,
    C: Digest,
    P: PublicKey,
    H: Hasher,
    S: Strategy,
{
    let operations = info_span!("application.execute.prepare").in_scope(|| {
        body.iter()
            .map(|transaction| executor::prepare_operation(transaction.get()?))
            .collect::<Option<Vec<_>>>()
            .ok_or(MALFORMED_TRANSACTION)
    })?;

    let state = load_execution_state(&state_batch, &operations)
        .instrument(info_span!("application.execute.load_state"))
        .await
        .expect("block state loading must succeed");

    let changeset = info_span!("application.execute.operations")
        .in_scope(|| execute_loaded(&state, &operations))
        .ok_or(STATIC_INVALID_TRANSACTION)?;
    let (state_batch, transaction_batch) = info_span!("application.execute.apply").in_scope(|| {
        let digests = operation_digests(&operations);
        let state_batch = apply_changeset(state_batch, &changeset);
        let transaction_batch = apply_transaction_digests(transaction_batch, &digests);
        (state_batch, transaction_batch)
    });

    Ok(finalize_child(
        state_batch,
        transaction_batch,
        parent,
        operations.len(),
        "database merkleization during verification must succeed",
    )
    .await)
}

pub(super) async fn apply_prepared_body<E, H, S>(
    state_batch: StateBatch<E, H, EightCap, S>,
    transaction_batch: TransactionBatch<E, H, S>,
    transaction_floor: mmr::Location,
    operations: &[PreparedOperation<H>],
) -> Result<db::MerkleizedDatabases<E, H, S>>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    let state = load_execution_state(&state_batch, operations)
        .instrument(info_span!("application.execute.load_state"))
        .await
        .expect("state loading must succeed for certified apply");
    let changeset = info_span!("application.execute.operations")
        .in_scope(|| execute_loaded(&state, operations))
        .ok_or(STATIC_INVALID_TRANSACTION)?;
    let (state_batch, transaction_batch) = info_span!("application.execute.apply").in_scope(|| {
        let digests = operation_digests(operations);
        let state_batch = apply_changeset(state_batch, &changeset);
        let transaction_batch = apply_transaction_digests(transaction_batch, &digests)
            .with_inactivity_floor(transaction_floor);
        (state_batch, transaction_batch)
    });

    db::finalize_execution(state_batch, transaction_batch)
        .await
        .map_err(|_| STATIC_INVALID_TRANSACTION)
}

pub(super) fn commitments_match<E, C, P, H, S>(
    header: &Header<C, H::Digest, P>,
    execution: &BlockExecution<E, H, S>,
) -> bool
where
    E: Storage + Clock + Metrics,
    C: Digest,
    P: PublicKey,
    H: Hasher,
    S: Strategy,
{
    if execution.state.root() != header.state_root {
        reject_verify(header.height, "state_root_mismatch");
        return false;
    }
    if execution.state_sync_range != header.state_range {
        reject_verify(header.height, "state_range_mismatch");
        return false;
    }
    if execution.transactions.root() != header.transactions_root {
        reject_verify(header.height, "transaction_root_mismatch");
        return false;
    }
    if execution.transactions_range != header.transactions_range {
        reject_verify(header.height, "transaction_range_mismatch");
        return false;
    }

    true
}

async fn load_state<E, H, S>(
    batch: &StateBatch<E, H, EightCap, S>,
    operations: &[PreparedOperation<H>],
) -> core::result::Result<State, commonware_storage::qmdb::Error<mmr::Family>>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    if operations.is_empty() {
        return Ok(State::new());
    }

    let mut account_keys = HashSet::with_capacity(operations.len().saturating_mul(2));
    for operation in operations {
        insert_touched_accounts(&mut account_keys, operation);
    }

    load_accounts(batch, account_keys.into_iter().collect()).await
}

async fn load_execution_state<E, H, S>(
    batch: &StateBatch<E, H, EightCap, S>,
    operations: &[PreparedOperation<H>],
) -> core::result::Result<LoadedState, commonware_storage::qmdb::Error<mmr::Family>>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    if operations.is_empty() {
        return Ok(LoadedState::Unique(Vec::new()));
    }

    let mut account_keys = Vec::with_capacity(operations.len().saturating_mul(2));
    let mut unique = HashSet::with_capacity(operations.len().saturating_mul(2));
    for operation in operations {
        account_keys.push(&operation.sender);
        unique.insert(&operation.sender);
        if let Some(recipient) = operation_recipient(operation) {
            account_keys.push(recipient);
            unique.insert(recipient);
        }
    }

    if unique.len() == account_keys.len() {
        let values = batch.get_many(&account_keys).await?;
        let accounts = values
            .into_iter()
            .zip(account_keys)
            .map(|(account, key)| (key.clone(), account.unwrap_or_default()))
            .collect();
        return Ok(LoadedState::Unique(accounts));
    }

    load_accounts(batch, unique.into_iter().cloned().collect())
        .await
        .map(LoadedState::Shared)
}

async fn load_accounts<E, H, S>(
    batch: &StateBatch<E, H, EightCap, S>,
    account_keys: Vec<AccountKey>,
) -> core::result::Result<State, commonware_storage::qmdb::Error<mmr::Family>>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    if account_keys.is_empty() {
        return Ok(State::new());
    }

    let keys = account_keys.iter().collect::<Vec<_>>();
    let values = batch.get_many(&keys).await?;
    Ok(account_keys
        .into_iter()
        .zip(values)
        .map(|(account_key, account)| (account_key, account.unwrap_or_default()))
        .collect())
}

fn execute_loaded<H>(
    state: &LoadedState,
    operations: &[PreparedOperation<H>],
) -> Option<executor::Changeset>
where
    H: Hasher,
{
    match state {
        LoadedState::Unique(accounts) => executor::execute_unique(operations, accounts),
        LoadedState::Shared(accounts) => executor::execute(accounts, operations),
    }
}

#[tracing::instrument(name = "application.execute.finalize", level = "info", skip_all)]
async fn finalize_child<E, C, P, H, S>(
    state_batch: StateBatch<E, H, EightCap, S>,
    transaction_batch: TransactionBatch<E, H, S>,
    parent: &SealedBlock<C, P, H>,
    transaction_count: usize,
    expect_message: &'static str,
) -> BlockExecution<E, H, S>
where
    E: Storage + Clock + Metrics,
    C: Digest,
    P: PublicKey,
    H: Hasher,
    S: Strategy,
{
    let transaction_batch =
        transaction_batch.with_inactivity_floor(parent_transactions_inactivity_floor(parent));
    let (state, transactions) = db::finalize_execution(state_batch, transaction_batch)
        .await
        .expect(expect_message);
    let state_sync_range = range_from_bounds(state.bounds());
    let transactions_range = range_from_bounds(transactions.bounds());

    BlockExecution {
        state,
        transactions,
        state_sync_range,
        transactions_range,
        transaction_count,
    }
}

fn range_from_bounds<F>(bounds: &Bounds<F>) -> commonware_utils::range::NonEmptyRange<u64>
where
    F: Family,
{
    non_empty_range!(*bounds.inactivity_floor, bounds.total_size)
}

fn operation_digests<H>(operations: &[PreparedOperation<H>]) -> Vec<H::Digest>
where
    H: Hasher,
{
    operations
        .iter()
        .map(|operation| operation.digest)
        .collect()
}

fn insert_touched_accounts<H>(
    account_keys: &mut HashSet<AccountKey>,
    operation: &PreparedOperation<H>,
) where
    H: Hasher,
{
    account_keys.insert(operation.sender.clone());
    if let Some(recipient) = operation_recipient(operation) {
        account_keys.insert(recipient.clone());
    }
}

const fn operation_recipient<H>(operation: &PreparedOperation<H>) -> Option<&AccountKey>
where
    H: Hasher,
{
    match &operation.payload {
        PreparedPayload::PublicTransfer { recipient, .. }
        | PreparedPayload::PrivateTransfer { recipient, .. } => Some(recipient),
        PreparedPayload::PrivateFund { .. }
        | PreparedPayload::PrivateBurn { .. }
        | PreparedPayload::PrivateRollover => None,
    }
}

#[cfg(test)]
mod tests {
    use super::range_from_bounds;
    use commonware_storage::{mmr, qmdb::batch_chain::Bounds};
    use commonware_utils::non_empty_range;

    #[test]
    fn range_comes_from_qmdb_bounds() {
        let bounds = Bounds {
            base_size: 7,
            db_size: 9,
            total_size: 15,
            ancestors: Vec::new(),
            inactivity_floor: mmr::Location::new(11),
        };

        assert_eq!(range_from_bounds(&bounds), non_empty_range!(11, 15));
    }
}
