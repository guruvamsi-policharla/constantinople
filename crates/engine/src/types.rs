//! Shared type aliases for the engine crate.
//!
//! These canonical aliases give a single definition to the core block,
//! coding, marshal, and finalization types that appear throughout the
//! engine, bootstrapper, and test modules.

use crate::ThresholdScheme;
use commonware_actor::Feedback;
use commonware_coding::ReedSolomon;
use commonware_consensus::{
    CertifiableBlock, Heightable, Reporter, Reporters,
    marshal::{
        ancestry::BlockProvider,
        coding::{Coding, Marshaled, shards, types::StoredCodedBlock},
        core::{
            CommitmentFallback, DigestFallback, Mailbox as MarshalMailbox,
            Variant as MarshalVariant,
        },
    },
    simplex::{self, types::Finalization},
    types::{Epoch, FixedEpocher, coding::Commitment},
};
use commonware_cryptography::{
    Hasher, PublicKey, bls12381::primitives::variant::Variant, certificate::ConstantProvider,
};
use commonware_glue::stateful::Stateful;
use commonware_storage::{mmr, qmdb::current::unordered::fixed, translator::EightCap};
use commonware_utils::sync::AsyncRwLock;
use constantinople_application::consensus::{
    Application, STATE_BITMAP_CHUNK_BYTES, TransactionHistoryDb, TransactionHistoryOperation,
};
use constantinople_primitives::{Account, AccountKey, Block, Sealed};
use std::{marker::PhantomData, sync::Arc};

/// A finalized block with its seal (commitment-based).
pub type EngineBlock<H, P> = Sealed<Block<Commitment, P, H>, H>;

/// The erasure-coding variant used by the marshal for block availability.
pub type EngineVariant<H, P> = Coding<EngineBlock<H, P>, ReedSolomon<H>, H, P>;

/// Marshal mailbox parameterized over the engine's threshold scheme.
pub type EngineMarshalMailbox<H, P, V> = MarshalMailbox<ThresholdScheme<P, V>, EngineVariant<H, P>>;

/// Block provider backed by the engine marshal mailbox.
#[derive(Clone)]
pub(crate) struct EngineBlockProvider<H, P, V>
where
    H: Hasher,
    P: PublicKey,
    V: Variant,
{
    mailbox: EngineMarshalMailbox<H, P, V>,
}

impl<H, P, V> From<EngineMarshalMailbox<H, P, V>> for EngineBlockProvider<H, P, V>
where
    H: Hasher,
    P: PublicKey,
    V: Variant,
{
    fn from(mailbox: EngineMarshalMailbox<H, P, V>) -> Self {
        Self { mailbox }
    }
}

impl<H, P, V> From<EngineBlockProvider<H, P, V>> for EngineMarshalMailbox<H, P, V>
where
    H: Hasher,
    P: PublicKey,
    V: Variant,
{
    fn from(provider: EngineBlockProvider<H, P, V>) -> Self {
        provider.mailbox
    }
}

impl<H, P, V> BlockProvider for EngineBlockProvider<H, P, V>
where
    H: Hasher,
    P: PublicKey,
    V: Variant,
{
    type Block = EngineBlock<H, P>;

    async fn subscribe(self, digest: H::Digest) -> Option<Self::Block> {
        self.mailbox
            .subscribe_by_digest(digest, DigestFallback::Wait)
            .await
            .ok()
            .map(<EngineVariant<H, P> as MarshalVariant>::into_inner)
    }

    async fn subscribe_parent(self, block: Self::Block) -> Option<Self::Block> {
        let parent_height = block.height().previous()?;
        let commitment = block.context().parent.1;
        self.mailbox
            .subscribe_by_commitment(
                commitment,
                CommitmentFallback::FetchByCommitment {
                    height: parent_height,
                },
            )
            .await
            .ok()
            .map(<EngineVariant<H, P> as MarshalVariant>::into_inner)
    }
}

/// A finalization certificate over the engine's threshold scheme.
pub type EngineFinalization<P, V> = Finalization<ThresholdScheme<P, V>, Commitment>;

/// Simplex activity stream observed by the engine, used by the optional
/// `simplex_observer` reporter slot in [`crate::Config`].
pub type EngineActivity<P, V> = simplex::types::Activity<ThresholdScheme<P, V>, Commitment>;

/// A no-op [`Reporter`] over [`EngineActivity`].
///
/// Pass `None::<NoopActivityReporter<P, V>>` to [`crate::Config::simplex_observer`]
/// when no external observer is wired in. The type parameter exists only to
/// pin the activity type; the reporter never forwards anything.
pub struct NoopActivityReporter<P, V>(PhantomData<fn() -> (P, V)>);

impl<P, V> Default for NoopActivityReporter<P, V> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<P, V> Clone for NoopActivityReporter<P, V> {
    fn clone(&self) -> Self {
        Self::default()
    }
}

impl<P, V> std::fmt::Debug for NoopActivityReporter<P, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoopActivityReporter").finish()
    }
}

impl<P, V> Reporter for NoopActivityReporter<P, V>
where
    P: PublicKey,
    V: Variant,
{
    type Activity = EngineActivity<P, V>;

    fn report(&mut self, _: Self::Activity) -> Feedback {
        Feedback::Ok
    }
}

pub(crate) type CodingBlock<H, P> = StoredCodedBlock<EngineBlock<H, P>, ReedSolomon<H>, H>;

pub type StateDb<E, H, P, T> =
    fixed::Db<mmr::Family, E, AccountKey<P>, Account, H, EightCap, STATE_BITMAP_CHUNK_BYTES, T>;

pub type StateSyncDb<E, H, P, T> = Arc<AsyncRwLock<StateDb<E, H, P, T>>>;

pub(crate) type StateResolverMailbox<E, H, P, T> = commonware_glue::stateful::db::p2p::Mailbox<
    StateDb<E, H, P, T>,
    mmr::Family,
    <StateSyncDb<E, H, P, T> as commonware_storage::qmdb::sync::resolver::Resolver>::Op,
    <StateSyncDb<E, H, P, T> as commonware_storage::qmdb::sync::resolver::Resolver>::Digest,
>;

pub(crate) type StateResolverActor<E, P, M, B, H, T> =
    commonware_glue::stateful::db::p2p::Actor<E, P, M, B, mmr::Family, StateDb<E, H, P, T>>;

pub type TransactionDb<E, H, T> = TransactionHistoryDb<E, H, T>;

pub type TransactionSyncDb<E, H, T> = Arc<AsyncRwLock<TransactionDb<E, H, T>>>;

pub(crate) type TransactionResolverMailbox<E, H, T> =
    commonware_glue::stateful::db::compact_p2p::Mailbox<
        TransactionDb<E, H, T>,
        mmr::Family,
        TransactionHistoryOperation<H>,
        H,
    >;

pub(crate) type TransactionResolverActor<E, P, M, B, H, T> =
    commonware_glue::stateful::db::compact_p2p::Actor<
        E,
        P,
        M,
        B,
        mmr::Family,
        TransactionDb<E, H, T>,
        H,
    >;

pub(crate) type App<E, H, P, V, I, B, SigT, HashT> =
    Application<E, H, Commitment, ThresholdScheme<P, V>, P, I, B, SigT, HashT>;

pub(crate) type AppMailbox<E, H, P, V, I, B, SigT, HashT> =
    commonware_glue::stateful::Mailbox<E, App<E, H, P, V, I, B, SigT, HashT>>;

pub(crate) type SchemeProvider<P, V> = ConstantProvider<ThresholdScheme<P, V>, Epoch>;

pub(crate) type StatefulApp<E, H, P, V, I, B, SigT, HashT> = Stateful<
    E,
    App<E, H, P, V, I, B, SigT, HashT>,
    EngineBlockProvider<H, P, V>,
    (
        StateResolverMailbox<E, H, P, HashT>,
        TransactionResolverMailbox<E, H, HashT>,
    ),
>;

pub(crate) type MarshaledApp<E, H, P, V, I, B, SigT, HashT> = Marshaled<
    E,
    AppMailbox<E, H, P, V, I, B, SigT, HashT>,
    EngineBlock<H, P>,
    ReedSolomon<H>,
    H,
    SchemeProvider<P, V>,
    HashT,
    FixedEpocher,
>;

pub(crate) type ShardsEngine<E, B, M, H, P, V, T> =
    shards::Engine<E, SchemeProvider<P, V>, B, M, ReedSolomon<H>, H, EngineBlock<H, P>, P, T>;

pub(crate) type ShardsMailbox<H, P> = shards::Mailbox<EngineBlock<H, P>, ReedSolomon<H>, H, P>;

/// Reporter combinator that fans simplex activity to the marshal mailbox and
/// an optional external observer (e.g. the indexer's certificate publisher).
pub(crate) type SimplexReporter<H, P, V, O> =
    Reporters<EngineActivity<P, V>, EngineMarshalMailbox<H, P, V>, O>;

pub(crate) type SimplexEngine<E, B, H, P, V, L, SigT, HashT, I, BV, O> = simplex::Engine<
    E,
    ThresholdScheme<P, V>,
    L,
    B,
    Commitment,
    MarshaledApp<E, H, P, V, I, BV, SigT, HashT>,
    MarshaledApp<E, H, P, V, I, BV, SigT, HashT>,
    SimplexReporter<H, P, V, O>,
    HashT,
>;
