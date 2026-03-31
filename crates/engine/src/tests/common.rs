use crate::ThresholdScheme;
use bytes::Bytes;
use commonware_coding::ReedSolomon;
use commonware_consensus::{
    marshal::{self, Identifier, coding::Coding, core::Mailbox as MarshalMailbox},
    types::{Height, View, coding::Commitment},
};
use commonware_cryptography::{
    Digestible, Sha256, Signer,
    bls12381::{
        dkg::{Output, deal},
        primitives::{group::Share, variant::MinSig},
    },
    ed25519,
};
use commonware_glue::simulate::{processed::ProcessedHeight, tracker::FinalizationUpdate};
use commonware_runtime::{Clock, Metrics, Quota, Storage};
use commonware_storage::metadata::{Config as MetadataConfig, Metadata};
use commonware_utils::{N3f1, TryCollect, channel::mpsc, sequence::U64, sync::Mutex, test_rng};
use constantinople_application::processor::{
    Precompiles,
    executor::Processor,
    frame::{Frame, FrameError},
};
use constantinople_primitives::{Block, Sealed};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
    time::Duration,
};

pub(crate) type TestHasher = Sha256;
pub(crate) type TestPrivateKey = ed25519::PrivateKey;
pub(crate) type TestPublicKey = ed25519::PublicKey;
pub(crate) type TestScheme = ThresholdScheme<TestPublicKey, MinSig>;
pub(crate) type TestBlock = Sealed<Block<Commitment, TestPublicKey, TestHasher>, TestHasher>;
pub(crate) type TestVariant = Coding<TestBlock, ReedSolomon<TestHasher>, TestHasher, TestPublicKey>;
pub(crate) type TestMarshalMailbox = MarshalMailbox<TestScheme, TestVariant>;

pub(crate) const TRANSACTION_NAMESPACE: &[u8] = b"constantinople-engine-test-transactions";
const STATE_SYNC_METADATA_SUFFIX: &str = "_state_sync_metadata";
const SYNC_DONE_KEY: U64 = U64::new(0);
pub(crate) const TEST_QUOTA: Quota = Quota::per_second(std::num::NonZeroU32::MAX);

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct NoopReporter;

impl commonware_consensus::Reporter for NoopReporter {
    type Activity = marshal::Update<TestBlock>;

    async fn report(&mut self, activity: Self::Activity) {
        if let marshal::Update::Block(_, response) = activity {
            commonware_utils::Acknowledgement::acknowledge(response);
        }
    }
}

#[derive(Clone)]
pub(crate) struct HeightMonitorReporter<R> {
    inner: R,
    monitor: mpsc::Sender<FinalizationUpdate<TestPublicKey>>,
    public_key: TestPublicKey,
}

impl<R> HeightMonitorReporter<R> {
    pub(crate) const fn new(
        public_key: TestPublicKey,
        monitor: mpsc::Sender<FinalizationUpdate<TestPublicKey>>,
        inner: R,
    ) -> Self {
        Self {
            inner,
            monitor,
            public_key,
        }
    }
}

type Fixture = (
    Vec<TestPrivateKey>,
    Output<MinSig, TestPublicKey>,
    BTreeMap<TestPublicKey, Option<Share>>,
);

impl<R> commonware_consensus::Reporter for HeightMonitorReporter<R>
where
    R: commonware_consensus::Reporter<Activity = marshal::Update<TestBlock>>,
{
    type Activity = marshal::Update<TestBlock>;

    async fn report(&mut self, activity: Self::Activity) {
        if let marshal::Update::Tip(_, height, digest) = &activity {
            let _ = self
                .monitor
                .send(FinalizationUpdate {
                    pk: self.public_key.clone(),
                    view: View::new(height.get()),
                    block_digest: digest.as_ref().to_vec(),
                })
                .await;
        }

        self.inner.report(activity).await;
    }
}

#[derive(Clone)]
pub(crate) struct ValidatorState {
    pub(crate) marshal: TestMarshalMailbox,
    pub(crate) startup_sync_height: Option<u64>,
}

impl PartialEq for ValidatorState {
    fn eq(&self, other: &Self) -> bool {
        self.startup_sync_height == other.startup_sync_height
    }
}

impl Eq for ValidatorState {}

impl ValidatorState {
    pub(crate) async fn digest_at_height(&self, height: u64) -> Option<Vec<u8>> {
        self.marshal
            .get_block(Identifier::Height(Height::new(height)))
            .await
            .map(|block| block.digest().as_ref().to_vec())
    }

    pub(crate) async fn processed_height(&self) -> u64 {
        self.marshal
            .get_processed_height()
            .await
            .map_or(0, |height| height.get())
    }
}

impl ProcessedHeight for ValidatorState {
    async fn processed_height(&self) -> u64 {
        self.processed_height().await
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct NoopPrecompiles;

impl Precompiles for NoopPrecompiles {
    fn is_precompile(&self, _address: constantinople_primitives::Address) -> bool {
        false
    }

    fn execute<S, R>(
        &self,
        _address: constantinople_primitives::Address,
        _frame: &mut Frame<'_, R>,
        _processor: &Processor<'_, S, Self>,
    ) -> Result<Bytes, FrameError>
    where
        S: commonware_parallel::Strategy,
        R: constantinople_application::processor::state::StateReader,
    {
        Err(FrameError::InvalidTransactionTarget)
    }
}

pub(crate) fn validator_fixture(validators: u32) -> Fixture {
    let signers = (0..validators)
        .map(|seed| TestPrivateKey::from_seed(seed.into()))
        .collect::<Vec<_>>();
    let participants = signers
        .iter()
        .map(TestPrivateKey::public_key)
        .try_collect()
        .unwrap();

    let mut rng = test_rng();
    let (output, shares) = deal::<MinSig, _, N3f1>(&mut rng, Default::default(), participants)
        .expect("fixture deal should succeed");
    let shares = shares
        .into_iter()
        .map(|(public_key, share)| (public_key, Some(share)))
        .collect();

    (signers, output, shares)
}

pub(crate) async fn fetch_majority_sync_target(
    mailboxes: &Arc<Mutex<BTreeMap<TestPublicKey, TestMarshalMailbox>>>,
    context: &impl Clock,
    me: &TestPublicKey,
) -> Option<TestBlock> {
    for _ in 0..20 {
        let peers = {
            let guard = mailboxes.lock();
            guard
                .iter()
                .filter(|(peer, _)| *peer != me)
                .map(|(_, mailbox)| mailbox.clone())
                .collect::<Vec<_>>()
        };
        if peers.is_empty() {
            context.sleep(Duration::from_millis(100)).await;
            continue;
        }

        let mut heights = Vec::new();
        let mut peers_by_height = Vec::new();
        for mailbox in peers {
            let Some((height, _)) = mailbox.get_info(Identifier::Latest).await else {
                continue;
            };
            heights.push(height);
            peers_by_height.push((mailbox, height));
        }
        if peers_by_height.is_empty() {
            context.sleep(Duration::from_millis(100)).await;
            continue;
        }

        let required = peers_by_height.len() / 2 + 1;
        heights.sort();
        let quorum_height = heights[heights.len() - required];
        let mut counts = HashMap::new();

        for (mailbox, height) in peers_by_height {
            if height < quorum_height {
                continue;
            }

            let Some(block) = mailbox.get_block(Identifier::Height(quorum_height)).await else {
                continue;
            };
            counts
                .entry(block.digest())
                .and_modify(|count| *count += 1usize)
                .or_insert(1usize);
        }

        for (digest, count) in counts {
            if count < required {
                continue;
            }

            for mailbox in {
                let guard = mailboxes.lock();
                guard
                    .iter()
                    .filter(|(peer, _)| *peer != me)
                    .map(|(_, mailbox)| mailbox.clone())
                    .collect::<Vec<_>>()
            } {
                if let Some(block) = mailbox.get_block(Identifier::Digest(digest)).await {
                    return Some(block.into_inner());
                }
            }
        }

        context.sleep(Duration::from_millis(100)).await;
    }

    None
}

pub(crate) async fn state_sync_done(
    context: &(impl Storage + Clock + Metrics),
    partition_prefix: &str,
) -> bool {
    let metadata = Metadata::<_, U64, bool>::init(
        context.clone(),
        MetadataConfig {
            partition: format!("{partition_prefix}{STATE_SYNC_METADATA_SUFFIX}"),
            codec_config: (),
        },
    )
    .await
    .expect("failed to read state sync metadata");

    metadata.get(&SYNC_DONE_KEY).copied().unwrap_or(false)
}
