use crate::tests::common::ValidatorState;
use commonware_cryptography::PublicKey;
use commonware_glue::simulate::{
    exit::ExitCondition, property::Property, tracker::ProgressTracker,
};
use std::{future::Future, pin::Pin};

#[derive(Clone, Copy)]
pub(crate) struct BlockAgreementAtHeight {
    height: u64,
    minimum_count: Option<usize>,
}

impl BlockAgreementAtHeight {
    pub(crate) const fn new(height: u64) -> Self {
        Self {
            height,
            minimum_count: None,
        }
    }

    pub(crate) const fn at_least(height: u64, minimum_count: usize) -> Self {
        Self {
            height,
            minimum_count: Some(minimum_count),
        }
    }
}

impl Property<crate::tests::common::TestPublicKey, ValidatorState> for BlockAgreementAtHeight {
    fn name(&self) -> &str {
        "block_agreement_at_height"
    }

    fn check<'a>(
        &'a self,
        _tracker: &'a ProgressTracker<crate::tests::common::TestPublicKey>,
        states: &'a [&'a ValidatorState],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let mut expected = None;
            let mut present = 0usize;
            for state in states {
                let Some(digest) = state.digest_at_height(self.height).await else {
                    if self.minimum_count.is_some() {
                        continue;
                    }

                    return Err(format!(
                        "missing finalized digest at height {} on at least one validator",
                        self.height
                    ));
                };
                present += 1;

                if let Some(previous) = expected.as_ref() {
                    if previous != &digest {
                        return Err(format!(
                            "digest disagreement at finalized height {}",
                            self.height
                        ));
                    }
                    continue;
                }

                expected = Some(digest);
            }

            if let Some(minimum_count) = self.minimum_count
                && present < minimum_count
            {
                return Err(format!(
                    "only {present} validators observed finalized height {}, expected at least {minimum_count}",
                    self.height
                ));
            }

            Ok(())
        })
    }
}

#[derive(Clone, Copy)]
pub(crate) struct FinalizedHeightAtLeast {
    height: u64,
}

impl FinalizedHeightAtLeast {
    pub(crate) const fn new(height: u64) -> Self {
        Self { height }
    }
}

impl<P: PublicKey> ExitCondition<P, ValidatorState> for FinalizedHeightAtLeast {
    fn name(&self) -> &str {
        "finalized_height_at_least"
    }

    fn requires_polling(&self) -> bool {
        true
    }

    fn reached<'a>(
        &'a self,
        _tracker: &'a ProgressTracker<P>,
        states: &'a [&'a ValidatorState],
        target_count: usize,
    ) -> Pin<Box<dyn Future<Output = Result<bool, String>> + Send + 'a>> {
        Box::pin(async move {
            let mut reached = 0usize;
            for state in states {
                if state.digest_at_height(self.height).await.is_some() {
                    reached += 1;
                }
            }

            Ok(reached >= target_count)
        })
    }
}

#[derive(Clone, Copy)]
pub(crate) struct StateSyncReadyAtHeight {
    height: u64,
}

impl StateSyncReadyAtHeight {
    pub(crate) const fn new(height: u64) -> Self {
        Self { height }
    }
}

impl<P: PublicKey> ExitCondition<P, ValidatorState> for StateSyncReadyAtHeight {
    fn name(&self) -> &str {
        "state_sync_ready_at_height"
    }

    fn requires_polling(&self) -> bool {
        true
    }

    fn reached<'a>(
        &'a self,
        _tracker: &'a ProgressTracker<P>,
        states: &'a [&'a ValidatorState],
        target_count: usize,
    ) -> Pin<Box<dyn Future<Output = Result<bool, String>> + Send + 'a>> {
        Box::pin(async move {
            let mut finalized = 0usize;
            let mut handoff = false;

            for state in states {
                if state.digest_at_height(self.height).await.is_some() {
                    finalized += 1;
                }

                let Some(sync_height) = state.startup_sync_height else {
                    continue;
                };
                if state.processed_height().await > sync_height {
                    handoff = true;
                }
            }

            Ok(finalized >= target_count.saturating_sub(1) && handoff)
        })
    }
}

#[derive(Clone, Copy)]
pub(crate) struct LateJoinerStateSyncHandoff;

impl Property<crate::tests::common::TestPublicKey, ValidatorState> for LateJoinerStateSyncHandoff {
    fn name(&self) -> &str {
        "late_joiner_state_sync_handoff"
    }

    fn check<'a>(
        &'a self,
        _tracker: &'a ProgressTracker<crate::tests::common::TestPublicKey>,
        states: &'a [&'a ValidatorState],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            for state in states {
                let Some(sync_height) = state.startup_sync_height else {
                    continue;
                };

                if state.processed_height().await > sync_height {
                    return Ok(());
                }
            }

            Err(
                "no validator both used startup state sync and advanced beyond the synced height"
                    .to_string(),
            )
        })
    }
}
