//! `run` subcommand — starts a validator from a TOML config.

use crate::{
    cli::StartupArg,
    config::{ValidatorConfig, decode_public_key},
};
use commonware_codec::Encode;
use commonware_consensus::simplex::elector::RoundRobin;
use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinSig, ed25519};
use commonware_glue::stateful::{StartupMode, db::SyncEngineConfig};
use commonware_p2p::{Ingress, Manager as _, authenticated::discovery};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Metrics as _, Quota, Runner as _,
    tokio::telemetry::{self, Logging},
};
use commonware_utils::{Acknowledgement, NZU64, NZUsize, TryCollect, hex};
use constantinople_application::processor::Precompiles;
use constantinople_engine::{
    CERTIFICATE_CHANNEL, Channels, Config as EngineConfig, Engine, MARSHAL_CHANNEL,
    MARSHAL_RESOLVER_CHANNEL, RESOLVER_CHANNEL, STATE_RESOLVER_CHANNEL,
    TRANSACTION_RESOLVER_CHANNEL, VOTE_CHANNEL,
};
use constantinople_mempool::server::Mempool;
use constantinople_primitives::Address;
use std::path::PathBuf;
use tracing::info;

#[derive(Clone, Debug, Default)]
struct NoopPrecompiles;

impl Precompiles for NoopPrecompiles {
    fn is_precompile(&self, _address: Address) -> bool {
        false
    }

    fn execute<S>(
        &self,
        _address: Address,
        _frame: &mut constantinople_application::processor::frame::Frame<'_>,
        _processor: &constantinople_application::processor::executor::Processor<'_, S, Self>,
    ) -> Result<bytes::Bytes, constantinople_application::processor::frame::FrameError>
    where
        S: commonware_parallel::Strategy,
    {
        Err(constantinople_application::processor::frame::FrameError::InvalidTransactionTarget)
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct NoopReporter;

impl commonware_consensus::Reporter for NoopReporter {
    type Activity = commonware_consensus::marshal::Update<
        constantinople_primitives::Sealed<
            constantinople_primitives::Block<
                commonware_consensus::types::coding::Commitment,
                ed25519::PublicKey,
                Sha256,
            >,
            Sha256,
        >,
    >;

    async fn report(&mut self, activity: Self::Activity) {
        if let commonware_consensus::marshal::Update::Block(_, response) = activity {
            response.acknowledge();
        }
    }
}

pub fn run(config_path: PathBuf, mode: StartupArg) {
    let raw = std::fs::read_to_string(&config_path).expect("failed to read config file");
    let cfg: ValidatorConfig = toml::from_str(&raw).expect("failed to parse config");
    let decoded = cfg.decode();

    let config_dir = config_path
        .parent()
        .expect("config file has no parent directory");
    let storage_dir = config_dir.join(&decoded.partition_prefix);
    let runtime_cfg = commonware_runtime::tokio::Config::new()
        .with_storage_directory(storage_dir)
        .with_worker_threads(cfg.worker_threads);
    let runner = commonware_runtime::tokio::Runner::new(runtime_cfg);

    let http_port = cfg.http_port;

    runner.start(|context| async move {
        telemetry::init(
            context.with_label("telemetry"),
            Logging {
                level: cfg.log_level.parse().expect("bad log_level in config"),
                json: false,
            },
            None,
            None,
        );

        info!(
            validator = %hex(&decoded.public_key.encode()),
            listen = %decoded.listen,
            http_port,
            "starting validator"
        );

        // Build the p2p network.
        let (mut network, mut oracle) = discovery::Network::new(
            context.with_label("p2p"),
            discovery::Config::local(
                decoded.signer.clone(),
                b"constantinople",
                decoded.listen,
                Ingress::Socket(decoded.listen),
                decoded.bootstrappers,
                4 * 1024 * 1024,
            ),
        );

        // Register all validators as peers.
        let all_pks = {
            let mut pks = vec![decoded.public_key.clone()];
            for b in &cfg.bootstrappers {
                pks.push(decode_public_key(&b.public_key));
            }
            pks
        };
        oracle
            .track(0, all_pks.into_iter().try_collect().unwrap())
            .await;

        // Register channels.
        let quota = Quota::per_second(std::num::NonZeroU32::MAX);
        let backlog = 1024;
        let channels = Channels {
            votes: network.register(VOTE_CHANNEL, quota, backlog),
            certificates: network.register(CERTIFICATE_CHANNEL, quota, backlog),
            resolver: network.register(RESOLVER_CHANNEL, quota, backlog),
            marshal: network.register(MARSHAL_CHANNEL, quota, backlog),
            marshal_resolver: network.register(MARSHAL_RESOLVER_CHANNEL, quota, backlog),
            state_resolver: network.register(STATE_RESOLVER_CHANNEL, quota, backlog),
            transaction_resolver: network.register(TRANSACTION_RESOLVER_CHANNEL, quota, backlog),
        };

        // Determine startup mode.
        let startup = match mode {
            StartupArg::MarshalSync => {
                info!("starting in marshal-sync mode");
                StartupMode::MarshalSync
            }
            StartupArg::StateSync => {
                info!("state-sync requested -- falling back to marshal-sync");
                StartupMode::MarshalSync
            }
        };

        // Build mempool with receipt callback.
        let mempool = Mempool::<
            commonware_consensus::types::coding::Commitment,
            ed25519::PublicKey,
            Sha256,
        >::new(
            b"constantinople-tx",
            constantinople_mempool::server::MempoolConfig {
                max_propose_bytes: cfg.max_propose_bytes,
                max_pool_bytes: cfg.max_pool_bytes,
            },
        );

        let mempool_inner = mempool.inner();
        let receipt_callback: constantinople_application::consensus::ReceiptCallback<
            <Sha256 as commonware_cryptography::Hasher>::Digest,
        > = std::sync::Arc::new(move |height, receipts| {
            let inner = mempool_inner.clone();
            tokio::spawn(async move {
                let mut guard = inner.lock().await;
                for receipt in &receipts {
                    let hash = receipt.transaction_hash.as_ref().to_vec();
                    if let Some(sender) = guard.waiters.remove(&hash) {
                        let _ = sender.send(constantinople_mempool::server::InclusionReceipt {
                            tx_hash: hex(&hash),
                            included: true,
                            height,
                            status: format!("{:?}", receipt.status),
                        });
                    }
                }
            });
        });

        let rejection_inner = mempool.inner();
        let rejection_callback: constantinople_application::consensus::RejectionCallback<
            <Sha256 as commonware_cryptography::Hasher>::Digest,
        > = std::sync::Arc::new(move |rejected_hashes| {
            let inner = rejection_inner.clone();
            tokio::spawn(async move {
                let mut guard = inner.lock().await;
                for hash in &rejected_hashes {
                    let hash_bytes = hash.as_ref().to_vec();
                    if let Some(sender) = guard.waiters.remove(&hash_bytes) {
                        let _ = sender.send(constantinople_mempool::server::InclusionReceipt {
                            tx_hash: hex(&hash_bytes),
                            included: false,
                            height: 0,
                            status: "Rejected".to_string(),
                        });
                    }
                }
            });
        });

        // Start HTTP server (state_reader filled after DB subscription).
        let router = constantinople_mempool::server::router(&mempool, None);
        let http_addr: std::net::SocketAddr = format!("0.0.0.0:{http_port}").parse().unwrap();
        let http_listener = tokio::net::TcpListener::bind(http_addr)
            .await
            .expect("failed to bind HTTP listener");
        info!(%http_addr, "HTTP server listening");
        let http_handle = tokio::spawn(async move {
            axum::serve(http_listener, router)
                .await
                .expect("HTTP server failed");
        });

        // Build and start the engine.
        info!("initializing engine");
        let engine = Engine::<_, _, _, _, Sha256, MinSig, RoundRobin<Sha256>, _, _, _>::new(
            context.with_label("engine"),
            EngineConfig {
                signer: decoded.signer,
                manager: oracle.clone(),
                blocker: oracle,
                namespace: b"constantinople".to_vec(),
                output: decoded.dkg_output,
                share: Some(decoded.share),
                input: mempool,
                precompiles: NoopPrecompiles,
                partition_prefix: decoded.partition_prefix,
                freezer_table_initial_size: 1024,
                strategy: Sequential,
                startup,
                sync_config: SyncEngineConfig {
                    fetch_batch_size: NZU64!(16),
                    apply_batch_size: 64,
                    max_outstanding_requests: 8,
                    update_channel_size: NZUsize!(256),
                    max_retained_roots: 32,
                },
                genesis_leader: decoded.genesis_leader,
                transaction_namespace: b"constantinople-tx",
                block_codec: Default::default(),
                genesis_allocations: decoded.genesis_allocations,
                receipt_callback: Some(receipt_callback),
                rejection_callback: Some(rejection_callback),
            },
        )
        .await;

        info!("starting engine");
        let engine_handle = engine.start(channels, None::<NoopReporter>);
        let network_handle = network.start();

        tokio::select! {
            _ = engine_handle => tracing::warn!("engine exited"),
            _ = network_handle => tracing::warn!("network exited"),
            _ = http_handle => tracing::warn!("http server exited"),
        }
    });
}
