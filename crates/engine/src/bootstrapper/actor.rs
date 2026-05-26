//! Bootstrapper actor.
//!
//! This actor stays online for the lifetime of the engine so other peers can
//! query our latest finalization. It also supports one higher-level control
//! request: wait until a safe initial state-sync floor is available.
//!
//! Fetch requests are retried periodically inside the actor. Callers should not
//! loop on the mailbox themselves because repeated fanout requests will run into
//! peer rate limits.
//!
//! Safety relies on an `f+1` assumption for peer set `0`. Every remote
//! response is validated before it can influence floor selection:
//! - the finalization certificate must verify against the configured threshold scheme
//! - only one response per peer counts in a round
//! - the pending fetch resolves only when `f+1` peers report the same proposal
//!
//! Peers only answer when they have a locally verified finalization. Nodes
//! without a safe floor stay silent for that round.

use super::{EngineFinalization, EngineMarshalMailbox, InitialTarget, Mailbox, mailbox::Message};
use crate::ThresholdScheme;
use commonware_codec::{Decode, Encode, EncodeSize, Error as CodecError, Read, ReadExt, Write};
use commonware_consensus::{simplex::types::Finalization, types::coding::Commitment};
use commonware_cryptography::{
    Hasher, PublicKey, bls12381::primitives::variant::Variant, certificate::Scheme,
};
use commonware_macros::select_loop;
use commonware_p2p::{Blocker, Provider, Receiver, Recipients, Sender};
use commonware_parallel::Sequential;
use commonware_runtime::{Clock, ContextCell, Handle, Spawner, spawn_cell};
use commonware_utils::{
    Faults, N3f1,
    channel::{fallible::OneshotExt, mpsc, oneshot},
};
use futures::future::{self, Either};
use rand_core::CryptoRngCore;
use std::time::{Duration, SystemTime};
use tracing::{debug, warn};

const PEER_SET_ID: u64 = 0;

/// Bootstrapper configuration.
pub struct Config<B, M, P, V>
where
    B: Blocker<PublicKey = P>,
    M: Provider<PublicKey = P>,
    P: PublicKey,
    V: Variant,
{
    /// Local validator identity.
    pub public_key: P,
    /// Provider for peer set `0`.
    pub peer_provider: M,
    /// Blocks peers that send malformed or inconsistent data.
    pub blocker: B,
    /// Threshold verifier for remote finalization certificates.
    pub scheme: ThresholdScheme<P, V>,
    /// Control mailbox capacity.
    pub mailbox_size: usize,
    /// Maximum time to wait for one network round to complete.
    pub round_timeout: Duration,
    /// Minimum delay between outbound fetch rounds.
    ///
    /// This throttles subscriber-driven fetches so the actor does not spam
    /// peers while waiting for a majority.
    pub retry_interval: Duration,
}

#[derive(Clone)]
enum WireMessage<P, V>
where
    P: PublicKey,
    V: Variant,
{
    Request {
        id: u64,
    },
    Response {
        id: u64,
        finalization: EngineFinalization<P, V>,
    },
}

impl<P, V> Write for WireMessage<P, V>
where
    P: PublicKey,
    V: Variant,
{
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::Request { id } => {
                0u8.write(buf);
                id.write(buf);
            }
            Self::Response { id, finalization } => {
                1u8.write(buf);
                id.write(buf);
                finalization.write(buf);
            }
        }
    }
}

impl<P, V> EncodeSize for WireMessage<P, V>
where
    P: PublicKey,
    V: Variant,
{
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Request { id } => id.encode_size(),
            Self::Response { id, finalization } => id.encode_size() + finalization.encode_size(),
        }
    }
}

impl<P, V> Read for WireMessage<P, V>
where
    P: PublicKey,
    V: Variant,
{
    type Cfg = WireConfig<P, V>;

    fn read_cfg(buf: &mut impl bytes::Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::Request {
                id: u64::read(buf)?,
            }),
            1 => Ok(Self::Response {
                id: u64::read(buf)?,
                finalization: Finalization::<ThresholdScheme<P, V>, Commitment>::read_cfg(
                    buf,
                    &cfg.certificate,
                )?,
            }),
            other => Err(CodecError::InvalidEnum(other)),
        }
    }
}

#[derive(Clone)]
struct WireConfig<P, V>
where
    P: PublicKey,
    V: Variant,
{
    certificate: <<ThresholdScheme<P, V> as Scheme>::Certificate as Read>::Cfg,
}

struct Fetch<P, V>
where
    P: PublicKey,
    V: Variant,
{
    id: u64,
    deadline: SystemTime,
    responses: Vec<(P, EngineFinalization<P, V>)>,
}

impl<P, V> Fetch<P, V>
where
    P: PublicKey,
    V: Variant,
{
    const fn new(id: u64, deadline: SystemTime) -> Self {
        Self {
            id,
            deadline,
            responses: Vec::new(),
        }
    }

    fn record_response(&mut self, peer: P, response: EngineFinalization<P, V>) {
        if self.responses.iter().any(|(existing, _)| *existing == peer) {
            return;
        }
        self.responses.push((peer, response));
    }

    fn majority_finalization(&self, required: usize) -> Option<EngineFinalization<P, V>> {
        let mut counts = Vec::new();

        for (_, finalization) in &self.responses {
            if let Some((_, count, _)) = counts
                .iter_mut()
                .find(|(proposal, _, _)| *proposal == finalization.proposal)
            {
                *count += 1;
                continue;
            }

            counts.push((finalization.proposal.clone(), 1, finalization.clone()));
        }

        counts
            .into_iter()
            .find_map(|(_, count, finalization)| (count >= required).then_some(finalization))
    }
}

/// Bootstrapper actor.
pub struct Actor<E, B, M, H, P, V>
where
    E: Clock + CryptoRngCore + Spawner,
    B: Blocker<PublicKey = P>,
    M: Provider<PublicKey = P>,
    H: Hasher,
    P: PublicKey,
    V: Variant,
{
    context: ContextCell<E>,
    mailbox: mpsc::Receiver<Message<H, P, V>>,
    public_key: P,
    peer_provider: M,
    blocker: B,
    scheme: ThresholdScheme<P, V>,
    marshal: Option<EngineMarshalMailbox<H, P, V>>,
    pending: Option<oneshot::Sender<InitialTarget<P, V>>>,
    fetch: Option<Fetch<P, V>>,
    retry_deadline: Option<SystemTime>,
    next_request_id: u64,
    quorum: usize,
    round_timeout: Duration,
    retry_interval: Duration,
    wire_config: WireConfig<P, V>,
}

impl<E, B, M, H, P, V> Actor<E, B, M, H, P, V>
where
    E: Clock + CryptoRngCore + Spawner,
    B: Blocker<PublicKey = P>,
    M: Provider<PublicKey = P>,
    H: Hasher,
    P: PublicKey,
    V: Variant,
{
    /// Create a new bootstrapper actor and its control [`Mailbox`].
    pub fn new(context: E, config: Config<B, M, P, V>) -> (Self, Mailbox<H, P, V>) {
        let (sender, mailbox) = mpsc::channel(config.mailbox_size);
        let mailbox_handle = Mailbox::new(sender);
        let n = config.scheme.participants().len();
        let quorum = N3f1::max_faults(n) as usize + 1;

        (
            Self {
                context: ContextCell::new(context),
                mailbox,
                public_key: config.public_key,
                peer_provider: config.peer_provider,
                blocker: config.blocker,
                scheme: config.scheme,
                marshal: None,
                pending: None,
                fetch: None,
                retry_deadline: None,
                next_request_id: 0,
                quorum,
                round_timeout: config.round_timeout,
                retry_interval: config.retry_interval,
                wire_config: WireConfig {
                    certificate: ThresholdScheme::<P, V>::certificate_codec_config_unbounded(),
                },
            },
            mailbox_handle,
        )
    }

    /// Spawn the actor on the runtime, returning a join handle.
    pub fn start<S, R>(mut self, network: (S, R)) -> Handle<()>
    where
        S: Sender<PublicKey = P> + Send + 'static,
        R: Receiver<PublicKey = P> + Send + 'static,
    {
        spawn_cell!(self.context, self.run(network))
    }

    /// Main event loop: multiplex mailbox and network messages.
    async fn run<S, R>(mut self, (mut sender, mut receiver): (S, R))
    where
        S: Sender<PublicKey = P>,
        R: Receiver<PublicKey = P>,
    {
        select_loop! {
            self.context,
            on_start => {
                let retry = match self.retry_deadline {
                    Some(deadline) => Either::Left(self.context.sleep_until(deadline)),
                    None => Either::Right(future::pending()),
                };
                let round = match &self.fetch {
                    Some(fetch) => Either::Left(self.context.sleep_until(fetch.deadline)),
                    None => Either::Right(future::pending()),
                };
            },
            on_stopped => {
                debug!("bootstrapper stopped");
            },
            _ = retry => {
                self.retry_deadline = None;
                self.start_fetch_if_needed(&mut sender).await;
            },
            _ = round => {
                self.handle_round_expired().await;
            },
            Some(message) = self.mailbox.recv() else {
                warn!("bootstrapper mailbox closed");
                break;
            } => {
                self.handle_message(message, &mut sender).await;
            },
            message = receiver.recv() => {
                let Ok((peer, payload)) = message else {
                    warn!("bootstrapper network closed");
                    break;
                };
                self.handle_network_message(peer, payload.as_ref(), &mut sender).await;
            },
        }
    }

    /// Dispatch a control message from the mailbox.
    async fn handle_message<S>(&mut self, message: Message<H, P, V>, sender: &mut S)
    where
        S: Sender<PublicKey = P>,
    {
        match message {
            Message::Attach { marshal } => {
                self.marshal = Some(marshal);
            }
            Message::FetchInitialTarget { response } => {
                debug_assert!(
                    self.pending.is_none(),
                    "only one fetch_initial_target caller is supported"
                );
                self.pending = Some(response);
                self.start_fetch_if_needed(sender).await;
            }
        }
    }

    /// Handle an inbound network message from a peer.
    async fn handle_network_message<S>(&mut self, peer: P, payload: &[u8], sender: &mut S)
    where
        S: Sender<PublicKey = P>,
    {
        let message = match WireMessage::<P, V>::decode_cfg(payload, &self.wire_config) {
            Ok(message) => message,
            Err(error) => {
                warn!(?error, "bootstrapper received malformed message");
                commonware_p2p::block!(
                    self.blocker,
                    peer,
                    "bootstrapper received malformed message"
                );
                return;
            }
        };

        match message {
            WireMessage::Request { id } => {
                let Some(finalization) = self.load_latest_finalization().await else {
                    return;
                };
                let wire = WireMessage::Response { id, finalization };
                let sent = sender.send(Recipients::One(peer), wire.encode(), false);
                if sent.is_empty() {
                    warn!("bootstrapper failed to send response");
                }
            }
            WireMessage::Response { id, finalization } => {
                self.handle_response(peer, id, finalization).await;
            }
        }
    }

    /// Process a peer's response to a fetch round.
    async fn handle_response(&mut self, peer: P, id: u64, response: EngineFinalization<P, V>) {
        let Some(finalization) = self.validate_response(&peer, response).await else {
            return;
        };

        let Some(fetch) = self.fetch.as_mut() else {
            return;
        };

        if fetch.id != id {
            return;
        }

        fetch.record_response(peer, finalization);

        let Some(finalization) = fetch.majority_finalization(self.quorum) else {
            return;
        };
        self.resolve_pending(finalization);
    }

    /// Verify a peer's finalization certificate.
    async fn validate_response(
        &mut self,
        peer: &P,
        finalization: EngineFinalization<P, V>,
    ) -> Option<EngineFinalization<P, V>> {
        if !finalization.verify(self.context.as_present_mut(), &self.scheme, &Sequential) {
            commonware_p2p::block!(
                self.blocker,
                peer.clone(),
                "bootstrapper received invalid finalization certificate"
            );
            return None;
        }

        Some(finalization)
    }

    /// Fan out a latest-finalization request to all peers and begin a new fetch round.
    async fn start_latest_round<S>(&mut self, sender: &mut S)
    where
        S: Sender<PublicKey = P>,
    {
        if !self.has_pending() {
            self.fetch = None;
            return;
        }

        let peers = self.peers().await;
        if peers.is_empty() {
            self.schedule_retry();
            return;
        }

        let id = self.next_id();
        let Some(sent) = Self::send_request(sender, id, peers).await else {
            warn!("bootstrapper failed to send latest-finalization request");
            self.schedule_retry();
            return;
        };
        if sent.len() < self.quorum {
            self.schedule_retry();
            return;
        }

        self.fetch = Some(Fetch::new(id, self.context.current() + self.round_timeout));
    }

    /// Retry later if the current round timed out without a majority.
    async fn handle_round_expired(&mut self) {
        if !self.has_pending() {
            self.fetch = None;
            return;
        }

        let Some(fetch) = self.fetch.take() else {
            return;
        };

        let Some(target) = fetch.majority_finalization(self.quorum) else {
            self.schedule_retry();
            return;
        };
        self.resolve_pending(target);
    }

    /// Load the latest local finalization from the marshal.
    ///
    /// The marshal only stores validated data, so we trust it without
    /// re-verifying the finalization certificate.
    async fn load_latest_finalization(&mut self) -> Option<EngineFinalization<P, V>> {
        let marshal = self.marshal.clone()?;
        let height = marshal.get_processed_height().await?;
        marshal.get_finalization(height).await
    }

    /// Return all peers in peer set 0, excluding ourselves.
    async fn peers(&mut self) -> Vec<P> {
        let Some(peers) = self.peer_provider.peer_set(PEER_SET_ID).await else {
            return Vec::new();
        };
        peers
            .primary
            .into_iter()
            .filter(|peer| *peer != self.public_key)
            .collect()
    }

    /// Broadcast a latest-finalization request to the given peers.
    async fn send_request<S>(sender: &mut S, id: u64, peers: Vec<P>) -> Option<Vec<P>>
    where
        S: Sender<PublicKey = P>,
    {
        let message = WireMessage::<P, V>::Request { id };
        let sent = sender.send(Recipients::Some(peers), message.encode(), false);
        if sent.is_empty() {
            return None;
        }
        Some(sent)
    }

    /// Clear the current round and wait before trying again.
    fn schedule_retry(&mut self) {
        self.fetch = None;
        if !self.has_pending() || self.retry_deadline.is_some() {
            return;
        }
        self.retry_deadline = Some(self.context.current() + self.retry_interval);
    }

    /// Allocate a monotonically increasing request id.
    const fn next_id(&mut self) -> u64 {
        let id = self.next_request_id;
        self.next_request_id = self.next_request_id.wrapping_add(1);
        id
    }

    /// Deliver the selected finalization to the pending caller.
    fn resolve_pending(&mut self, finalization: EngineFinalization<P, V>) {
        self.fetch = None;
        self.retry_deadline = None;
        if let Some(sender) = self.pending.take() {
            sender.send_lossy(finalization);
        }
    }

    /// Returns true when there is an active pending fetch whose receiver is still open.
    fn has_pending(&self) -> bool {
        self.pending
            .as_ref()
            .is_some_and(|sender| !sender.is_closed())
    }

    /// Start a new fetch round if there is a pending request and no work in flight.
    async fn start_fetch_if_needed<S>(&mut self, sender: &mut S)
    where
        S: Sender<PublicKey = P>,
    {
        if !self.has_pending() || self.fetch.is_some() || self.retry_deadline.is_some() {
            return;
        }

        self.start_latest_round(sender).await;
    }
}
