//! Cryptographic components for private (Zether-style) transfers.
//!
//! This is a thin adapter over [`zkpari::ledger`], which owns the actual
//! cryptography: the range-proof relation, key generation, proving, the HVZK
//! simulator, and random-linear-combination batch verification. This module
//! supplies only the chain-facing types the rest of constantinople depends on
//! (`BalanceCommitment`, `TransferProof`, `BurnProof`, `PrivateBalance`,
//! `verify_proofs_batch`, …), their wire codecs, and a process-wide CRS.
//!
//! Curve: **BN254** G1. Private balances are Pedersen commitments in the
//! payment basis fixed by the ledger CRS. A private transfer publishes the
//! amount commitment and **two** single-value range proofs — one for the
//! amount, one for the sender's remaining balance
//! (`com_remaining = com_sender - com_amount`, derived by the verifier). Both
//! values lie in `[0, 2^64)`, which together with the homomorphic
//! conservation `com_sender = com_amount + com_remaining` rules out overflow
//! and over-spending.
//!
//! Funds and burns move value between the public `u64` balance and the private
//! commitment with a public amount. Funding adds `commit(v)` (zero opening,
//! publicly computable) and needs no proof. A burn is a transfer to a public
//! sink: its amount is the public `commit(value)`, so it carries only the
//! remaining-balance range proof.
//!
//! Incoming payments accumulate in a separate `pending` commitment so an
//! in-flight outgoing chain can never be invalidated by a deposit (the Zether
//! griefing attack); the real protocol adds an epoch rollover folding
//! `pending` into the spendable balance, which this example chain omits.
//!
//! # Trusted setup
//!
//! The CRS is generated deterministically from a fixed seed at first use
//! ([`params`]). This stands in for a real multi-party trusted setup and is
//! **demo-grade only**: anyone can recompute the toxic waste. Swap [`params`]
//! for externally distributed keys to productionize.

use ark_bn254::Bn254;
use ark_ec::{AffineRepr, CurveGroup, pairing::Pairing};
use bytes::{Buf, BufMut};
use commonware_codec::{Error as CodecError, FixedSize, Read, Write};
use commonware_formatting::hex;
use rand::{SeedableRng, rngs::StdRng};
use rand_core::{OsRng, RngCore};
use std::sync::OnceLock;
use zkpari::{
    CommittedInputOpening, Proof, ProvingKey, ZkPari,
    ledger::{LedgerParams, RangeProof},
};

type E = Bn254;
type Fr = <E as Pairing>::ScalarField;
type G1 = <E as Pairing>::G1Affine;

/// Compressed G1 encoding length, used for the canonical identity cache
/// (equality, ordering, hashing, hex display).
const G1_BYTES: usize = 32;
/// Uncompressed G1 encoding length, used on the wire: decoding skips the
/// square root that compressed decoding pays to recover `y`.
const G1_UNCOMPRESSED_BYTES: usize = 64;
/// Scalar (`Fr`) encoding length.
const FR_BYTES: usize = 32;

/// One transmitted range proof: `T`, `U` (uncompressed G1) and the scalar
/// `v_a`. The committed-input commitment is not transmitted — the verifier
/// reconstructs it from ledger state.
const RANGE_PROOF_BYTES: usize = 2 * G1_UNCOMPRESSED_BYTES + FR_BYTES;

/// Seed for the deterministic demo CRS. See the module docs: demo-grade only.
const CRS_SEED: u64 = 0xC0457A47_71400713;

/// Returns the process-wide ledger parameters (proving/verifying keys and the
/// retained setup trapdoor), generating them deterministically on first use.
///
/// The trapdoor is toxic waste in a real deployment; here the CRS is
/// demo-grade and the trapdoor powers the fast simulated-proof path used by
/// load generators ([`PrivateBalance::simulate_transfer`]).
fn params() -> &'static LedgerParams<E> {
    static PARAMS: OnceLock<LedgerParams<E>> = OnceLock::new();
    PARAMS.get_or_init(|| LedgerParams::<E>::setup(&mut StdRng::seed_from_u64(CRS_SEED)))
}

/// Returns the ZK-Pari proving key shared by clients and validators.
///
/// Exposed so external tooling can commit and prove against the same CRS.
pub fn proving_key() -> &'static ProvingKey<E> {
    &params().pk
}

fn g1_to_compressed(point: &G1) -> [u8; G1_BYTES] {
    let mut bytes = [0u8; G1_BYTES];
    point
        .serialize_compressed(&mut bytes[..])
        .expect("compressed G1 fits its encoding");
    bytes
}

fn g1_to_uncompressed(point: &G1) -> [u8; G1_UNCOMPRESSED_BYTES] {
    let mut bytes = [0u8; G1_UNCOMPRESSED_BYTES];
    point
        .serialize_uncompressed(&mut bytes[..])
        .expect("uncompressed G1 fits its encoding");
    bytes
}

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

/// Validated uncompressed decode: canonical, on-curve, **and prime-order
/// subgroup**. Load-bearing — these points enter unchecked MSMs and pairings.
fn g1_from_uncompressed(bytes: &[u8]) -> Option<G1> {
    G1::deserialize_uncompressed(bytes).ok()
}

fn g1_from_compressed(bytes: &[u8]) -> Option<G1> {
    G1::deserialize_compressed(bytes).ok()
}

fn read_array<const N: usize>(buf: &mut impl Buf) -> Result<[u8; N], CodecError> {
    if buf.remaining() < N {
        return Err(CodecError::EndOfBuffer);
    }
    let mut bytes = [0u8; N];
    buf.copy_to_slice(&mut bytes);
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// BalanceCommitment
// ---------------------------------------------------------------------------

/// A Pedersen commitment to a private balance (a BN254 G1 point).
///
/// The chain stores and homomorphically updates these: a private transfer
/// subtracts the amount commitment from the sender's balance commitment and
/// adds it to the recipient's pending commitment. The identity point commits
/// to zero with zero blinding. A compressed-bytes cache backs equality,
/// ordering, hashing, and hex display; the wire codec is uncompressed.
#[derive(Debug, Clone, Copy)]
pub struct BalanceCommitment {
    point: G1,
    bytes: [u8; G1_BYTES],
}

impl BalanceCommitment {
    fn from_point(point: G1) -> Self {
        Self {
            bytes: g1_to_compressed(&point),
            point,
        }
    }

    /// The commitment to a zero balance (the identity point).
    pub fn zero() -> Self {
        Self::from_point(G1::zero())
    }

    /// Reconstructs a commitment from its canonical compressed encoding.
    pub fn from_bytes(bytes: &[u8; G1_BYTES]) -> Option<Self> {
        Some(Self::from_point(g1_from_compressed(bytes)?))
    }

    /// The canonical compressed encoding (identity for equality/hashing/hex).
    pub const fn as_bytes(&self) -> &[u8; G1_BYTES] {
        &self.bytes
    }

    /// Publicly computable commitment to `value` with zero blinding.
    pub fn commit(value: u64) -> Self {
        Self::from_point(params().commit(value))
    }

    /// Commitment to `value` with blinding `opening`, in the payment basis.
    pub fn commit_with(value: u64, opening: &CommittedInputOpening<Fr>) -> Self {
        Self::from_point(params().commit_with(value, opening))
    }

    /// Homomorphic addition.
    pub fn add(&self, amount: &Self) -> Self {
        Self::from_point((self.point.into_group() + amount.point.into_group()).into_affine())
    }

    /// Homomorphic subtraction.
    pub fn sub(&self, amount: &Self) -> Self {
        Self::from_point((self.point.into_group() - amount.point.into_group()).into_affine())
    }

    /// The underlying group element (for proof-claim construction).
    const fn point(&self) -> G1 {
        self.point
    }
}

impl Default for BalanceCommitment {
    fn default() -> Self {
        Self::zero()
    }
}

impl PartialEq for BalanceCommitment {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for BalanceCommitment {}

impl PartialOrd for BalanceCommitment {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BalanceCommitment {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.bytes.cmp(&other.bytes)
    }
}

impl core::hash::Hash for BalanceCommitment {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.bytes.hash(state);
    }
}

impl FixedSize for BalanceCommitment {
    const SIZE: usize = G1_UNCOMPRESSED_BYTES;
}

impl Write for BalanceCommitment {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(&g1_to_uncompressed(&self.point));
    }
}

impl Read for BalanceCommitment {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        let bytes = read_array::<G1_UNCOMPRESSED_BYTES>(buf)?;
        let point = g1_from_uncompressed(&bytes).ok_or(CodecError::Invalid(
            "BalanceCommitment",
            "invalid G1 point encoding",
        ))?;
        Ok(Self::from_point(point))
    }
}

impl core::fmt::Display for BalanceCommitment {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex(&self.bytes))
    }
}

#[cfg(any(feature = "arbitrary", test))]
impl arbitrary::Arbitrary<'_> for BalanceCommitment {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self::commit(u.arbitrary()?))
    }
}

// ---------------------------------------------------------------------------
// Range-proof wire bytes
// ---------------------------------------------------------------------------

/// A single range proof in its wire form: `(T, U)` uncompressed plus the
/// scalar `v_a`. Stored as raw bytes so the chain-facing proof types stay
/// `Copy`, `Hash`, `Arbitrary`, and codec-trivial; group elements are decoded
/// and validated only at verification time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(any(feature = "arbitrary", test), derive(arbitrary::Arbitrary))]
struct RangeProofBytes {
    t_g: [u8; G1_UNCOMPRESSED_BYTES],
    u_g: [u8; G1_UNCOMPRESSED_BYTES],
    v_a: [u8; FR_BYTES],
}

impl RangeProofBytes {
    const SIZE: usize = RANGE_PROOF_BYTES;

    fn from_proof(proof: &RangeProof<E>) -> Self {
        let mut v_a = [0u8; FR_BYTES];
        proof
            .v_a
            .serialize_compressed(&mut v_a[..])
            .expect("Fr fits its encoding");
        Self {
            t_g: g1_to_uncompressed(&proof.t_g),
            u_g: g1_to_uncompressed(&proof.u_g),
            v_a,
        }
    }

    /// Decodes and validates the proof's group elements, returning a
    /// verification claim bound to `commitment`. `None` on bad encoding.
    fn to_claim(self, commitment: G1) -> Option<(Proof<E>, Vec<Fr>)> {
        let range = RangeProof::<E> {
            t_g: g1_from_uncompressed(&self.t_g)?,
            u_g: g1_from_uncompressed(&self.u_g)?,
            v_a: Fr::deserialize_compressed(&self.v_a[..]).ok()?,
        };
        Some(range.to_claim(commitment))
    }

    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(&self.t_g);
        buf.put_slice(&self.u_g);
        buf.put_slice(&self.v_a);
    }

    fn read(buf: &mut impl Buf) -> Result<Self, CodecError> {
        Ok(Self {
            t_g: read_array::<G1_UNCOMPRESSED_BYTES>(buf)?,
            u_g: read_array::<G1_UNCOMPRESSED_BYTES>(buf)?,
            v_a: read_array::<FR_BYTES>(buf)?,
        })
    }
}

/// Proves `commitment = commit_with(value, opening)` opens to a 64-bit value.
fn prove_range(
    value: u64,
    opening: &CommittedInputOpening<Fr>,
    rng: &mut impl RngCore,
) -> RangeProofBytes {
    RangeProofBytes::from_proof(&RangeProof::prove(params(), value, opening, rng))
}

/// Forges a range proof for `commitment` from the setup trapdoor (HVZK
/// simulation). Attests no range validity; load generation only.
fn simulate_range(commitment: &BalanceCommitment, rng: &mut impl RngCore) -> RangeProofBytes {
    RangeProofBytes::from_proof(&RangeProof::simulate(params(), commitment.point(), rng))
}

// ---------------------------------------------------------------------------
// Transfer / burn proofs
// ---------------------------------------------------------------------------

/// Proof attached to a private transfer: two single-value range proofs (the
/// transferred amount and the sender's remaining balance).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(any(feature = "arbitrary", test), derive(arbitrary::Arbitrary))]
pub struct TransferProof {
    amount: RangeProofBytes,
    remaining: RangeProofBytes,
}

impl TransferProof {
    /// Verifies the transfer proof against the sender's declared input
    /// commitment and the published amount commitment.
    pub fn verify_transfer(&self, input: &BalanceCommitment, amount: &BalanceCommitment) -> bool {
        verify_proofs_batch(&[ProofClaim::Transfer {
            input: *input,
            amount: *amount,
            proof: *self,
        }])
    }
}

impl FixedSize for TransferProof {
    const SIZE: usize = 2 * RangeProofBytes::SIZE;
}

impl Write for TransferProof {
    fn write(&self, buf: &mut impl BufMut) {
        self.amount.write(buf);
        self.remaining.write(buf);
    }
}

impl Read for TransferProof {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            amount: RangeProofBytes::read(buf)?,
            remaining: RangeProofBytes::read(buf)?,
        })
    }
}

/// Proof attached to a burn: one range proof for the sender's remaining
/// private balance (the amount is the public `commit(value)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(any(feature = "arbitrary", test), derive(arbitrary::Arbitrary))]
pub struct BurnProof {
    remaining: RangeProofBytes,
}

impl BurnProof {
    /// Verifies the burn proof against the sender's declared input commitment
    /// and the public burned value.
    pub fn verify_burn(&self, input: &BalanceCommitment, value: u64) -> bool {
        verify_proofs_batch(&[ProofClaim::Burn {
            input: *input,
            value,
            proof: *self,
        }])
    }
}

impl FixedSize for BurnProof {
    const SIZE: usize = RangeProofBytes::SIZE;
}

impl Write for BurnProof {
    fn write(&self, buf: &mut impl BufMut) {
        self.remaining.write(buf);
    }
}

impl Read for BurnProof {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            remaining: RangeProofBytes::read(buf)?,
        })
    }
}

// ---------------------------------------------------------------------------
// Batch verification
// ---------------------------------------------------------------------------

/// A single transaction's proof obligation, paired with the public
/// commitments it must bind to.
///
/// Collect one per private-side transaction in a block and hand them to
/// [`verify_proofs_batch`], which checks every range proof in a single
/// random-linear-combination pairing equation.
// The transfer variant carries two range proofs; boxing to equalize variant
// size would only add allocations to a short-lived, by-value type.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Copy)]
pub enum ProofClaim {
    /// A private transfer: the amount proof binds to `amount`, the remaining
    /// proof to `input - amount`.
    Transfer {
        /// The sender's declared private balance commitment before the
        /// transfer.
        input: BalanceCommitment,
        /// The published amount commitment.
        amount: BalanceCommitment,
        /// The transfer's two range proofs.
        proof: TransferProof,
    },
    /// A burn: the remaining proof binds to `input - commit(value)`.
    Burn {
        /// The sender's declared private balance commitment before the burn.
        input: BalanceCommitment,
        /// The public amount withdrawn.
        value: u64,
        /// The burn's range proof.
        proof: BurnProof,
    },
}

impl ProofClaim {
    /// Decodes this claim's range proof(s) and appends one verification claim
    /// per proof to `out`. Returns `false` on a bad group-element encoding.
    fn collect_into(&self, out: &mut Vec<(Proof<E>, Vec<Fr>)>) -> bool {
        match self {
            Self::Transfer {
                input,
                amount,
                proof,
            } => {
                let remaining_commitment = input.sub(amount).point();
                let Some(amount_claim) = proof.amount.to_claim(amount.point()) else {
                    return false;
                };
                let Some(remaining_claim) = proof.remaining.to_claim(remaining_commitment) else {
                    return false;
                };
                out.push(amount_claim);
                out.push(remaining_claim);
                true
            }
            Self::Burn {
                input,
                value,
                proof,
            } => {
                let amount = BalanceCommitment::commit(*value);
                let remaining_commitment = input.sub(&amount).point();
                let Some(remaining_claim) = proof.remaining.to_claim(remaining_commitment) else {
                    return false;
                };
                out.push(remaining_claim);
                true
            }
        }
    }
}

/// Verifies every proof in `claims` with a single batched pairing check.
///
/// Each transfer contributes two range-proof claims (amount and remaining);
/// each burn contributes one. All are folded into one
/// [`ZkPari::batch_verify`] — a random linear combination that replaces
/// per-proof pairings with a handful of size-`n` MSMs and one final pairing
/// product. Returns `true` iff every proof verifies. An empty slice trivially
/// passes.
///
/// The batched check is all-or-nothing: it does not identify which claim
/// failed. Callers that must isolate a culprit (e.g. a proposer filtering its
/// mempool) should re-check failing batches one claim at a time.
pub fn verify_proofs_batch(claims: &[ProofClaim]) -> bool {
    let mut proofs_and_inputs: Vec<(Proof<E>, Vec<Fr>)> = Vec::with_capacity(claims.len() * 2);
    for claim in claims {
        if !claim.collect_into(&mut proofs_and_inputs) {
            return false;
        }
    }
    if proofs_and_inputs.is_empty() {
        return true;
    }
    // Batch-verification randomness must be unpredictable to proof submitters;
    // each verifier samples its own from OS entropy. A valid batch verifies
    // for any randomness, so this does not affect determinism.
    ZkPari::<E>::batch_verify(&proofs_and_inputs, &params().vk, &mut OsRng)
}

// ---------------------------------------------------------------------------
// Client-side prover
// ---------------------------------------------------------------------------

/// A client's secret view of its private balance: the plaintext value and the
/// Pedersen opening.
///
/// The chain never sees this; it tracks only [`BalanceCommitment`]s. Spending
/// requires both fields — they are to the private balance what a signing key
/// is to the account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateBalance {
    value: u64,
    opening: CommittedInputOpening<Fr>,
}

/// A planned private transfer: the secret data needed to prove it.
///
/// Produced by [`PrivateBalance::plan_transfer`], which advances the balance
/// state immediately so planning can run sequentially while the expensive
/// [`TransferPlan::prove`] calls run in parallel.
#[derive(Debug, Clone)]
pub struct TransferPlan {
    amount: u64,
    remaining: u64,
    delta_opening: CommittedInputOpening<Fr>,
    remaining_opening: CommittedInputOpening<Fr>,
}

impl TransferPlan {
    /// The amount commitment published with the transaction.
    pub fn amount_commitment(&self) -> BalanceCommitment {
        BalanceCommitment::commit_with(self.amount, &self.delta_opening)
    }

    /// The opening of the amount commitment, shared with the recipient out of
    /// band (the paper's eVRF-based randomness recovery derives it from a
    /// shared secret instead).
    pub const fn amount_opening(&self) -> &CommittedInputOpening<Fr> {
        &self.delta_opening
    }

    /// Produces the transfer proof (amount and remaining range proofs).
    pub fn prove(&self, rng: &mut impl RngCore) -> TransferProof {
        TransferProof {
            amount: prove_range(self.amount, &self.delta_opening, rng),
            remaining: prove_range(self.remaining, &self.remaining_opening, rng),
        }
    }

    /// Produces a simulated transfer proof, binding to the same commitments as
    /// [`Self::prove`] but forged from the setup trapdoor via the HVZK
    /// simulator instead of a witness. For load generation only.
    pub fn simulate(&self, rng: &mut impl RngCore) -> TransferProof {
        // The remaining commitment `commit_with(remaining, remaining_opening)`
        // equals what the verifier reconstructs as `input - amount` (the
        // openings are pinned so the homomorphism holds).
        let remaining_com = BalanceCommitment::commit_with(self.remaining, &self.remaining_opening);
        TransferProof {
            amount: simulate_range(&self.amount_commitment(), rng),
            remaining: simulate_range(&remaining_com, rng),
        }
    }
}

impl PrivateBalance {
    /// An empty private balance (zero value, zero opening), matching the
    /// chain's default [`BalanceCommitment::zero`] account state.
    pub fn empty() -> Self {
        Self {
            value: 0,
            opening: CommittedInputOpening::zero(),
        }
    }

    /// The plaintext balance.
    pub const fn value(&self) -> u64 {
        self.value
    }

    /// The on-chain commitment this state opens.
    pub fn commitment(&self) -> BalanceCommitment {
        BalanceCommitment::commit_with(self.value, &self.opening)
    }

    /// Mirrors an on-chain fund: the public amount is added with zero
    /// blinding, so the opening is unchanged.
    pub const fn fund(&mut self, value: u64) {
        self.value = self
            .value
            .checked_add(value)
            .expect("funded private balance must not overflow");
    }

    /// Plans a private transfer of `amount`, advancing this balance to the
    /// post-transfer state. Returns `None` if `amount` exceeds the balance
    /// (the remaining-balance range proof would be unsatisfiable).
    pub fn plan_transfer(&mut self, amount: u64, rng: &mut impl RngCore) -> Option<TransferPlan> {
        let remaining = self.value.checked_sub(amount)?;
        let delta_opening = CommittedInputOpening::rand(rng);
        let remaining_opening = &self.opening - &delta_opening;

        let plan = TransferPlan {
            amount,
            remaining,
            delta_opening,
            remaining_opening: remaining_opening.clone(),
        };
        self.value = remaining;
        self.opening = remaining_opening;
        Some(plan)
    }

    /// Plans and proves a private transfer in one step.
    pub fn transfer(
        &mut self,
        amount: u64,
        rng: &mut impl RngCore,
    ) -> Option<(BalanceCommitment, TransferProof)> {
        let plan = self.plan_transfer(amount, rng)?;
        Some((plan.amount_commitment(), plan.prove(rng)))
    }

    /// Like [`Self::transfer`], but forges the proof from the setup trapdoor
    /// via the HVZK simulator instead of proving a witness. For load
    /// generation only.
    pub fn simulate_transfer(
        &mut self,
        amount: u64,
        rng: &mut impl RngCore,
    ) -> Option<(BalanceCommitment, TransferProof)> {
        let plan = self.plan_transfer(amount, rng)?;
        Some((plan.amount_commitment(), plan.simulate(rng)))
    }

    /// Burns `value` back to the public balance, proving the remaining private
    /// balance is non-negative. A burn is a transfer to a public sink: the
    /// "amount" is the public `commit(value)` (zero opening), so the opening
    /// of the remaining balance is unchanged.
    pub fn burn(&mut self, value: u64, rng: &mut impl RngCore) -> Option<BurnProof> {
        let remaining = self.value.checked_sub(value)?;
        let proof = BurnProof {
            remaining: prove_range(remaining, &self.opening, rng),
        };
        self.value = remaining;
        Some(proof)
    }

    /// Like [`Self::burn`], but forges the proof from the setup trapdoor via
    /// the HVZK simulator instead of proving a witness. For load generation
    /// only.
    pub fn simulate_burn(&mut self, value: u64, rng: &mut impl RngCore) -> Option<BurnProof> {
        let remaining = self.value.checked_sub(value)?;
        let input = self.commitment();
        let amount_com = BalanceCommitment::commit(value);
        let remaining_com = input.sub(&amount_com);
        let proof = BurnProof {
            remaining: simulate_range(&remaining_com, rng),
        };
        self.value = remaining;
        Some(proof)
    }

    /// Mirrors an incoming payment: the recipient learns `(amount, opening)`
    /// out of band and folds them into its view of the `pending` commitment.
    pub fn receive(&mut self, amount: u64, opening: &CommittedInputOpening<Fr>) {
        self.value = self
            .value
            .checked_add(amount)
            .expect("received private balance must not overflow");
        self.opening = &self.opening + opening;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};
    use commonware_utils::test_rng;

    #[test]
    fn encoded_sizes_match_bn254() {
        assert_eq!(BalanceCommitment::SIZE, 64);
        assert_eq!(TransferProof::SIZE, 320);
        assert_eq!(BurnProof::SIZE, 160);
    }

    #[test]
    fn commitment_codec_roundtrip() {
        let commitment = BalanceCommitment::commit(42);
        let encoded = commitment.encode();
        assert_eq!(encoded.len(), BalanceCommitment::SIZE);
        let decoded = BalanceCommitment::decode(&mut &encoded[..]).expect("decode");
        assert_eq!(decoded, commitment);
    }

    #[test]
    fn zero_commitment_is_identity_and_neutral() {
        let zero = BalanceCommitment::zero();
        assert_eq!(zero, BalanceCommitment::default());

        let commitment = BalanceCommitment::commit(7);
        assert_eq!(zero.add(&commitment), commitment);
        assert_eq!(commitment.sub(&zero), commitment);
        assert_eq!(commitment.sub(&commitment), zero);
    }

    #[test]
    fn commitments_are_homomorphic() {
        let a = BalanceCommitment::commit(30);
        let b = BalanceCommitment::commit(12);
        assert_eq!(a.add(&b), BalanceCommitment::commit(42));
        assert_eq!(BalanceCommitment::commit(42).sub(&b), a);
    }

    #[test]
    fn invalid_commitment_bytes_are_rejected() {
        let bytes = [0xFFu8; BalanceCommitment::SIZE];
        assert!(BalanceCommitment::decode(&mut &bytes[..]).is_err());
    }

    #[test]
    fn transfer_proof_verifies_and_binds_commitments() {
        let mut rng = test_rng();
        let mut balance = PrivateBalance::empty();
        balance.fund(100);
        let input = balance.commitment();

        let (amount_com, proof) = balance.transfer(30, &mut rng).expect("transfer in range");

        assert!(proof.verify_transfer(&input, &amount_com));
        // Wrong input commitment: remaining-balance binding fails.
        assert!(!proof.verify_transfer(&BalanceCommitment::commit(99), &amount_com));
        // Wrong amount commitment: amount binding fails.
        assert!(!proof.verify_transfer(&input, &BalanceCommitment::commit(30)));

        // The post-transfer state opens the homomorphically derived commitment.
        assert_eq!(balance.commitment(), input.sub(&amount_com));
        assert_eq!(balance.value(), 70);
    }

    #[test]
    fn transfer_exceeding_balance_is_unprovable() {
        let mut rng = test_rng();
        let mut balance = PrivateBalance::empty();
        balance.fund(10);
        assert!(balance.transfer(11, &mut rng).is_none());
        assert_eq!(balance.value(), 10, "failed plan must not mutate state");
    }

    #[test]
    fn burn_proof_verifies() {
        let mut rng = test_rng();
        let mut balance = PrivateBalance::empty();
        balance.fund(50);
        let input = balance.commitment();

        let proof = balance.burn(20, &mut rng).expect("burn in range");
        assert!(proof.verify_burn(&input, 20));
        assert!(!proof.verify_burn(&input, 21));
        assert_eq!(
            balance.commitment(),
            input.sub(&BalanceCommitment::commit(20))
        );
    }

    #[test]
    fn recipient_recovers_pending_with_shared_opening() {
        let mut rng = test_rng();
        let mut sender = PrivateBalance::empty();
        sender.fund(100);

        let mut plan_input = sender.clone();
        let plan = plan_input.plan_transfer(25, &mut rng).expect("in range");
        let amount_com = plan.amount_commitment();

        let mut pending = PrivateBalance::empty();
        pending.receive(25, plan.amount_opening());
        assert_eq!(
            pending.commitment(),
            BalanceCommitment::zero().add(&amount_com)
        );
    }

    #[test]
    fn proof_codec_roundtrip() {
        let mut rng = test_rng();
        let mut balance = PrivateBalance::empty();
        balance.fund(100);
        let input = balance.commitment();
        let (amount_com, proof) = balance.transfer(1, &mut rng).expect("transfer in range");

        let encoded = proof.encode();
        assert_eq!(encoded.len(), TransferProof::SIZE);
        let decoded = TransferProof::decode(&mut &encoded[..]).expect("decode");
        assert_eq!(decoded, proof);
        assert!(decoded.verify_transfer(&input, &amount_com));

        let burn = balance.burn(1, &mut rng).expect("burn in range");
        let encoded = burn.encode();
        assert_eq!(encoded.len(), BurnProof::SIZE);
        assert_eq!(BurnProof::decode(&mut &encoded[..]).expect("decode"), burn);
    }

    #[test]
    fn simulated_transfer_and_burn_verify() {
        let mut rng = test_rng();
        let mut balance = PrivateBalance::empty();
        balance.fund(100);
        let input = balance.commitment();

        let (amount_com, proof) = balance
            .simulate_transfer(30, &mut rng)
            .expect("transfer in range");
        assert!(
            proof.verify_transfer(&input, &amount_com),
            "simulated transfer proof must verify on-chain"
        );
        assert!(!proof.verify_transfer(&input, &BalanceCommitment::commit(30)));
        assert_eq!(balance.commitment(), input.sub(&amount_com));

        let burn_input = balance.commitment();
        let burn = balance.simulate_burn(10, &mut rng).expect("burn in range");
        assert!(burn.verify_burn(&burn_input, 10));
        assert!(!burn.verify_burn(&burn_input, 11));
    }

    /// The batched check must bind every claim to its declared commitments:
    /// tampering with any claim's amount, value, or input — or swapping inputs
    /// between claims — must reject the whole batch.
    #[test]
    fn batch_verification_binds_claims_to_commitments() {
        let mut rng = test_rng();

        let mut claims = Vec::new();
        for value in [10u64, 20, 30] {
            let mut balance = PrivateBalance::empty();
            balance.fund(value * 2);
            let input = balance.commitment();
            let (amount, proof) = balance.transfer(value, &mut rng).expect("in range");
            claims.push(ProofClaim::Transfer {
                input,
                amount,
                proof,
            });
        }
        let mut balance = PrivateBalance::empty();
        balance.fund(40);
        let burn_input = balance.commitment();
        let burn = balance.burn(15, &mut rng).expect("in range");
        claims.push(ProofClaim::Burn {
            input: burn_input,
            value: 15,
            proof: burn,
        });

        assert!(verify_proofs_batch(&claims));
        assert!(verify_proofs_batch(&claims[..1]));

        for index in 0..claims.len() {
            let mut tampered = claims.clone();
            match &mut tampered[index] {
                ProofClaim::Transfer { amount, .. } => {
                    *amount = amount.add(&BalanceCommitment::commit(1));
                }
                ProofClaim::Burn { value, .. } => *value += 1,
            }
            assert!(!verify_proofs_batch(&tampered), "tampered claim {index}");
        }

        let mut swapped = claims.clone();
        let (first_input, second_input) = match (&claims[0], &claims[1]) {
            (
                ProofClaim::Transfer { input: first, .. },
                ProofClaim::Transfer { input: second, .. },
            ) => (*first, *second),
            _ => unreachable!("first two claims are transfers"),
        };
        if let ProofClaim::Transfer { input, .. } = &mut swapped[0] {
            *input = second_input;
        }
        if let ProofClaim::Transfer { input, .. } = &mut swapped[1] {
            *input = first_input;
        }
        assert!(!verify_proofs_batch(&swapped), "swapped inputs");
    }
}
