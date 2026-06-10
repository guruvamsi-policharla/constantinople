//! Cryptographic components for private (Zether-style) transfers, backed by
//! ZK-Pari.
//!
//! Private balances are Pedersen commitments over BLS12-381 G1, in the payment
//! basis `(G_pay, G~_pay) = (Sigma_ci_2[0], Gamma_ci_2)` fixed by the ZK-Pari
//! CRS. A private transfer is the batched one-to-many construction with a
//! single recipient (`B = 1`): it publishes the amount commitment and **one**
//! ZK-Pari proof of `3 G1 + 1 F` that range-checks *both* the transferred
//! amount and the sender's remaining balance at once — replacing the two
//! separate range proofs of the naive construction. Concretely:
//!
//! - Block 1 commits the claimed values `[amount, remaining]`; its commitment
//!   `C_ci_1` is transmitted with the proof.
//! - Block 2 commits the aggregate `v_theta = amount + theta * remaining`. Its
//!   commitment `com_theta = com_amount + theta * com_remaining` is recomputed
//!   by the verifier from the ledger commitments and is never transmitted.
//! - `theta` is a Fiat-Shamir challenge bound to `(com_sender, com_amount,
//!   C_ci_1)` and enters the circuit as a public input; the circuit enforces
//!   the Horner aggregation, so by Schwartz-Zippel the range-checked claimed
//!   values equal the values inside the ledger commitments.
//!
//! Verification therefore checks, with no secret knowledge: the single proof
//! verifies (both values are in `[0, 2^64)`), `C_ci_1` matches the transmitted
//! commitment, and balance conservation holds because `com_remaining =
//! com_sender - com_amount` is *derived* by the verifier.
//!
//! Funds and burns move value between the public `u64` balance and the private
//! commitment with a public amount. Funding adds `commit(v)` (zero opening,
//! publicly computable) and needs no proof. A burn is structurally a transfer
//! to a public sink: its "amount" is the public `commit(value)`, so it reuses
//! the same batched proof to range-check the remaining balance.
//!
//! Incoming payments accumulate in a separate `pending` commitment so an
//! in-flight outgoing chain can never be invalidated by a deposit (the Zether
//! griefing attack); the real protocol adds an epoch rollover folding
//! `pending` into the spendable balance, which this example chain omits.
//!
//! # Trusted setup
//!
//! The CRS is generated deterministically from a fixed seed at first use
//! ([`proving_key`]). This stands in for a real multi-party trusted setup and
//! is **demo-grade only**: anyone can recompute the toxic waste. Swap
//! [`crs`] for externally distributed keys to productionize.

use ark_bls12_381::Bls12_381;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM, pairing::Pairing};
use ark_ff::Field;
use ark_relations::{
    gr1cs::{
        ConstraintSystemRef, R1CS_PREDICATE_LABEL, SynthesisError, Variable,
        predicate::{PredicateConstraintSystem, polynomial_constraint::SR1CS_PREDICATE_LABEL},
    },
    lc,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bytes::{Buf, BufMut};
use commonware_codec::{Error as CodecError, FixedSize, Read, Write};
use commonware_formatting::hex;
use rand::{SeedableRng, rngs::StdRng};
use rand_core::{OsRng, RngCore};
use std::sync::OnceLock;
use zkpari::{
    CommittedInputOpening, Proof, ProvingKey, Trapdoor, VerifyingKey, ZkPari, ZkPariCircuit,
    utils::transcript::IOPTranscript,
};

type E = Bls12_381;
type Fr = <E as Pairing>::ScalarField;
type G1 = <E as Pairing>::G1Affine;

const G1_BYTES: usize = 48;
const FR_BYTES: usize = 32;

/// One recipient per private transfer: the batched circuit's `B`.
const BATCH_SIZE: usize = 1;

/// CRS block index of the payment basis that ledger commitments live in
/// (block 2 of the batched circuit: `[claimed values]`, then `[aggregate]`).
const LEDGER_BLOCK: usize = 1;

/// Fiat-Shamir domain for the transfer-aggregation challenge `theta`.
const THETA_DOMAIN: &[u8] = b"constantinople-private-transfer-theta";

/// Seed for the deterministic demo CRS. See the module docs: demo-grade only.
const CRS_SEED: u64 = 0xC0457A47_71400713;

// ---------------------------------------------------------------------------
// Batched range circuit (native SR1CS), from the zkpari
// `batched_private_transfer` example, specialized via `batch_size`. With
// `B = 1` it range-checks the claimed amount and the remaining balance and
// enforces the Horner aggregation `amount + theta * remaining = v_theta`,
// declaring two committed-input blocks:
//   block 1: [amount, remaining]      -> C_ci_1 (transmitted)
//   block 2: [v_theta]                -> com_theta (verifier-recomputed)
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct BatchedRangeCircuit<F: Field> {
    theta: Option<F>,
    amounts: Option<Vec<u64>>,
    remaining: Option<u64>,
    batch_size: usize,
}

impl<F: Field> ZkPariCircuit<F> for BatchedRangeCircuit<F> {
    fn synthesize(self, cs: ConstraintSystemRef<F>) -> Result<Vec<Vec<Variable>>, SynthesisError> {
        cs.remove_predicate(R1CS_PREDICATE_LABEL);
        let _ = cs.register_predicate(
            SR1CS_PREDICATE_LABEL,
            PredicateConstraintSystem::new_sr1cs_predicate()
                .map_err(|_| SynthesisError::Unsatisfiable)?,
        );

        let b = self.batch_size;
        let theta = self.theta;

        // Committed values: the B claimed amounts followed by the remaining balance.
        let raw_values: Option<Vec<u64>> = match (self.amounts.as_ref(), self.remaining) {
            (Some(amounts), Some(remaining)) => {
                assert_eq!(amounts.len(), b);
                Some(amounts.iter().copied().chain([remaining]).collect())
            }
            _ => None,
        };
        let values: Option<Vec<F>> = raw_values
            .as_ref()
            .map(|raw| raw.iter().map(|v| F::from(*v)).collect());

        // Block 1 (committed inputs, allocated first): v^_1, ..., v^_B, v^_rem.
        let mut value_vars = Vec::with_capacity(b + 1);
        for i in 0..=b {
            let vals = values.clone();
            let v = cs.new_witness_variable(move || {
                vals.ok_or(SynthesisError::AssignmentMissing).map(|v| v[i])
            })?;
            value_vars.push(v);
        }

        // Block 2 (single committed input): v_theta = sum_i theta^i * values[i].
        let v_theta_value: Option<F> = match (values.as_ref(), theta) {
            (Some(vals), Some(th)) => {
                let mut acc = vals[b];
                for v in vals[..b].iter().rev() {
                    acc = acc * th + v;
                }
                Some(acc)
            }
            _ => None,
        };
        let v_theta_var =
            cs.new_witness_variable(|| v_theta_value.ok_or(SynthesisError::AssignmentMissing))?;

        // theta is an ordinary public input (chosen after the ledger
        // commitments and the block-1 commitment are fixed).
        let theta_var = cs.new_input_variable(|| theta.ok_or(SynthesisError::AssignmentMissing))?;

        // 64-bit range check for every committed value.
        for (i, &v) in value_vars.iter().enumerate() {
            let mut bit_vars = Vec::with_capacity(64);
            for bit in 0..64u32 {
                let raw = raw_values.clone();
                let bv = cs.new_witness_variable(move || {
                    let raw = raw.ok_or(SynthesisError::AssignmentMissing)?;
                    Ok(if (raw[i] >> bit) & 1 == 1 {
                        F::ONE
                    } else {
                        F::ZERO
                    })
                })?;
                bit_vars.push(bv);
            }
            let mut recon_minus_v = lc!() - v;
            let mut coeff = F::ONE;
            for &bv in &bit_vars {
                recon_minus_v += (coeff, bv);
                coeff.double_in_place();
            }
            let zero_lc = lc!() + v - v;
            cs.enforce_sr1cs_constraint(|| recon_minus_v, || zero_lc)?;
            for &bv in &bit_vars {
                cs.enforce_sr1cs_constraint(|| lc!() + bv, || lc!() + bv)?;
            }
        }

        // Horner aggregation: acc = v^_rem; acc = acc * theta + v^_i for i = B..1,
        // with each product realized as (a+t)^2, (a-t)^2 so a*t = (s_plus - s_minus)/4.
        let quarter = F::from(4u64).inverse().unwrap();
        let mut acc_lc = lc!() + value_vars[b];
        let mut acc_val: Option<F> = values.as_ref().map(|vals| vals[b]);
        for i in (0..b).rev() {
            let (av, th) = (acc_val, theta);
            let s_plus = cs.new_witness_variable(move || {
                let a = av.ok_or(SynthesisError::AssignmentMissing)?;
                let t = th.ok_or(SynthesisError::AssignmentMissing)?;
                Ok((a + t).square())
            })?;
            let s_minus = cs.new_witness_variable(move || {
                let a = av.ok_or(SynthesisError::AssignmentMissing)?;
                let t = th.ok_or(SynthesisError::AssignmentMissing)?;
                Ok((a - t).square())
            })?;
            let lhs_plus = acc_lc.clone() + theta_var;
            let lhs_minus = acc_lc.clone() - theta_var;
            cs.enforce_sr1cs_constraint(|| lhs_plus, || lc!() + s_plus)?;
            cs.enforce_sr1cs_constraint(|| lhs_minus, || lc!() + s_minus)?;
            acc_lc = lc!() + (quarter, s_plus) + (-quarter, s_minus) + value_vars[i];
            acc_val = match (acc_val, theta, values.as_ref()) {
                (Some(a), Some(t), Some(vals)) => Some(a * t + vals[i]),
                _ => None,
            };
        }

        // (acc - v_theta)^2 = 0.
        let final_lhs = acc_lc - v_theta_var;
        let zero_lc = lc!() + value_vars[0] - value_vars[0];
        cs.enforce_sr1cs_constraint(|| final_lhs, || zero_lc)?;

        Ok(vec![value_vars, vec![v_theta_var]])
    }
}

const fn setup_circuit() -> BatchedRangeCircuit<Fr> {
    BatchedRangeCircuit {
        theta: None,
        amounts: None,
        remaining: None,
        batch_size: BATCH_SIZE,
    }
}

/// Returns the process-wide CRS, generating it deterministically on first use.
///
/// The [`Trapdoor`] is retained alongside the keys. In a real deployment this
/// is toxic waste that must be destroyed; here the CRS is demo-grade (see the
/// module docs) and the trapdoor powers the fast simulated-proof path
/// ([`PrivateBalance::simulate_transfer`]) used by load generators.
fn crs() -> &'static (ProvingKey<E>, VerifyingKey<E>, Trapdoor<E>) {
    static CRS: OnceLock<(ProvingKey<E>, VerifyingKey<E>, Trapdoor<E>)> = OnceLock::new();
    CRS.get_or_init(|| {
        let mut rng = StdRng::seed_from_u64(CRS_SEED);
        ZkPari::<E>::keygen_with_trapdoor(setup_circuit(), &mut rng)
    })
}

/// Returns the ZK-Pari proving key shared by clients and validators.
///
/// Exposed so external tooling can commit and prove against the same CRS.
pub fn proving_key() -> &'static ProvingKey<E> {
    &crs().0
}

fn g1_to_bytes(point: &G1) -> [u8; G1_BYTES] {
    let mut bytes = [0u8; G1_BYTES];
    point
        .serialize_compressed(&mut bytes[..])
        .expect("compressed G1 fits 48 bytes");
    bytes
}

fn g1_from_bytes(bytes: &[u8]) -> Option<G1> {
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

/// A Pedersen commitment to a private balance (a BLS12-381 G1 point).
///
/// The chain stores and homomorphically updates these: a private transfer
/// subtracts the amount commitment from the sender's balance commitment and
/// adds it to the recipient's pending commitment. The identity point commits
/// to zero with zero blinding.
#[derive(Debug, Clone, Copy)]
pub struct BalanceCommitment {
    point: G1,
    bytes: [u8; G1_BYTES],
}

impl BalanceCommitment {
    /// The commitment to a zero balance (the identity point).
    pub fn zero() -> Self {
        Self::from_point(G1::identity())
    }

    fn from_point(point: G1) -> Self {
        Self {
            point,
            bytes: g1_to_bytes(&point),
        }
    }

    /// Creates a commitment from canonical compressed bytes, validating the
    /// point.
    pub fn from_bytes(bytes: &[u8; G1_BYTES]) -> Option<Self> {
        Some(Self {
            point: g1_from_bytes(bytes)?,
            bytes: *bytes,
        })
    }

    /// Returns the canonical compressed encoding.
    pub const fn as_bytes(&self) -> &[u8; G1_BYTES] {
        &self.bytes
    }

    /// Commitment to a public amount with zero blinding: `value * G_pay`.
    ///
    /// Publicly computable, which is what makes fund and burn amounts
    /// verifiable without a proof of opening.
    pub fn commit(value: u64) -> Self {
        Self::commit_with(value, &CommittedInputOpening::zero())
    }

    /// Commitment to `value` with blinding `opening`, in the payment basis.
    pub fn commit_with(value: u64, opening: &CommittedInputOpening<Fr>) -> Self {
        Self::from_point(proving_key().pedersen_commit(LEDGER_BLOCK, &[Fr::from(value)], opening))
    }

    /// Homomorphic addition.
    pub fn add(&self, amount: &Self) -> Self {
        Self::from_point((self.point.into_group() + amount.point.into_group()).into_affine())
    }

    /// Homomorphic subtraction.
    pub fn sub(&self, amount: &Self) -> Self {
        Self::from_point((self.point.into_group() - amount.point.into_group()).into_affine())
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
    const SIZE: usize = G1_BYTES;
}

impl Write for BalanceCommitment {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(&self.bytes);
    }
}

impl Read for BalanceCommitment {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        let bytes = read_array::<G1_BYTES>(buf)?;
        Self::from_bytes(&bytes).ok_or(CodecError::Invalid(
            "BalanceCommitment",
            "invalid G1 point encoding",
        ))
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
// Batched transfer proofs
// ---------------------------------------------------------------------------

/// The Fiat-Shamir aggregation challenge `theta`, bound to everything fixed
/// before it is drawn: the sender's balance commitment, the amount
/// commitment, and the block-1 commitment to the claimed values.
///
/// Prover and verifier derive it identically, so neither transmits it.
fn derive_theta(input: &BalanceCommitment, amount: &BalanceCommitment, c_ci_1: &G1) -> Fr {
    let mut transcript = IOPTranscript::<Fr>::new(THETA_DOMAIN);
    let _ = transcript.append_serializable_element(b"com_sender", &input.point);
    let _ = transcript.append_serializable_element(b"com_amount", &amount.point);
    let _ = transcript.append_serializable_element(b"c_ci_1", c_ci_1);
    transcript
        .get_and_append_challenge(b"theta")
        .expect("transcript challenge")
}

/// The aggregate commitment the verifier recomputes:
/// `com_theta = com_amount + theta * com_remaining`, with
/// `com_remaining = input - amount`.
fn aggregate_commitment(input: &BalanceCommitment, amount: &BalanceCommitment, theta: Fr) -> G1 {
    let com_remaining = input.sub(amount);
    <E as Pairing>::G1::msm_unchecked(&[amount.point, com_remaining.point], &[Fr::ONE, theta])
        .into_affine()
}

/// One batched ZK-Pari proof: `C_ci_1` plus `(T, U, v_a)` = `3 G1 + 1 F`
/// (176 bytes). `com_theta` (block 2) is recomputed by the verifier and never
/// transmitted.
///
/// Range-checks both the transferred amount and the sender's remaining balance
/// in a single proof; see the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(any(feature = "arbitrary", test), derive(arbitrary::Arbitrary))]
struct BatchedProof {
    c_ci_1: [u8; G1_BYTES],
    t_g: [u8; G1_BYTES],
    u_g: [u8; G1_BYTES],
    v_a: [u8; FR_BYTES],
}

impl BatchedProof {
    const SIZE: usize = G1_BYTES + G1_BYTES + G1_BYTES + FR_BYTES;

    fn from_proof(proof: &Proof<E>) -> Self {
        let mut v_a = [0u8; FR_BYTES];
        proof
            .v_a
            .serialize_compressed(&mut v_a[..])
            .expect("Fr fits 32 bytes");
        Self {
            c_ci_1: g1_to_bytes(&proof.c_ci[0]),
            t_g: g1_to_bytes(&proof.t_g),
            u_g: g1_to_bytes(&proof.u_g),
            v_a,
        }
    }

    /// Honestly proves a one-recipient batched transfer.
    ///
    /// `amount_com` is the published amount commitment (opening `r_amount`);
    /// `remaining`/`r_rem` describe the sender's balance afterwards.
    fn prove(
        input: &BalanceCommitment,
        amount: u64,
        amount_com: &BalanceCommitment,
        r_amount: &CommittedInputOpening<Fr>,
        remaining: u64,
        r_rem: &CommittedInputOpening<Fr>,
        rng: &mut impl RngCore,
    ) -> Self {
        let rho_1 = CommittedInputOpening::<Fr>::rand(rng);
        let c_ci_1 = proving_key().pedersen_commit(0, &claimed_values(amount, remaining), &rho_1);
        let theta = derive_theta(input, amount_com, &c_ci_1);
        let rho_2 = CommittedInputOpening {
            rho: r_amount.rho + theta * r_rem.rho,
        };
        let proof = ZkPari::<E>::prove_with_openings(
            BatchedRangeCircuit {
                theta: Some(theta),
                amounts: Some(vec![amount]),
                remaining: Some(remaining),
                batch_size: BATCH_SIZE,
            },
            proving_key(),
            &[rho_1, rho_2],
            rng,
        )
        .expect("batched range proof synthesis cannot fail for in-range values");
        Self::from_proof(&proof)
    }

    /// Forges an accepting batched transcript via the HVZK simulator, using the
    /// setup trapdoor instead of a witness.
    ///
    /// This is **not** a proof of range validity: it exists for load
    /// generation, where honestly proving every transfer (circuit synthesis +
    /// MSMs) would dwarf the cost being measured. The block-1 commitment is
    /// formed honestly (one cheap Pedersen commit) so the transcript is
    /// distributed like a real one; only the expensive proof body is forged.
    /// Relies on the demo CRS trapdoor and must never gate real value.
    fn simulate(
        input: &BalanceCommitment,
        amount: u64,
        amount_com: &BalanceCommitment,
        remaining: u64,
        rng: &mut impl RngCore,
    ) -> Self {
        let rho_1 = CommittedInputOpening::<Fr>::rand(rng);
        let c_ci_1 = proving_key().pedersen_commit(0, &claimed_values(amount, remaining), &rho_1);
        let theta = derive_theta(input, amount_com, &c_ci_1);
        let com_theta = aggregate_commitment(input, amount_com, theta);
        let proof = ZkPari::<E>::simulate(&crs().2, &crs().1, &[c_ci_1, com_theta], &[theta], rng);
        Self::from_proof(&proof)
    }

    /// Reconstructs the full ZK-Pari proof and its public input `[theta]` from
    /// the transmitted material plus the declared commitments. Returns `None`
    /// if a group element fails to decode.
    fn to_verification(
        self,
        input: &BalanceCommitment,
        amount: &BalanceCommitment,
    ) -> Option<(Proof<E>, Vec<Fr>)> {
        let c_ci_1 = g1_from_bytes(&self.c_ci_1)?;
        let t_g = g1_from_bytes(&self.t_g)?;
        let u_g = g1_from_bytes(&self.u_g)?;
        let v_a = Fr::deserialize_compressed(&self.v_a[..]).ok()?;
        let theta = derive_theta(input, amount, &c_ci_1);
        let com_theta = aggregate_commitment(input, amount, theta);
        Some((
            Proof::<E> {
                c_ci: vec![c_ci_1, com_theta],
                t_g,
                u_g,
                v_a,
            },
            vec![theta],
        ))
    }

    fn verify(&self, input: &BalanceCommitment, amount: &BalanceCommitment) -> bool {
        self.to_verification(input, amount)
            .is_some_and(|(proof, public_input)| {
                ZkPari::<E>::verify(&proof, &crs().1, &public_input)
            })
    }
}

impl Write for BatchedProof {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(&self.c_ci_1);
        buf.put_slice(&self.t_g);
        buf.put_slice(&self.u_g);
        buf.put_slice(&self.v_a);
    }
}

impl Read for BatchedProof {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        // Group elements are validated lazily at verification time, keeping
        // decode cheap; a malformed proof simply fails to verify.
        Ok(Self {
            c_ci_1: read_array::<G1_BYTES>(buf)?,
            t_g: read_array::<G1_BYTES>(buf)?,
            u_g: read_array::<G1_BYTES>(buf)?,
            v_a: read_array::<FR_BYTES>(buf)?,
        })
    }
}

/// The block-1 claimed values `[amount, remaining]` as field elements.
fn claimed_values(amount: u64, remaining: u64) -> [Fr; BATCH_SIZE + 1] {
    [Fr::from(amount), Fr::from(remaining)]
}

/// Proof attached to a private transfer: one batched ZK-Pari proof
/// (`3 G1 + 1 F`, 176 bytes) range-checking the transferred amount and the
/// sender's remaining balance together.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(any(feature = "arbitrary", test), derive(arbitrary::Arbitrary))]
pub struct TransferProof(BatchedProof);

impl TransferProof {
    /// Verifies the transfer proof against the sender's declared input
    /// commitment and the published amount commitment.
    pub fn verify_transfer(&self, input: &BalanceCommitment, amount: &BalanceCommitment) -> bool {
        self.0.verify(input, amount)
    }
}

impl FixedSize for TransferProof {
    const SIZE: usize = BatchedProof::SIZE;
}

impl Write for TransferProof {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl Read for TransferProof {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self(BatchedProof::read_cfg(buf, &())?))
    }
}

/// Proof attached to a burn. A burn is a transfer to a public sink: its
/// "amount" is the publicly recomputable `commit(value)`, so it reuses the
/// same batched proof (176 bytes) to range-check the remaining balance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(any(feature = "arbitrary", test), derive(arbitrary::Arbitrary))]
pub struct BurnProof(BatchedProof);

impl BurnProof {
    /// Verifies the burn proof against `input` and the public withdrawn
    /// `value`, whose commitment `commit(value)` plays the role of the amount.
    pub fn verify_burn(&self, input: &BalanceCommitment, value: u64) -> bool {
        self.0.verify(input, &BalanceCommitment::commit(value))
    }
}

impl FixedSize for BurnProof {
    const SIZE: usize = BatchedProof::SIZE;
}

impl Write for BurnProof {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl Read for BurnProof {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self(BatchedProof::read_cfg(buf, &())?))
    }
}

// ---------------------------------------------------------------------------
// Batch verification
// ---------------------------------------------------------------------------

/// A single proof to verify, paired with the public commitments it must bind
/// to.
///
/// Collect one per private-side transaction in a block and hand them to
/// [`verify_proofs_batch`], which checks them all in a single
/// random-linear-combination pairing equation.
// The transfer variant carries two range proofs; boxing to equalize variant
// size would only add allocations to a short-lived, by-value verification type.
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
        /// The transfer's range proofs.
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
    /// Appends this claim's reconstructed ZK-Pari proof (one batched proof,
    /// with public input `[theta]`) to `out`. Returns `false` if the proof's
    /// group elements fail to decode.
    fn collect_into(&self, out: &mut Vec<(Proof<E>, Vec<Fr>)>) -> bool {
        let verification = match self {
            Self::Transfer {
                input,
                amount,
                proof,
            } => proof.0.to_verification(input, amount),
            Self::Burn {
                input,
                value,
                proof,
            } => proof
                .0
                .to_verification(input, &BalanceCommitment::commit(*value)),
        };
        verification.is_some_and(|verification| {
            out.push(verification);
            true
        })
    }
}

/// Verifies every proof in `claims` with a single batched pairing check.
///
/// Each transfer and burn contributes one batched ZK-Pari proof; all are
/// folded into one `batch_verify` (a random linear combination, replacing
/// per-proof pairings with one 128-bit MSM per proof element). Returns `true`
/// iff every proof verifies. An empty slice trivially passes.
///
/// The batched check is all-or-nothing: it does not identify which claim
/// failed. Callers that must isolate a culprit (e.g. a proposer filtering its
/// mempool) should re-check failing batches one claim at a time.
pub fn verify_proofs_batch(claims: &[ProofClaim]) -> bool {
    let mut proofs_and_inputs: Vec<(Proof<E>, Vec<Fr>)> = Vec::with_capacity(claims.len());
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
    ZkPari::<E>::batch_verify(&proofs_and_inputs, &crs().1, &mut OsRng)
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
    input: BalanceCommitment,
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

    /// Produces the single batched transfer proof.
    pub fn prove(&self, rng: &mut impl RngCore) -> TransferProof {
        TransferProof(BatchedProof::prove(
            &self.input,
            self.amount,
            &self.amount_commitment(),
            &self.delta_opening,
            self.remaining,
            &self.remaining_opening,
            rng,
        ))
    }

    /// Produces a simulated transfer proof, binding to the same commitments as
    /// [`Self::prove`] but forged from the setup trapdoor via the HVZK
    /// simulator instead of a witness. For load generation only.
    pub fn simulate(&self, rng: &mut impl RngCore) -> TransferProof {
        TransferProof(BatchedProof::simulate(
            &self.input,
            self.amount,
            &self.amount_commitment(),
            self.remaining,
            rng,
        ))
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
        let input = self.commitment();
        let delta_opening = CommittedInputOpening::rand(rng);
        let remaining_opening = &self.opening - &delta_opening;

        let plan = TransferPlan {
            input,
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
    /// via the HVZK simulator instead of proving a witness. The published
    /// commitments are identical and real; only the range proof is simulated,
    /// so it attests no range validity. For load generation only.
    pub fn simulate_transfer(
        &mut self,
        amount: u64,
        rng: &mut impl RngCore,
    ) -> Option<(BalanceCommitment, TransferProof)> {
        let plan = self.plan_transfer(amount, rng)?;
        Some((plan.amount_commitment(), plan.simulate(rng)))
    }

    /// Burns `value` back to the public balance, proving the remaining
    /// private balance is non-negative. A burn is a transfer to a public sink:
    /// the "amount" is the public `commit(value)` (zero opening), so the
    /// opening of the remaining balance is unchanged.
    pub fn burn(&mut self, value: u64, rng: &mut impl RngCore) -> Option<BurnProof> {
        let remaining = self.value.checked_sub(value)?;
        let input = self.commitment();
        let amount_com = BalanceCommitment::commit(value);
        let proof = BatchedProof::prove(
            &input,
            value,
            &amount_com,
            &CommittedInputOpening::zero(),
            remaining,
            &self.opening,
            rng,
        );
        self.value = remaining;
        Some(BurnProof(proof))
    }

    /// Like [`Self::burn`], but forges the proof from the setup trapdoor via
    /// the HVZK simulator instead of proving a witness. For load generation
    /// only.
    pub fn simulate_burn(&mut self, value: u64, rng: &mut impl RngCore) -> Option<BurnProof> {
        let remaining = self.value.checked_sub(value)?;
        let input = self.commitment();
        let amount_com = BalanceCommitment::commit(value);
        let proof = BatchedProof::simulate(&input, value, &amount_com, remaining, rng);
        self.value = remaining;
        Some(BurnProof(proof))
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
        // commit(a) + commit(b) == commit(a + b) with zero openings.
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

        // The on-chain pending slot accumulates the amount commitment; the
        // recipient folds in (amount, opening) learned out of band.
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

    #[test]
    fn batched_proof_is_three_g1_plus_one_field() {
        // One batched proof per transfer/burn: 3 G1 + 1 F = 176 bytes,
        // replacing the naive two range proofs (256 bytes) for transfers.
        assert_eq!(TransferProof::SIZE, 3 * G1_BYTES + FR_BYTES);
        assert_eq!(BurnProof::SIZE, 3 * G1_BYTES + FR_BYTES);
        assert_eq!(TransferProof::SIZE, 176);
    }

    #[test]
    fn garbage_proof_fails_verification_without_panicking() {
        let proof = TransferProof(BatchedProof {
            c_ci_1: [3u8; G1_BYTES],
            t_g: [7u8; G1_BYTES],
            u_g: [7u8; G1_BYTES],
            v_a: [9u8; FR_BYTES],
        });
        assert!(
            !proof.verify_transfer(&BalanceCommitment::commit(1), &BalanceCommitment::commit(1))
        );
    }
}
