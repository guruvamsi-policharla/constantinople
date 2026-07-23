# Private payments

Constantinople's private-payment feature hides transfer **amounts** behind
homomorphic commitments with zero-knowledge range proofs, while keeping
senders, recipients, and nonces public. This document is the reviewer's map:
the protocol model, the wire format with real sizes, execution semantics, the
load-generation/deploy tooling, and the measured performance envelope.

## Account model

Every account carries, alongside its public `balance` and `nonce`, a
`PrivateAccount` of two commitments (`crates/primitives/src/privacy.rs`):

- **`pending`** — incoming private value awaiting explicit acceptance.
- **`current`** — spendable private value.

Four operations move value through them (`Payload` variants,
`crates/primitives/src/transaction.rs`):

| op | effect | proof carried |
|---|---|---|
| `PrivateFund` | public balance → own `pending` | none — the funded value is public, the commitment is verified by recomputation (`FundProof = ()`) |
| `PrivateRollover` | `pending` folded into `current` | none — homomorphic addition |
| `PrivateTransfer` | `current` → recipient's `pending` | two 64-bit range proofs: the transferred amount and the sender's remaining balance (conservation) |
| `PrivateBurn` | `current` → public balance (de-shield) | one range proof on the remaining balance |

The split between `pending` and `current` exists so a *recipient's* spendable
commitment never changes underneath an in-flight proof: transfer proofs bind
to the sender's `current`, and only the owner's explicit rollover mutates it.
Consequence: **an account can have exactly one private operation in flight**
— operation N+1's proof is built on N's output state. This constraint shapes
the spammer's design (below).

`PrivateBurn` is fully wired (executor, indexer) and unit-tested, but no
client emits it yet — the spammer's cycle is fund → rollover → transfer.

## Backends and features

The proof system is pluggable via `commonware-privacy` (a path dependency on
the sibling `../monorepo` checkout — see *Known blockers*):

- **mock** (default feature `privacy-backend-mock`): zero-size proofs,
  trivial verification. For tests and pipeline benchmarks.
- **zkpari** (`privacy-backend-zkpari`): Pedersen-style commitments and
  range proofs over BN254. Coexists with the default mock feature and wins
  via `not(...)` guards, so builds never need `default-features = false`.
- **simulator** (`privacy-backend-simulator`): add-on exposing the setup
  trapdoor so load generators can forge valid proofs cheaply while
  validators still verify them for real. Requires a base backend.

Backend selection is workspace-global (cargo feature unification through
`constantinople-primitives`). Two type aliases split wire from storage:
`ChainPrivatePaymentBackend` (uncompressed points, curve-checked at decode)
and `StatePrivatePaymentBackend` (unchecked — state bytes come from the
authenticated local database, already checked at ingress). The free
`to_state_*` functions in `privacy.rs` are the only conversion seam.

## Wire format and sizes (zkpari, as deployed)

Points ride the wire **uncompressed** (64 B G1; chosen to avoid per-point
decompression at verification). A transaction is
`sender_key(34) ‖ payload ‖ nonce(8) ‖ signature(64)`:

| transaction | payload | total |
|---|---|---|
| public transfer | tag + to(32) + value(8) | **147 B** |
| private fund | tag + value(8) + commitment(64) | **179 B** |
| private rollover | tag | **107 B** |
| private transfer | tag + to(32) + amount commitment(64) + 2×160 B range proofs | **523 B** (measured 526 B/tx in blocks) |
| private burn | tag + value(8) + 160 B range proof | **275 B** |

Verification cost (measured on c8g.8xlarge, 28 rayon threads, batch
verification): ~1.1 µs/tx signatures + ~3.1 µs/tx range proofs — CPU is not
the binding constraint at current scales; **bytes are** (see below).

## Execution semantics

Private execution runs on the lane executor
(`crates/application/src/executor.rs`). The load-bearing contract is
**filtered transactions**: an op whose proof fails, whose nonce is consumed,
or whose commitment state is stale is *filtered* — excluded from effects
without invalidating its block. Filtering feeds the partial-finalization
loop:

1. The spammer submits a batch to the relayer and blocks.
2. The relayer forwards to the leader, tracks the batch through consensus,
   and returns a definitive outcome: `finalized`, `partially_finalized`
   (with the **original-batch indices** that landed), or `dropped`
   (`bin/validator/src/relayer.rs`).
3. The client advances local commitment/nonce state **only** for finalized
   indices and retries the rest with fresh proofs and the same still-free
   nonces (`bin/spammer/src/private.rs`).

Because nonces advance only on finalization, retries are always legitimate,
and client state can never run ahead of the chain.

## Load generation and sizing

The one-op-in-flight-per-account constraint means throughput comes from
*width*: many accounts, partitioned into per-leader **lanes**, each lane
keeping one batch in flight (`bin/spammer/src/private.rs`). Lanes pin to
leaders, so a lane lands one batch per leader rotation
(`validators × view-time`), and the in-flight count — not finalization
latency — is the sizing constant:

```
TPS ≈ in-flight ÷ rotation_seconds,   in-flight = lanes × batch ≤ accounts
```

`constantinople-deploy generate --spammer-target-inflight N` derives lanes,
batch size, and accounts from the single number that matters, and rejects
inconsistent explicit values at generate time (`bin/deploy/src/main.rs`,
`resolve_spammer_plan`). `--spammer-private-proof-mode simulated` runs the
whole cluster on zkpari with the spammer forging proofs via the trapdoor.

## Measured performance (July 2026, 50 validators, us-east-1 + us-west-2)

Steady-state private-transfer throughput saturates at **~17.6 MB/s of block
data ≈ 33K TPS at 526 B/tx**, byte-bound on cross-region erasure-shard
dissemination (~2 WAN round-trips of idle wait per view before
reconstruction) plus a linear coding/verify tail:

| in-flight | txs/block | view interval | TPS |
|---|---|---|---|
| 50,400 | 1,008 | 80 ms | 12.5K (rotation-bound, links idle) |
| 201,600 | 4,032 | 128 ms | 31.4K |
| 251,200 | 5,024 | ~160 ms | **33.4K (optimal)** |
| 502,400 | 10,048 | 312 ms | 32.2K (latency for nothing) |

Since throughput is byte-bound, TPS scales inversely with transaction size.
The highest-leverage known follow-up is a **joint range proof** (one proof
covering both 64-bit range checks instead of two): transfer txs drop
523 → 363 B, a projected ~48K TPS with no added CPU. Not yet implemented in
`commonware-privacy` (`TransferProof` is two independent proofs).

## Known blockers and follow-ups

- **Path dependency**: `commonware-privacy` is consumed from `../monorepo`
  on the unmerged `gv-privacy-2026.7` branch. Upstream cannot merge this
  series until the crate is published or merged; CI pins the exact monorepo
  commit (`.github/actions/setup/action.yml`).
- **Joint range proof** (above): ~+47% TPS.
- **Indexer queryability**: private transactions index with `value = 0` and
  no payload-kind discriminator; typed columns are follow-up work.
- **Explorer display**: the explorer submits public transfers correctly and
  tolerates private blocks, but renders no private payload details.
