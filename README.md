# Constantinople

A high-throughput blockchain demo built on [`commonware`](https://github.com/commonwarexyz/monorepo) primitives.
Constantinople wires together simplex consensus, erasure-coded broadcast, and QMDB storage into a
simple blockchain that can facilitate transfers and execution of embedded precompiles.

## Architecture

```
bin/
  validator/        CLI that assembles and runs a validator node
  tx-cli/           Transaction builder and submission tool

crates/
  primitives/       Core types: blocks, transactions, accounts, receipts, access lists
  application/      Consensus integration and transaction processor
  mempool/          HTTP mempool server and transaction source
  engine/           Engine assembly: wires consensus, marshal, QMDB, and p2p together
```

### Commonware Primitives

| Primitive | Role |
|---|---|
| [`commonware-consensus`](https://github.com/commonwarexyz/monorepo/tree/main/commonware-consensus) (simplex) | Single-epoch BFT consensus with threshold BLS finality |
| [`commonware-consensus`](https://github.com/commonwarexyz/monorepo/tree/main/commonware-consensus) (marshal) | Erasure-coded broadcast and backfill of finalized blocks |
| [`commonware-storage`](https://github.com/commonwarexyz/monorepo/tree/main/commonware-storage) (QMDB) | Merkleized key-value database for state and transaction roots |
| [`commonware-glue`](https://github.com/commonwarexyz/monorepo/tree/main/commonware-glue) (stateful) | State management, startup sync (marshal-sync and state-sync) |
| [`commonware-p2p`](https://github.com/commonwarexyz/monorepo/tree/main/commonware-p2p) | Authenticated peer-to-peer networking with discovery |

### Transaction Processor

The processor in `crates/application/src/processor` implements a simple account model with
balance transfers and pluggable Rust precompiles:

- **Block access lists**: the proposer builds a block-level access list during execution,
  enabling greedy parallel scheduling of independent transactions during verification.
- **Precompiles**: implement the `Precompiles` trait to register arbitrary Rust functions at
  specific addresses. Precompiles execute inside a `Frame` that provides scoped reads, writes,
  transfers, and nested calls.
- **Deterministic execution**: the scheduler groups transactions into dependency rounds and
  executes them in a deterministic order, producing a changeset, receipts, and merkle roots.

## Quick Start

### Setup

Generate validator configs for a local cluster (e.g. 4 validators):

```sh
cargo run --bin constantinople -- setup \
  --validators 4 \
  --output-dir ./configs \
  --base-port 3000 \
  --base-http-port 8080
```

### Run

Start each validator with its config:

```sh
cargo run --bin constantinople -- run --config ./configs/validator-0.toml
```

Or use the `mprocs` command printed by `setup` to launch all validators at once.

### Submit a Transaction

```sh
cargo run --bin constantinople-tx -- transfer \
  --key <hex-private-key> \
  --to <hex-address> \
  --value 100 \
  --nonce 0 \
  --endpoint http://localhost:8080
```

## Development

```sh
just build    # build the workspace
just test     # run all tests (includes doc tests)
just lint     # format check + doc check + clippy (denies warnings)
just fmt-fix  # auto-fix formatting
```

## License

[MIT](LICENSE.md)
