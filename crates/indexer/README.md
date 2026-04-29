# constantinople-indexer

Uploads consensus artifacts from secondary (non-voting) Constantinople
validators to an [exoware](https://exoware.xyz) store via
[`exoware-sdk::StoreClient`](https://docs.rs/exoware-sdk).

The indexer is **publish-only**. Querying is served directly by the exoware
server. This crate provides:

- `KeyCodec` wrappers for the seven artifact families (blocks, transactions,
  certificates, height/digest indexes, metadata).
- A `Reporter` that taps marshal `Update` events and uploads finalized blocks
  with their transactions in a single atomic batch.
- A `Reporter` that taps simplex `Activity` events and uploads
  notarization/finalization certificates.
- An `IndexerClient` that wraps `StoreClient` with typed read accessors for
  tests and library consumers.
- A `[[bin]] indexer` that runs `exoware_simulator::server::run` for local
  development.
