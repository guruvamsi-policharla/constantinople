# `constantinople-application`

Consensus-facing application wrapper for `constantinople`.

This crate connects `commonware-consensus` to the in-memory application processor by:

- proposing signed execution blocks from a transaction source
- verifying received blocks with the processor
- caching prepared database batches during `propose` and `verify`
- persisting those batches during the application `apply` step after consensus finalizes a block

Use [`application::Application`] to implement `commonware_consensus::Application` and
`commonware_consensus::VerifyingApplication`.
