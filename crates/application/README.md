# `constantinople-application`

Consensus-facing application and transfer executor.

The crate is intentionally small:

- `executor` owns deterministic account transitions.
- `consensus` adapts the executor to `commonware_glue::stateful`.

Keep this crate direct and performance-oriented. Avoid abstraction layers unless
they remove real hot-path complexity.
