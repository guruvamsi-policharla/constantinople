# Constantinople Engine

Assembly for the full Constantinople validator stack.

This crate wires together:

- `constantinople-application`
- `commonware-glue::stateful`
- erasure-coded marshal
- simplex consensus with epoch transitions
- DKG-based continuous resharing

The engine is runtime and network-agnostic. Tests can run it under the
deterministic runtime and simulated networking, while production can supply a
real runtime and transport.
