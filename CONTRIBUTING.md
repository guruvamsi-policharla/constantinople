# Contributing

External contributions are welcome, but this repository is focused on improving Constantinople
itself: the validator, the engine, the mempool, the application logic, the deployment tooling, and
the documentation around them.

Changes are more likely to be accepted when they directly improve the repository in a concrete way,
for example:

- fixing correctness bugs
- adding regression coverage
- improving performance in hot paths that matter here
- tightening deployment or developer workflows
- clarifying documentation that is specific to Constantinople

Changes are less likely to be accepted when they add complexity without a clear payoff, for example:

- new optional features that are not needed by this repo
- new dependencies without a strong reason
- large refactors that do not improve behavior, readability, or maintainability
- drive-by formatting or AI-generated churn without clear value

## Development Workflow

This repository uses [`just`](https://github.com/casey/just) to wrap common development commands.
If you do not already have it installed, see the Just installation guide or run:

```sh
cargo install just
```

Common commands:

```sh
just build
just test
just lint
just fmt-fix
just fmt-check
just docs-test
just docs-check
```

Before opening a pull request, run:

```sh
just lint
just test
```

If you are working on deployment artifacts or remote deployment workflows, the Docker-backed build
recipes live in `docker/justfile`. The most common targets are:

```sh
just validator-graviton-binary
just validator-intel-binary
```

Run `just --list` to see the full command surface.

## Code Expectations

Keep changes easy to read. Favor straightforward code, early returns, and clear tests over clever
abstractions.

When fixing a bug, include a regression test when practical. When changing behavior, update the
docs that describe that behavior in the same pull request.

## Pull Requests

If you are planning a non-trivial change, open an issue first or start the discussion in the pull
request so the scope is clear before too much code is written.

Keep pull requests narrow. Small, focused changes are easier to review and easier to roll back if
needed.

## Security

For security issues, follow the private reporting guidance in [`SECURITY.md`](./SECURITY.md)
instead of opening a public issue.

## Licensing

Review the repository license files before contributing:

- [`LICENSE-MIT`](./LICENSE-MIT)
- [`LICENSE-APACHE`](./LICENSE-APACHE)
