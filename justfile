set positional-arguments

alias f := fmt-fix
alias l := lint
alias t := test

# default recipe to display help information
default:
  @just --list

# Build the workspace
build *args='':
  cargo build --workspace --all $@

# Build the validator Docker builder image
docker-validator-image:
  docker buildx bake --progress plain -f docker/docker-bake.hcl constantinople-validator

# Build the spammer Docker builder image
docker-spammer-image:
  docker buildx bake --progress plain -f docker/docker-bake.hcl constantinople-spammer

# Build both Docker builder images
docker-images: docker-validator-image docker-spammer-image

# Build the ARM64 validator binary into deploy/
validator-binary: docker-validator-image
  docker run --rm -v ${PWD}:/constantinople constantinople-validator-builder:local

# Build the ARM64 spammer binary into deploy/
spammer-binary: docker-spammer-image
  docker run --rm -v ${PWD}:/constantinople constantinople-spammer-builder:local

# Build both ARM64 deployable binaries into deploy/
deploy-binaries: validator-binary spammer-binary

# Fixes the formatting of the workspace
fmt-fix:
  cargo +nightly fmt --all

# Check the formatting of the workspace
fmt-check:
  cargo +nightly fmt --all -- --check

# Lint the workspace
lint: fmt-check docs-check
  cargo +nightly clippy --workspace --all --all-features --all-targets -- -D warnings

# Run Rust tests
test *args='': docs-test
  cargo nextest run --workspace --all --all-features $@

# Test the Rust documentation
docs-test *args='--all':
    cargo test --doc --locked $@

# Lint the Rust documentation
docs-check *args='':
    RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --document-private-items $@

# Check for unused dependencies
udeps:
  cargo +nightly udeps --all-targets
