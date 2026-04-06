# `commonware-docker`

This directory contains the Docker build configuration used to compile Constantinople's deployable
ARM64 binaries for AWS Graviton.

## Install Dependencies

* `docker`: https://www.docker.com/get-started/
* `docker-buildx`: https://github.com/docker/buildx?tab=readme-ov-file#installing

## Building Locally

The `justfile` wraps the Docker build flow:

```sh
just build-image
```

By default, these build ARM64 images for AWS Graviton (`linux/arm64`).

#### Build Validator Binary

```sh
just validator-binary
```

This writes:

* `deploy/validator`
* `deploy/validator-debug`

#### Build Deployable Binary

```sh
just build-deployer-binaries
```

This writes:

* `deploy/validator`
* `deploy/validator-debug`

#### Troubleshooting

If you receive an error like the following:

```
ERROR: Multi-platform build is not supported for the docker driver.
Switch to a different driver, or turn on the containerd image store, and try again.
Learn more at https://docs.docker.com/go/build-multi-platform/
```

Create and activate a new builder and retry the bake command.

```sh
docker buildx create --name commonware-builder --use
```
