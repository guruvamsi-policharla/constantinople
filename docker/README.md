# `commonware-docker`

This directory contains all of the repositories' dockerfiles as well as the [bake file](https://docs.docker.com/build/bake/)
used to define this repository's docker build configuration.

## Install Dependencies

* `docker`: https://www.docker.com/get-started/
* `docker-buildx`: https://github.com/docker/buildx?tab=readme-ov-file#installing

## Building Locally

To build any image in the bake file locally, use `docker buildx bake`:

```sh
export TARGET="<target_name>"

# Optional: adjust the tag for the image
# Defaults to `constantinople:local`
export DEFAULT_TAG="my-image:local"

# Optional: Override the platforms to build the image for.
# Defaults to `linux/amd64,linux/arm64`
export PLATFORMS="<platforms>"

docker buildx bake \
  --progress plain \
  -f docker/docker-bake.hcl \
  $TARGET
```

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
