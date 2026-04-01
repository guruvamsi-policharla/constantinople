variable "REGISTRY" {
  default = "ghcr.io"
}

variable "REPOSITORY" {
  default = "commonwarexyz/constantinople"
}

variable "DEFAULT_TAG" {
  default = "constantinople:local"
}

variable "PLATFORMS" {
  // Only specify a single platform when `--load` ing into docker.
  // Multi-platform is supported when outputting to disk or pushing to a registry.
  // Multi-platform builds can be tested locally with:  --set="*.output=type=image,push=false"
  default = "linux/amd64,linux/arm64"
}

// Special target: https://github.com/docker/metadata-action#bake-definition
target "docker-metadata-action" {
  tags = ["${DEFAULT_TAG}"]
}

target "constantinople-validator" {
  inherits = ["docker-metadata-action"]
  context = "."
  dockerfile = "docker/validator.dockerfile"
  platforms = split(",", PLATFORMS)
}

target "constantinople-spam-bot" {
  inherits = ["docker-metadata-action"]
  context = "."
  dockerfile = "docker/validator.dockerfile"
  platforms = split(",", PLATFORMS)
}
