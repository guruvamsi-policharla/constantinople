variable "REGISTRY" {
  default = "ghcr.io"
}

variable "REPOSITORY" {
  default = "commonwarexyz/constantinople"
}

variable "DEFAULT_TAG" {
  default = "local"
}

variable "PLATFORMS" {
  default = "linux/arm64"
}

target "builder" {
  context = "."
  dockerfile = "docker/Dockerfile"
  platforms = split(",", PLATFORMS)
  tags = ["constantinople-builder:${DEFAULT_TAG}"]
}
