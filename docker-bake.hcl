# Docker Bake configuration for kobe
# Build:     docker buildx bake -f docker-bake.hcl
# Dry run:   docker buildx bake -f docker-bake.hcl --print
# Push (CI): docker buildx bake -f docker-bake.hcl push

variable "REGISTRY" {
  default = "zondax"
}

variable "IMAGE_TAG" {
  default = "dev"
}

variable "VERSION" {
  default = "0.0.0"
}

variable "BUILD_VERSION" {
  default = "dev"
}

variable "BUILD_COMMIT" {
  default = "unknown"
}

variable "BUILD_DATE" {
  default = "unknown"
}

variable "RUST_VERSION" {
  default = "1.93"
}

# Generate tag array: latest, IMAGE_TAG, and rolling semver tags (v0.1.0, v0.1, v0)
function "tags" {
  params = [name]
  result = compact([
    "${REGISTRY}/${name}:latest",
    "${REGISTRY}/${name}:${IMAGE_TAG}",
    notequal(VERSION, "0.0.0") ? "${REGISTRY}/${name}:v${VERSION}" : "",
    notequal(VERSION, "0.0.0") ? "${REGISTRY}/${name}:v${split(".", VERSION)[0]}.${split(".", VERSION)[1]}" : "",
    notequal(VERSION, "0.0.0") ? "${REGISTRY}/${name}:v${split(".", VERSION)[0]}" : "",
  ])
}

# =============================================================================
# Groups
# =============================================================================
group "default" {
  targets = ["operator"]
}

group "push" {
  targets = ["operator-push"]
}

# =============================================================================
# Shared base config
# =============================================================================
target "_common" {
  dockerfile = "Dockerfile"
  context    = "."
  platforms  = ["linux/amd64"]
  args = {
    RUST_VERSION  = RUST_VERSION
    BUILD_VERSION = BUILD_VERSION
    BUILD_COMMIT  = BUILD_COMMIT
    BUILD_DATE    = BUILD_DATE
  }
}

# =============================================================================
# Local build (no push)
# =============================================================================
target "operator" {
  inherits   = ["_common"]
  tags       = tags("kobe")
  cache-from = ["type=registry,ref=${REGISTRY}/kobe:buildcache"]
}

# =============================================================================
# CI build + push + cache export
# =============================================================================
target "operator-push" {
  inherits   = ["_common"]
  tags       = tags("kobe")
  cache-from = ["type=registry,ref=${REGISTRY}/kobe:buildcache"]
  output     = ["type=registry"]
  cache-to   = ["type=registry,ref=${REGISTRY}/kobe:buildcache,mode=max"]
}
