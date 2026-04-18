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

variable "PLATFORM" {
  default = "linux/amd64"
}

variable "LOCAL_CACHE_ROOT" {
  default = ".tmp/buildx-cache"
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
  targets = ["operator", "kobe-sync"]
}

group "push" {
  targets = ["operator-push", "kobe-sync-push"]
}

# =============================================================================
# Shared build stage (built once, reused via context)
# =============================================================================
target "builder" {
  dockerfile = "docker/builder.Dockerfile"
  context    = "."
  platforms  = [PLATFORM]
  cache-from = ["type=local,src=${LOCAL_CACHE_ROOT}/builder"]
  cache-to   = ["type=local,dest=${LOCAL_CACHE_ROOT}/builder,mode=max"]
  args = {
    BUILD_VERSION = BUILD_VERSION
  }
}

# =============================================================================
# Operator image
# =============================================================================
target "operator" {
  dockerfile = "docker/operator.Dockerfile"
  context    = "."
  contexts = {
    builder = "target:builder"
  }
  platforms = [PLATFORM]
  tags      = tags("kobe-operator")
  cache-from = [
    "type=local,src=${LOCAL_CACHE_ROOT}/builder",
    "type=local,src=${LOCAL_CACHE_ROOT}/operator",
  ]
  cache-to = ["type=local,dest=${LOCAL_CACHE_ROOT}/operator,mode=max"]
  args = {
    BUILD_VERSION = BUILD_VERSION
    BUILD_COMMIT  = BUILD_COMMIT
    BUILD_DATE    = BUILD_DATE
  }
  # cache-from disabled during binary rename transition
  # cache-from = ["type=registry,ref=${REGISTRY}/kobe-operator:buildcache"]
}

target "operator-push" {
  inherits = ["operator"]
  output   = ["type=registry"]
  # cache-to = ["type=registry,ref=${REGISTRY}/kobe-operator:buildcache,mode=max"]
}

# =============================================================================
# Kobe-sync image
# =============================================================================
target "kobe-sync" {
  dockerfile = "docker/kobe-sync.Dockerfile"
  context    = "."
  contexts = {
    builder = "target:builder"
  }
  platforms = [PLATFORM]
  tags      = tags("kobe-sync")
  cache-from = [
    "type=local,src=${LOCAL_CACHE_ROOT}/builder",
    "type=local,src=${LOCAL_CACHE_ROOT}/kobe-sync",
  ]
  cache-to = ["type=local,dest=${LOCAL_CACHE_ROOT}/kobe-sync,mode=max"]
  args = {
    BUILD_VERSION = BUILD_VERSION
    BUILD_COMMIT  = BUILD_COMMIT
    BUILD_DATE    = BUILD_DATE
  }
  # cache-from = ["type=registry,ref=${REGISTRY}/kobe-sync:buildcache"]
}

target "kobe-sync-push" {
  inherits = ["kobe-sync"]
  output   = ["type=registry"]
  # cache-to = ["type=registry,ref=${REGISTRY}/kobe-sync:buildcache,mode=max"]
}
