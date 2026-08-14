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

# Generate the tag array. Each tag means exactly ONE thing:
#
#   dev        moving; head of main (the `IMAGE_TAG` slot — also how a local
#              `docker buildx bake` and the e2e harness name their builds)
#   sha-<7>    immutable; the exact commit that produced the image
#   latest     newest RELEASE
#   vX.Y.Z     that release, immutable
#   vX.Y / vX  newest release in that series
#
# `latest` is release-gated on purpose. It used to be emitted unconditionally,
# which made it a second name for `dev`: every publish moved it, so it tracked
# whatever last ran (main push, nightly, or a branch dispatch) rather than the
# newest release. Anyone pulling `latest` expecting a released build silently
# got main — or worse, an unmerged branch.
#
# `IMAGE_TAG` is dropped when empty so a release run publishes ONLY the release
# tags and leaves `dev` pointing where it was; `dev` advances on the next push
# to main. Empty is checked rather than assumed because `"${REGISTRY}/${name}:"`
# is a malformed tag, not an empty string, so `compact` would not remove it.
function "tags" {
  params = [name]
  result = compact([
    notequal(IMAGE_TAG, "") ? "${REGISTRY}/${name}:${IMAGE_TAG}" : "",
    notequal(BUILD_COMMIT, "unknown") ? "${REGISTRY}/${name}:sha-${substr(BUILD_COMMIT, 0, 7)}" : "",
    notequal(VERSION, "0.0.0") ? "${REGISTRY}/${name}:latest" : "",
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
