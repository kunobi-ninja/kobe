#!/usr/bin/env bash

set -euo pipefail

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for hack/lease-smoke.sh" >&2
  exit 1
fi

if ! command -v kubectl >/dev/null 2>&1; then
  echo "kubectl is required for hack/lease-smoke.sh" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

POOL="${1:-ci-small}"
TTL="${2:-15m}"
shift $(( $# > 0 ? 1 : 0 ))
shift $(( $# > 0 ? 1 : 0 ))
KOBE_ARGS=("$@")
LEASE_WAIT_TIMEOUT="${LEASE_WAIT_TIMEOUT:-15s}"
CONNECT_TIMEOUT_SECONDS="${CONNECT_TIMEOUT_SECONDS:-5}"
CONNECT_RETRY_SECONDS="${CONNECT_RETRY_SECONDS:-1}"
ALLOW_COLD_START="${ALLOW_COLD_START:-0}"
LEASE_WAIT_TIMEOUT_COLD="${LEASE_WAIT_TIMEOUT_COLD:-120s}"
CONNECT_TIMEOUT_SECONDS_COLD="${CONNECT_TIMEOUT_SECONDS_COLD:-60}"

LEASE_ID=""
RELEASED=0

cleanup() {
  if [[ -n "$LEASE_ID" && "$RELEASED" -eq 0 ]]; then
    echo "Releasing lease $LEASE_ID..." >&2
    cargo run --bin kobe -- "${KOBE_ARGS[@]}" release "$LEASE_ID" -o json >/dev/null
  fi
}

trap cleanup EXIT

preflight_pool_state() {
  local status_json
  local pool_json
  local ready
  local creating
  local leased
  local recycling
  local queue_depth

  echo "Checking pool state..." >&2
  status_json="$(cargo run --bin kobe -- "${KOBE_ARGS[@]}" status -o json)"
  pool_json="$(printf '%s' "$status_json" | jq -c --arg pool "$POOL" '.pools[] | select(.name == $pool)')"

  if [[ -z "$pool_json" ]]; then
    echo "Pool '$POOL' was not found in kobe status output" >&2
    exit 1
  fi

  ready="$(printf '%s' "$pool_json" | jq -r '.ready')"
  creating="$(printf '%s' "$pool_json" | jq -r '.creating')"
  leased="$(printf '%s' "$pool_json" | jq -r '.leased')"
  recycling="$(printf '%s' "$pool_json" | jq -r '.recycling // 0')"
  queue_depth="$(printf '%s' "$pool_json" | jq -r '.queueDepth')"

  echo "Pool '$POOL': ready=$ready leased=$leased creating=$creating recycling=$recycling queue=$queue_depth" >&2

  if (( ready > 0 )); then
    return 0
  fi

  if [[ "$ALLOW_COLD_START" == "1" ]]; then
    LEASE_WAIT_TIMEOUT="$LEASE_WAIT_TIMEOUT_COLD"
    CONNECT_TIMEOUT_SECONDS="$CONNECT_TIMEOUT_SECONDS_COLD"
    echo "Pool '$POOL' is cold. Using relaxed cold-start budget: lease wait=$LEASE_WAIT_TIMEOUT, API readiness=${CONNECT_TIMEOUT_SECONDS}s." >&2
    return 0
  fi

  echo "Pool '$POOL' has no ready clusters. Failing fast because this smoke test is for the warm path." >&2
  echo "Set ALLOW_COLD_START=1 to exercise provisioning latency instead." >&2
  exit 1
}

wait_for_cluster_api() {
  local kubeconfig_path="$1"
  local deadline=$((SECONDS + CONNECT_TIMEOUT_SECONDS))
  local started_at="$SECONDS"
  local last_error=""
  local probe_out
  local probe_err
  local attempt=0

  probe_out="$(mktemp)"
  probe_err="$(mktemp)"
  trap 'rm -f "$probe_out" "$probe_err"' RETURN

  while (( SECONDS < deadline )); do
    attempt=$((attempt + 1))
    if kubectl --request-timeout=5s --kubeconfig "$kubeconfig_path" get namespace kube-system -o name >"$probe_out" 2>"$probe_err"; then
      local elapsed=$((SECONDS - started_at))
      echo "Cluster API ready after ${elapsed}s." >&2
      return 0
    else
      last_error="$(tr '\n' ' ' <"$probe_err")"
    fi

    local elapsed=$((SECONDS - started_at))
    local remaining=$((deadline - SECONDS))
    local preview="$last_error"
    if (( ${#preview} > 140 )); then
      preview="${preview:0:137}..."
    fi
    echo "  [attempt ${attempt}] waiting for namespace query (${elapsed}s elapsed, ${remaining}s left) - ${preview:-no response yet}" >&2
    sleep "$CONNECT_RETRY_SECONDS"
  done

  echo "Timed out waiting for leased cluster API readiness after ${CONNECT_TIMEOUT_SECONDS}s" >&2
  if [[ -n "$last_error" ]]; then
    echo "Last readiness error: $last_error" >&2
  fi
  return 1
}

preflight_pool_state

echo "Requesting lease from pool '$POOL' (ttl=$TTL, lease wait timeout=$LEASE_WAIT_TIMEOUT)..." >&2
LEASE_JSON="$(
  cargo run --bin kobe -- "${KOBE_ARGS[@]}" lease "$POOL" --ttl "$TTL" --wait-timeout "$LEASE_WAIT_TIMEOUT" -o json
)"

LEASE_ID="$(printf '%s' "$LEASE_JSON" | jq -r '.id')"
PHASE="$(printf '%s' "$LEASE_JSON" | jq -r '.phase')"
PROFILE="$(printf '%s' "$LEASE_JSON" | jq -r '.profile')"
KUBECONFIG_PATH="$(printf '%s' "$LEASE_JSON" | jq -r '.kubeconfigPath // empty')"
CLUSTER_NAME="$(printf '%s' "$LEASE_JSON" | jq -r '.clusterName // empty')"

if [[ -z "$LEASE_ID" || "$LEASE_ID" == "null" ]]; then
  echo "Lease response did not include an id" >&2
  exit 1
fi

if [[ -z "$KUBECONFIG_PATH" ]]; then
  echo "Lease $LEASE_ID did not return a kubeconfig path" >&2
  exit 1
fi

if [[ ! -f "$KUBECONFIG_PATH" ]]; then
  echo "Lease kubeconfig was not written: $KUBECONFIG_PATH" >&2
  exit 1
fi

echo "Lease acquired: $LEASE_ID" >&2
echo "Validating kubeconfig shape..." >&2
SERVER="$(kubectl --kubeconfig "$KUBECONFIG_PATH" config view --raw -o jsonpath='{.clusters[0].cluster.server}')"
CONTEXT_NAME="$(kubectl --kubeconfig "$KUBECONFIG_PATH" config view --raw -o jsonpath='{.contexts[0].name}')"

EXPECTED_SUFFIX="/connect/$LEASE_ID"
if [[ "$SERVER" != *"$EXPECTED_SUFFIX" ]]; then
  echo "Expected kubeconfig server to end with $EXPECTED_SUFFIX, got: $SERVER" >&2
  exit 1
fi

if [[ "$CONTEXT_NAME" != "$LEASE_ID" ]]; then
  echo "Expected kubeconfig context name '$LEASE_ID', got: $CONTEXT_NAME" >&2
  exit 1
fi

echo "Waiting for cluster API readiness..." >&2
wait_for_cluster_api "$KUBECONFIG_PATH"

echo "Checking API reachability..." >&2
kubectl --kubeconfig "$KUBECONFIG_PATH" get namespace kube-system -o name >/dev/null

echo "Releasing lease..." >&2
RELEASE_JSON="$(cargo run --bin kobe -- "${KOBE_ARGS[@]}" release "$LEASE_ID" -o json)"
RELEASE_STATUS="$(printf '%s' "$RELEASE_JSON" | jq -r '.status')"

if [[ "$RELEASE_STATUS" != "released" && "$RELEASE_STATUS" != "not_found" ]]; then
  echo "Unexpected release status for $LEASE_ID: $RELEASE_STATUS" >&2
  exit 1
fi

RELEASED=1

cat <<EOF
Lease smoke test passed.
  pool:        $PROFILE
  lease_id:    $LEASE_ID
  cluster:     ${CLUSTER_NAME:-unknown}
  phase:       $PHASE
  kubeconfig:  $KUBECONFIG_PATH
  server:      $SERVER
  release:     $RELEASE_STATUS
EOF
