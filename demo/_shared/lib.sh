#!/usr/bin/env bash
# Shared library for demo/<cloud>/demo scripts.
#
# Sourced, NOT executed directly. The library intentionally does NOT set
# `set -euo pipefail` — that would affect the caller's shell state. Callers
# are expected to set it before sourcing (the per-cloud ./demo scripts do).
#
# Callers MUST set:
#   KUBECONFIG_GLOB         e.g. "exoscale-*-config" or "hetzner-*-config"
# Callers MAY set/override (defaults applied here if unset):
#   KOBE_VERSION, NAMESPACE, RELEASE, POOL, DEFAULT_LEASE_TTL, KOBE_PORT,
#   TLS_PORT, TLS_DIR, SSH_PUBKEY, PULL_SECRET_NAME, DOCKER_REGISTRY,
#   DOCKER_HUB_EMAIL, KOBE_REPO.
# Callers MAY define extra functions used by the dispatcher:
#   dispatch_extra "$@"     return 0 if handled, non-zero to fall through
#   usage_extra             prints additional help text after lib_usage

# Anchored to lib.sh location so paths don't depend on caller cwd.
LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHARED_CHART_DIR="$LIB_DIR/chart"
SHARED_MANIFESTS_DIR="$LIB_DIR/manifests"

# --- Configuration defaults --------------------------------------------------
: "${KUBECONFIG_GLOB:?KUBECONFIG_GLOB must be set by caller}"
KOBE_REPO="${KOBE_REPO:-$(cd "$LIB_DIR/../.." && pwd)}"
KOBE_VERSION="${KOBE_VERSION:-0.19.1}"
KOBE_TGZ="$SHARED_CHART_DIR/charts/kobe-${KOBE_VERSION}.tgz"
NAMESPACE="${NAMESPACE:-kobe-system}"
RELEASE="${RELEASE:-kobe-demo}"
POOL="${POOL:-demo-k3s-small}"
DEFAULT_LEASE_TTL="${DEFAULT_LEASE_TTL:-30m}"
KOBE_PORT="${KOBE_PORT:-8080}"
TLS_PORT="${TLS_PORT:-8443}"
TLS_DIR="${TLS_DIR:-$HOME/.config/kobe-demo}"
SSH_PUBKEY="${SSH_PUBKEY:-$(cat ~/.ssh/id_ed25519.pub 2>/dev/null || true)}"
PULL_SECRET_NAME="${PULL_SECRET_NAME:-regcred}"
DOCKER_REGISTRY="${DOCKER_REGISTRY:-https://index.docker.io/v1/}"

# CLOUD_DIR is the directory holding the calling ./demo script (and its
# values.yaml). Computed from $0 in the caller; we re-derive it here from
# BASH_SOURCE[1] for the case where lib.sh is sourced directly.
CLOUD_DIR="${CLOUD_DIR:-$(cd "$(dirname "${BASH_SOURCE[1]:-$0}")" && pwd)}"

# --- Output helpers ----------------------------------------------------------
bold()   { printf "\033[1m%s\033[0m\n" "$*"; }
step()   { printf "\n\033[1;36m==> %s\033[0m\n" "$*"; }
cmd()    { printf "\033[2m\$ %s\033[0m\n" "$*"; "$@"; }
note()   { printf "\033[2m   %s\033[0m\n" "$*"; }
err()    { printf "\033[1;31mERROR:\033[0m %s\n" "$*" >&2; exit 1; }

# --- Kubeconfig picker -------------------------------------------------------
pick_kubeconfig() {
  if [[ -n "${KUBECONFIG:-}" && -f "$KUBECONFIG" ]]; then
    case "$(basename "$KUBECONFIG")" in
      $KUBECONFIG_GLOB)
        note "Using KUBECONFIG from environment: $KUBECONFIG"
        return ;;
      *)
        note "Ignoring inherited KUBECONFIG=$KUBECONFIG (does not match $KUBECONFIG_GLOB)"
        unset KUBECONFIG ;;
    esac
  fi
  shopt -s nullglob
  local matches=( "$HOME"/.kube/$KUBECONFIG_GLOB )
  shopt -u nullglob
  case ${#matches[@]} in
    0) err "No kubeconfigs found in ~/.kube/ (looking for $KUBECONFIG_GLOB)." ;;
    1)
      export KUBECONFIG="${matches[0]}"
      note "Auto-selected the only matching kubeconfig: $KUBECONFIG"
      ;;
    *)
      bold "Multiple matching kubeconfigs found — pick one:"
      local i=1
      for f in "${matches[@]}"; do
        printf "  [%d] %s\n" "$i" "$(basename "$f")"
        i=$((i+1))
      done
      printf "Selection: "
      read -r choice
      [[ "$choice" =~ ^[0-9]+$ ]] || err "Invalid selection: $choice"
      [[ "$choice" -ge 1 && "$choice" -le "${#matches[@]}" ]] || err "Out of range: $choice"
      export KUBECONFIG="${matches[$((choice-1))]}"
      note "Selected: $KUBECONFIG"
      ;;
  esac
}

# --- Subcommands -------------------------------------------------------------
cmd_up() {
  step "Step 1/6: Pick kubeconfig"
  pick_kubeconfig

  step "Step 2/6: Verify cluster access"
  cmd kubectl get nodes

  step "Step 3/6: Verify vendored kobe chart is present"
  if [[ ! -f "$KOBE_TGZ" ]]; then
    err "$KOBE_TGZ missing. Run: ./demo refresh"
  fi
  note "Found $KOBE_TGZ"

  step "Step 4/6: Verify Docker Hub pull-secret exists"
  cmd kubectl get namespace "$NAMESPACE" >/dev/null 2>&1 || \
    cmd kubectl create namespace "$NAMESPACE"
  if ! kubectl -n "$NAMESPACE" get secret "$PULL_SECRET_NAME" >/dev/null 2>&1; then
    err "Pull-secret '$PULL_SECRET_NAME' missing in namespace $NAMESPACE.
       The kobe operator image (zondax/kobe-operator) is hosted on a private
       Docker Hub repo and the cluster needs credentials to pull it.

       Run once:
         ./demo pull-secret <docker-hub-user> <docker-hub-token>"
  fi
  note "Found pull-secret '$PULL_SECRET_NAME' in $NAMESPACE"

  step "Step 5/6: Install kobe-demo (helm upgrade --install)"
  local args=(
    helm upgrade --install "$RELEASE" "$SHARED_CHART_DIR"
    -f "$SHARED_CHART_DIR/values.yaml"
    -f "$CLOUD_DIR/values.yaml"
    --create-namespace -n "$NAMESPACE"
  )
  [[ -n "$SSH_PUBKEY" ]] && args+=( --set "sshPublicKey=$SSH_PUBKEY" )
  cmd "${args[@]}"

  step "Step 6/6: Wait for kobe operator + ClusterPool to be Ready"
  cmd kubectl -n "$NAMESPACE" rollout status "deploy/$RELEASE" --timeout=3m
  local min_ready
  min_ready="$(kubectl -n "$NAMESPACE" get clusterpool "$POOL" \
              -o jsonpath='{.spec.scaling.minReady}' 2>/dev/null || echo 1)"
  note "Polling ClusterPool $POOL until status.ready >= $min_ready (timeout 5m)..."
  local ready=0
  for i in {1..30}; do
    ready="$(kubectl -n "$NAMESPACE" get clusterpool "$POOL" \
              -o jsonpath='{.status.ready}' 2>/dev/null || echo 0)"
    ready="${ready:-0}"
    printf "   [%2d/30] ready=%s/%s\n" "$i" "$ready" "$min_ready"
    [[ "$ready" -ge "$min_ready" ]] && break
    sleep 10
  done
  [[ "$ready" -ge "$min_ready" ]] || err "ClusterPool $POOL ready=$ready did not reach minReady=$min_ready in 5 minutes."

  bold "Done. Next:"
  echo "  ./demo forward       # in another terminal"
  echo "  ./demo lease         # to get a kubeconfig for a leased k3s cluster"
}

cmd_down() {
  pick_kubeconfig
  step "Uninstall release $RELEASE from namespace $NAMESPACE"
  cmd helm uninstall -n "$NAMESPACE" "$RELEASE"
  note "CRDs and namespace $NAMESPACE are intentionally left in place."
}

cmd_lease() {
  pick_kubeconfig
  step "Lease a cluster from pool $POOL (TTL $DEFAULT_LEASE_TTL)"
  note "Make sure './demo tunnel' (or 'forward') is running in another terminal."
  cmd kobe lease "$POOL" --ttl "$DEFAULT_LEASE_TTL"

  # Auto-patch the freshly written kubeconfig to use https://localhost:$TLS_PORT
  # so kubectl/Kunobi can talk to the leased cluster (kubectl 1.31+ refuses to
  # send bearer tokens over plain HTTP).
  shopt -s nullglob
  local matches=( "$HOME"/.kube/kobe-"$POOL"-*.yaml )
  shopt -u nullglob
  if [[ "${#matches[@]}" -gt 0 ]]; then
    local newest
    newest="$(ls -t "${matches[@]}" | head -1)"
    note "Auto-patching kubeconfig $newest → https://localhost:$TLS_PORT"
    patch_lease_kubeconfig "$newest"
  fi
}

cmd_release() {
  pick_kubeconfig
  local lease_id="${1:-}"
  if [[ -n "$lease_id" ]]; then
    step "Release lease $lease_id"
    cmd kobe release "$lease_id"
  else
    step "Release all active leases (kobe purge)"
    note "No lease ID given — using 'kobe purge' to release all and clean local kubeconfigs."
    cmd kobe purge
  fi
}

pick_leased_kubeconfig() {
  local explicit="${1:-}"
  if [[ -n "$explicit" ]]; then
    [[ -f "$explicit" ]] || err "Kubeconfig not found at $explicit"
    printf '%s\n' "$explicit"
    return
  fi
  shopt -s nullglob
  local matches=( "$HOME"/.kube/kobe-"$POOL"-*.yaml )
  shopt -u nullglob
  [[ "${#matches[@]}" -gt 0 ]] || err "No leased kubeconfig in ~/.kube/kobe-$POOL-*.yaml. Run './demo lease' first."
  local newest
  newest="$(ls -t "${matches[@]}" | head -1)"
  printf '%s\n' "$newest"
}

cmd_deploy_ubuntu() {
  local kubeconfig
  kubeconfig="$(pick_leased_kubeconfig "${1:-}")"
  step "Deploy Ubuntu pod into leased cluster (server-side apply via curl)"
  note "Using leased kubeconfig: $kubeconfig"

  # kubectl 1.31+ refuses to send bearer tokens over plain HTTP, but the kobe
  # connect proxy is HTTP-only. Use curl with the bearer token instead.
  local token server
  token="$(yq -r '.users[0].user.token' "$kubeconfig")"
  server="$(yq -r '.clusters[0].cluster.server' "$kubeconfig")"
  [[ -n "$token"  && "$token"  != "null" ]] || err "No bearer token found in $kubeconfig"
  [[ -n "$server" && "$server" != "null" ]] || err "No cluster server URL found in $kubeconfig"

  case "$server" in
    https://localhost:"$TLS_PORT"/*)
      if ! curl -sk --max-time 2 -o /dev/null "https://localhost:$TLS_PORT/" 2>/dev/null; then
        err "Cannot reach https://localhost:$TLS_PORT — start './demo tunnel' in another terminal first."
      fi
      ;;
  esac

  apply_yaml_doc() {
    local kind="$1" ns="$2" name="$3" body="$4" path
    case "$kind" in
      Namespace)          path="/api/v1/namespaces/$name" ;;
      ServiceAccount)     path="/api/v1/namespaces/$ns/serviceaccounts/$name" ;;
      ClusterRoleBinding) path="/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/$name" ;;
      Deployment)         path="/apis/apps/v1/namespaces/$ns/deployments/$name" ;;
      *) err "Unsupported kind: $kind (extend cmd_deploy_ubuntu's path table)" ;;
    esac
    note "PATCH $path  ($kind $ns/$name)"
    local code
    code="$(printf '%s' "$body" | curl -sk --max-time 30 \
      -o /tmp/kobe-demo-apply.out -w '%{http_code}' \
      -X PATCH "$server$path?fieldManager=kobe-demo&force=true" \
      -H "Authorization: Bearer $token" \
      -H "Content-Type: application/apply-patch+yaml" \
      --data-binary @-)"
    if [[ "$code" != 2* ]]; then
      printf '   HTTP %s — response:\n' "$code" >&2
      cat /tmp/kobe-demo-apply.out >&2; echo >&2
      err "Apply failed for $kind $ns/$name"
    fi
  }

  shopt -s nullglob
  local files=( "$SHARED_MANIFESTS_DIR"/ubuntu/*.yaml )
  shopt -u nullglob
  [[ "${#files[@]}" -gt 0 ]] || err "No files in $SHARED_MANIFESTS_DIR/ubuntu/"

  local count=0
  for f in "${files[@]}"; do
    local doc kind ns name
    doc="$(cat "$f")"
    kind="$(yq -r '.kind' "$f")"
    name="$(yq -r '.metadata.name' "$f")"
    ns="$(yq -r '.metadata.namespace // ""' "$f")"
    apply_yaml_doc "$kind" "$ns" "$name" "$doc"
    count=$((count+1))
  done

  note "Applied $count document(s)."
  note "Now point Kunobi at $kubeconfig and exec into deploy/demo-ubuntu in 'demo-workloads'."
}

cmd_forward() {
  pick_kubeconfig
  step "Port-forward kobe API svc/$RELEASE to localhost:$KOBE_PORT"
  note "Press Ctrl+C to stop."
  cmd kubectl -n "$NAMESPACE" port-forward "svc/$RELEASE" "$KOBE_PORT:8080"
}

ensure_tls_cert() {
  mkdir -p "$TLS_DIR"
  local crt="$TLS_DIR/tls.crt" key="$TLS_DIR/tls.key"
  if [[ -f "$crt" && -f "$key" ]]; then
    note "Reusing TLS cert at $TLS_DIR/"
    return
  fi
  step "Generate self-signed TLS cert (one-time, kept at $TLS_DIR/)"
  cmd openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -keyout "$key" -out "$crt" \
      -subj "/CN=localhost" \
      -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
}

cmd_tunnel() {
  pick_kubeconfig

  if ! command -v socat >/dev/null 2>&1; then
    err "socat not installed. brew install socat (or apt-get install socat) and try again."
  fi

  ensure_tls_cert

  step "Start kubectl port-forward in background → svc/$RELEASE :$KOBE_PORT"
  kubectl -n "$NAMESPACE" port-forward "svc/$RELEASE" "$KOBE_PORT:8080" \
    >/tmp/kobe-demo-pf.log 2>&1 &
  local pf_pid=$!
  trap "kill $pf_pid 2>/dev/null || true" EXIT INT TERM
  sleep 1
  if ! kill -0 "$pf_pid" 2>/dev/null; then
    err "kubectl port-forward died — see /tmp/kobe-demo-pf.log"
  fi
  note "kubectl port-forward PID $pf_pid (logs at /tmp/kobe-demo-pf.log)"

  step "Start TLS terminator (socat) on :$TLS_PORT → localhost:$KOBE_PORT"
  note "Leased-cluster kubectl/Kunobi traffic should target https://localhost:$TLS_PORT"
  note "Run './demo lease' (or 'patch-lease') to point lease kubeconfigs at this URL."
  note "Press Ctrl+C to stop both port-forward and TLS terminator."
  cmd socat \
    "openssl-listen:$TLS_PORT,reuseaddr,fork,cert=$TLS_DIR/tls.crt,key=$TLS_DIR/tls.key,verify=0" \
    "tcp:localhost:$KOBE_PORT"
}

patch_lease_kubeconfig() {
  local kc="$1"
  [[ -f "$kc" ]] || err "Kubeconfig not found: $kc"
  yq -i \
    "(.clusters[].cluster.server) |= sub(\"http://localhost:$KOBE_PORT\"; \"https://localhost:$TLS_PORT\")
     | .clusters[].cluster.\"insecure-skip-tls-verify\" = true" \
    "$kc"
}

cmd_patch_lease() {
  local kubeconfig
  kubeconfig="$(pick_leased_kubeconfig "${1:-}")"
  step "Patch leased kubeconfig to use https://localhost:$TLS_PORT"
  note "Target: $kubeconfig"
  patch_lease_kubeconfig "$kubeconfig"
  note "Done. kubectl/Kunobi can now use this kubeconfig (./demo tunnel must be running)."
}

cmd_pull_secret() {
  local user="${1:-}"
  local token="${2:-}"
  local email="${3:-${DOCKER_HUB_EMAIL:-noreply@example.com}}"
  if [[ -z "$user" || -z "$token" ]]; then
    err "Usage: ./demo pull-secret <docker-hub-user> <docker-hub-token> [email]
       Token must have read access to zondax/kobe-operator and zondax/kobe-sync
       on Docker Hub. Generate one at https://hub.docker.com/settings/security."
  fi
  pick_kubeconfig
  step "Create/replace Docker Hub pull-secret '$PULL_SECRET_NAME' in $NAMESPACE"
  cmd kubectl get namespace "$NAMESPACE" >/dev/null 2>&1 || \
    cmd kubectl create namespace "$NAMESPACE"
  kubectl -n "$NAMESPACE" delete secret "$PULL_SECRET_NAME" --ignore-not-found >/dev/null
  cmd kubectl -n "$NAMESPACE" create secret docker-registry "$PULL_SECRET_NAME" \
    --docker-server="$DOCKER_REGISTRY" \
    --docker-username="$user" \
    --docker-password="$token" \
    --docker-email="$email"
  note "Done. Now run: ./demo up"
}

cmd_status() {
  pick_kubeconfig
  step "Pool / Instance / Lease status"
  cmd kubectl -n "$NAMESPACE" get clusterpool,clusterinstance,clusterlease
}

cmd_refresh() {
  step "Refresh vendored kobe chart from $KOBE_REPO"
  [[ -d "$KOBE_REPO/charts/kobe" ]] || err "$KOBE_REPO/charts/kobe not found. Set KOBE_REPO=..."
  local subcharts_dir="$KOBE_REPO/charts/kobe/charts"
  if [[ ! -d "$subcharts_dir" ]] || [[ -z "$(ls -A "$subcharts_dir" 2>/dev/null)" ]]; then
    note "Subcharts missing — running 'helm dependency build' (uses Chart.lock)"
    cmd helm dependency build "$KOBE_REPO/charts/kobe"
  else
    note "Subcharts already present at $subcharts_dir — skipping dep fetch"
  fi
  cmd rm -f "$SHARED_CHART_DIR"/charts/kobe-*.tgz
  cmd helm package "$KOBE_REPO/charts/kobe" -d "$SHARED_CHART_DIR/charts/"
}

cmd_lint() {
  step "Lint the umbrella chart"
  cmd helm lint "$SHARED_CHART_DIR" \
    -f "$SHARED_CHART_DIR/values.yaml" \
    -f "$CLOUD_DIR/values.yaml" \
    --set sshPublicKey="ssh-ed25519 AAAATEMPLATEPLACEHOLDER lint@local"
}

cmd_template() {
  step "Render full template output (no cluster contact)"
  cmd helm template "$RELEASE" "$SHARED_CHART_DIR" \
    -f "$SHARED_CHART_DIR/values.yaml" \
    -f "$CLOUD_DIR/values.yaml" \
    --set sshPublicKey="ssh-ed25519 AAAATEMPLATEPLACEHOLDER lint@local"
}

# --- Shared dispatcher -------------------------------------------------------
# Caller invokes `lib_dispatch "$@"` at the end of its ./demo script.
# If the caller defines `dispatch_extra "$@"`, lib_dispatch calls it first;
# extra returns 0 if it handled the verb, non-zero to fall through.
lib_dispatch() {
  if declare -f dispatch_extra >/dev/null 2>&1; then
    if dispatch_extra "$@"; then
      return 0
    fi
  fi
  case "${1:-}" in
    up)              cmd_up ;;
    down)            cmd_down ;;
    lease)           cmd_lease ;;
    release)         shift; cmd_release "$@" ;;
    deploy-ubuntu)   shift; cmd_deploy_ubuntu "$@" ;;
    forward)         cmd_forward ;;
    tunnel)          cmd_tunnel ;;
    patch-lease)     shift; cmd_patch_lease "$@" ;;
    status)          cmd_status ;;
    pull-secret)     shift; cmd_pull_secret "$@" ;;
    refresh)         cmd_refresh ;;
    lint)            cmd_lint ;;
    template)        cmd_template ;;
    ""|-h|--help|help) lib_usage ;;
    *) err "Unknown subcommand: $1 (try ./demo help)" ;;
  esac
}

lib_usage() {
  cat <<EOF
Usage: ./demo <subcommand>

Shared subcommands:
  up             Pick kubeconfig, verify cluster, helm install, wait for pool Ready
  down           helm uninstall
  lease          kobe lease against the demo pool
  release        kobe release <lease-id> (or 'kobe purge' if no id given)
                   Usage: ./demo release [LEASE_ID]
  deploy-ubuntu  Server-side-apply demo/_shared/manifests/ubuntu/*.yaml into the leased cluster
                   Usage: ./demo deploy-ubuntu [LEASED_KUBECONFIG_PATH]
  forward        kubectl port-forward kobe API on :$KOBE_PORT (HTTP — for kobe CLI only)
  tunnel         port-forward + TLS terminator on :$TLS_PORT (HTTPS — for kubectl/Kunobi against leased clusters)
  patch-lease    Rewrite a leased kubeconfig to use https://localhost:$TLS_PORT
                   Usage: ./demo patch-lease [LEASED_KUBECONFIG_PATH]
  status         kubectl get clusterpool,clusterinstance,clusterlease
  pull-secret    Create regcred docker-registry secret in $NAMESPACE
                   Usage: ./demo pull-secret <user> <token> [email]
  refresh        Re-package $SHARED_CHART_DIR/charts/kobe-X.Y.Z.tgz from \$KOBE_REPO
  lint           helm lint the umbrella chart
  template       helm template (local-only render)

Env overrides: KOBE_REPO, KOBE_VERSION, NAMESPACE, RELEASE, POOL,
               KUBECONFIG, SSH_PUBKEY, KOBE_PORT, DEFAULT_LEASE_TTL,
               PULL_SECRET_NAME, DOCKER_REGISTRY, DOCKER_HUB_EMAIL
EOF
  if declare -f usage_extra >/dev/null 2>&1; then
    usage_extra
  fi
}
