# kobe-on-Hetzner-Cloud demo — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `demo/hetzner/` variant of the existing `demo/exoscale/` demo that provisions its own k3s cluster on Hetzner Cloud via Terraform, then runs the same kobe install + lease + deploy-ubuntu flow on top — while factoring the cloud-agnostic helm chart + bash helpers into `demo/_shared/` so both clouds share them.

**Architecture:** Two-layer split. Provisioning layer (Hetzner-only, Terraform, single-node k3s on a CX22, extensible to multi-node via `node_count`) plus an application layer that's the existing Helm umbrella chart unchanged. The cloud-specific `./demo` becomes a 30-line wrapper that sources `_shared/lib.sh` and (for Hetzner) adds `tf up/down/output` verbs.

**Tech Stack:** Bash 3+, Helm v3.14+/v4, kubectl 1.31+, Terraform 1.5+, `hetznercloud/hcloud` provider, k3s v1.31.3+k3s1, cloud-init.

**Spec:** `docs/superpowers/specs/2026-05-14-kobe-on-hetzner-demo-design.md`

**Worktree:** All work happens in `.worktrees/hetzner-demo/` on branch `feat/hetzner-demo`. Paths in this plan are relative to the worktree root unless absolute.

**Testing strategy:** This is shell + Terraform + Helm — not a TDD codebase. The "test gates" are:
- `bash -n <script>` (syntax check)
- `helm lint <chart-path> -f <values>` (chart well-formed)
- `helm template <release> <chart-path> -f <values> --set ...` (template renders)
- `terraform fmt -check` and `terraform validate` (HCL well-formed; provider config valid)
- For the refactor, a **parity check**: `helm template` output before vs after the move must be byte-identical (modulo a known set of expected diffs, listed in Task 8).

Each task includes its own validation; commits happen per task or per closely-related task group.

---

## File structure (after this plan)

```
demo/
  _shared/                                                    NEW
    chart/                                                    moved from demo/exoscale/
      Chart.yaml                                              edited: name + description generalised
      values.yaml                                             edited: localPath defaults to false
      templates/{access-policy,cluster-pool,local-path,NOTES.txt}.yaml  moved verbatim
      charts/kobe-0.19.1.tgz                                  moved verbatim
    manifests/
      ubuntu/{00-namespace,10-deployment}.yaml                moved verbatim
    lib.sh                                                    NEW: extracted from exoscale/demo
  exoscale/
    README.md                                                 edited: layout section + new paths
    demo                                                      rewritten: thin lib.sh wrapper
    values.yaml                                               rewritten: SKS overrides only
  hetzner/                                                    NEW
    README.md
    demo
    values.yaml
    terraform/
      .gitignore
      variables.tf
      main.tf
      outputs.tf
      cloud-init.server.yaml.tftpl
      cloud-init.agent.yaml.tftpl
```

---

## Phase 0 — Preflight

### Task 0: Verify environment & tools

**Files:** none (read-only)

- [ ] **Step 1: Confirm worktree state**

```bash
cd /Users/emmanuelmurano/Documents/Work/Zondax/Git/kobe/.worktrees/hetzner-demo
git status
git branch --show-current
git log --oneline -2
```

Expected:
- Clean working tree
- Branch: `feat/hetzner-demo`
- HEAD commit: `7727eb9 docs(specs): design — kobe-on-Hetzner-Cloud demo`
- Parent: `fb46097 feat(demo): self-contained kobe-on-Exoscale-SKS demo (#86)`

- [ ] **Step 2: Verify tools are installed**

```bash
helm version --short      # v3.14+ or v4.x
kubectl version --client --short
yq --version              # any v4.x
terraform version         # 1.5+
bash --version | head -1  # 3+
shellcheck --version      # optional but useful
```

If `terraform` is missing: `brew install terraform`. If `shellcheck` is missing the plan can still run; it's just an extra hint.

- [ ] **Step 3: Take a baseline snapshot of `helm template` output for the existing demo**

```bash
cd demo/exoscale
helm template kobe-demo . \
  --set sshPublicKey="ssh-ed25519 AAAATEMPLATEPLACEHOLDER lint@local" \
  > /tmp/exoscale-template-before.yaml
wc -l /tmp/exoscale-template-before.yaml
cd ../..
```

Expected: ~hundreds of lines written, no errors. This file is the baseline for the Task 8 parity check.

---

## Phase 1 — Extract `_shared/` (chart + manifests)

### Task 1: Create `_shared/` skeleton and move chart files

**Files:**
- Create: `demo/_shared/chart/Chart.yaml`
- Create: `demo/_shared/chart/values.yaml`
- Move: `demo/exoscale/templates/` → `demo/_shared/chart/templates/`
- Move: `demo/exoscale/charts/kobe-0.19.1.tgz` → `demo/_shared/chart/charts/kobe-0.19.1.tgz`

- [ ] **Step 1: Create the skeleton**

```bash
mkdir -p demo/_shared/chart/templates demo/_shared/chart/charts demo/_shared/manifests/ubuntu
```

- [ ] **Step 2: Move templates and tarball (preserving git history with `git mv`)**

```bash
git mv demo/exoscale/templates/access-policy.yaml  demo/_shared/chart/templates/access-policy.yaml
git mv demo/exoscale/templates/cluster-pool.yaml   demo/_shared/chart/templates/cluster-pool.yaml
git mv demo/exoscale/templates/local-path.yaml     demo/_shared/chart/templates/local-path.yaml
git mv demo/exoscale/templates/NOTES.txt           demo/_shared/chart/templates/NOTES.txt
rmdir demo/exoscale/templates
git mv demo/exoscale/charts/kobe-0.19.1.tgz        demo/_shared/chart/charts/kobe-0.19.1.tgz
rmdir demo/exoscale/charts
```

- [ ] **Step 3: Write the shared `Chart.yaml`** (generalised name/description, otherwise identical)

```yaml
apiVersion: v2
name: kobe-demo
description: Self-contained kobe demo umbrella chart (cloud-agnostic).
type: application
version: 0.1.0
appVersion: "0.19.1"
keywords:
  - kobe
  - demo
maintainers:
  - name: Zondax
    url: https://zondax.ch
# The vendored kobe chart .tgz lives in charts/ and is regenerated by
# './demo refresh' when this repo's charts/kobe/ changes. Helm v4 requires
# an explicit dependencies block even for pre-vendored tarballs; the
# `repository: ""` sentinel tells helm not to fetch it.
dependencies:
  - name: kobe
    version: "0.19.1"
    repository: ""
```

Write that to `demo/_shared/chart/Chart.yaml`, then delete the old:

```bash
rm demo/exoscale/Chart.yaml
```

- [ ] **Step 4: Write the shared `values.yaml`** (default-off for `localPath`, otherwise the same surface as today's `demo/exoscale/values.yaml`)

```yaml
# REQUIRED: identity that the kobe operator will accept on its HTTP API.
# Set via: helm install ... --set sshPublicKey="ssh-ed25519 AAA..."
# (`./demo up` auto-reads ~/.ssh/id_ed25519.pub if present and passes it.)
#
# IMPORTANT: kobe operator only accepts Ed25519 keys — RSA is rejected with
# "Unauthorized: only Ed25519 keys are accepted". Generate one with:
#   ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -C "you@example.com"
sshPublicKey: ""

pool:
  name: demo-k3s-small
  size: 2                       # warm-pool target
  minReady: 1
  maxClusters: 3
  ttl: 1h
  maxTtlPerLease: 2h
  maxConcurrentLeases: 5
  k3s:
    version: v1.31.3+k3s1
    servers: 1
    agents: 1

# Default OFF — k3s ships local-path-provisioner already. Clouds whose
# managed k8s doesn't ship a default StorageClass (e.g. Exoscale SKS) flip
# this to true in their cloud-specific values.yaml.
localPath:
  enabled: false
  setAsDefault: false

# Pass-through to the kobe subchart.
kobe:
  replicas: 1                   # demo doesn't need HA
  operatorNamespace: kobe-system
  imagePullSecrets:
    - name: regcred
  kine:
    enabled: false              # k3s pool doesn't need it
  ingress:
    enabled: false              # port-forward in the demo
  serviceMonitor:
    enabled: false              # no Prometheus on a fresh SKS
```

- [ ] **Step 5: Validate the shared chart in isolation**

```bash
helm lint demo/_shared/chart \
  --set sshPublicKey="ssh-ed25519 AAAATEMPLATEPLACEHOLDER lint@local"
```

Expected: `1 chart(s) linted, 0 chart(s) failed`. (Warnings are OK; failures are not.)

- [ ] **Step 6: Commit**

```bash
git add demo/_shared/chart/ demo/exoscale/
git commit -m "refactor(demo): extract umbrella chart to demo/_shared/chart

Moves Chart.yaml, values.yaml, templates/, and the vendored kobe-0.19.1.tgz
to demo/_shared/chart/ so multiple cloud-specific demos can share them.
demo/exoscale/ no longer owns these files; rewiring of demo/exoscale/demo
follows in a later commit.

localPath defaults to enabled=false in the shared chart; Exoscale's
cloud-specific values.yaml will re-enable it."
```

### Task 2: Move `manifests/ubuntu/`

**Files:**
- Move: `demo/exoscale/manifests/ubuntu/00-namespace.yaml` → `demo/_shared/manifests/ubuntu/00-namespace.yaml`
- Move: `demo/exoscale/manifests/ubuntu/10-deployment.yaml` → `demo/_shared/manifests/ubuntu/10-deployment.yaml`

- [ ] **Step 1: Move both files**

```bash
git mv demo/exoscale/manifests/ubuntu/00-namespace.yaml  demo/_shared/manifests/ubuntu/00-namespace.yaml
git mv demo/exoscale/manifests/ubuntu/10-deployment.yaml demo/_shared/manifests/ubuntu/10-deployment.yaml
rmdir demo/exoscale/manifests/ubuntu demo/exoscale/manifests
```

- [ ] **Step 2: Sanity check the YAML still parses**

```bash
yq . demo/_shared/manifests/ubuntu/00-namespace.yaml  >/dev/null
yq . demo/_shared/manifests/ubuntu/10-deployment.yaml >/dev/null
```

Expected: no output, exit 0.

- [ ] **Step 3: Commit**

```bash
git add demo/_shared/manifests/ demo/exoscale/
git commit -m "refactor(demo): move manifests/ubuntu/ to demo/_shared/

cmd_deploy_ubuntu (later commit) will read from demo/_shared/manifests/ubuntu/."
```

---

## Phase 2 — Extract `_shared/lib.sh` and rewire `demo/exoscale/demo`

### Task 3: Write `_shared/lib.sh` (extracted functions, parameterized)

**Files:**
- Create: `demo/_shared/lib.sh`

The extraction rules:
- Functions move verbatim from `demo/exoscale/demo` (pre-refactor lines 30–398).
- `pick_kubeconfig()` becomes parameterized: takes `$KUBECONFIG_GLOB` (caller-set env) instead of hardcoded `exoscale-*-config`.
- Path-relative bits (`charts/kobe-*.tgz`, `manifests/ubuntu/*.yaml`, `helm upgrade --install ... .`) are anchored to `LIB_DIR` so they keep working regardless of the caller's cwd.
- `cmd_up`'s 6 steps + the 5-minute pool-poll loop are unchanged.
- Top-level config defaults (`KOBE_VERSION`, `NAMESPACE`, etc.) live in `lib.sh` so a chart bump is one file.

- [ ] **Step 1: Write the file**

```bash
cat > demo/_shared/lib.sh <<'LIBSH_EOF'
#!/usr/bin/env bash
# Shared library for demo/<cloud>/demo scripts.
#
# Callers MUST set:
#   KUBECONFIG_GLOB         e.g. "exoscale-*-config" or "hetzner-*-config"
# Callers MAY set/override (defaults applied here if unset):
#   KOBE_VERSION, NAMESPACE, RELEASE, POOL, DEFAULT_LEASE_TTL, KOBE_PORT,
#   TLS_PORT, TLS_DIR, SSH_PUBKEY, PULL_SECRET_NAME, DOCKER_REGISTRY,
#   DOCKER_HUB_EMAIL, KOBE_REPO.
# Callers MAY define extra cmd_* functions (e.g. cmd_tf_up) and an extra
# `dispatch_extra` function; lib_dispatch tries those before failing.

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
LIBSH_EOF
chmod +x demo/_shared/lib.sh
```

- [ ] **Step 2: Syntax-check the script**

```bash
bash -n demo/_shared/lib.sh
```

Expected: no output, exit 0.

- [ ] **Step 3: Commit**

```bash
git add demo/_shared/lib.sh
git commit -m "feat(demo): add demo/_shared/lib.sh

Shared bash library that holds every cloud-agnostic ./demo verb
(up, down, lease, release, deploy-ubuntu, forward, tunnel,
patch-lease, status, pull-secret, refresh, lint, template).

Parameterized via env vars: KUBECONFIG_GLOB is required; the rest
have sane defaults. Paths anchor on the lib.sh location (LIB_DIR)
so caller cwd doesn't matter. Provides lib_dispatch which routes
verbs, calling dispatch_extra first if defined so cloud-specific
scripts can add their own verbs (e.g. Hetzner's tf up/down)."
```

### Task 4: Rewrite `demo/exoscale/demo` as a thin wrapper

**Files:**
- Modify (rewrite): `demo/exoscale/demo`

- [ ] **Step 1: Rewrite the script**

```bash
cat > demo/exoscale/demo <<'DEMO_EOF'
#!/usr/bin/env bash
# Orchestrates the kobe-on-Exoscale-SKS demo end-to-end.
# Subcommands: see ./demo help
set -euo pipefail

CLOUD_DIR="$(cd "$(dirname "$0")" && pwd)"
KUBECONFIG_GLOB="exoscale-*-config"

# shellcheck source=../_shared/lib.sh
source "$CLOUD_DIR/../_shared/lib.sh"

lib_dispatch "$@"
DEMO_EOF
chmod +x demo/exoscale/demo
```

- [ ] **Step 2: Verify**

```bash
bash -n demo/exoscale/demo
demo/exoscale/demo help | head -20
```

Expected: help text printed by `lib_usage`, no syntax errors.

- [ ] **Step 3: Commit**

```bash
git add demo/exoscale/demo
git commit -m "refactor(demo/exoscale): rewrite ./demo as thin _shared/lib.sh wrapper

All verb implementations now live in demo/_shared/lib.sh. Exoscale's
./demo just sets KUBECONFIG_GLOB='exoscale-*-config' and calls
lib_dispatch."
```

### Task 5: Slim `demo/exoscale/values.yaml` to SKS-only overrides

**Files:**
- Modify (rewrite): `demo/exoscale/values.yaml`

- [ ] **Step 1: Write the slimmed file**

```yaml
# Exoscale SKS-specific overrides on top of demo/_shared/chart/values.yaml.
# SKS doesn't ship a default StorageClass, so install Rancher's
# local-path-provisioner and mark it default.
localPath:
  enabled: true
  setAsDefault: true
```

Write that to `demo/exoscale/values.yaml`.

- [ ] **Step 2: Commit**

```bash
git add demo/exoscale/values.yaml
git commit -m "refactor(demo/exoscale): slim values.yaml to SKS-only overrides

Shared defaults now live in demo/_shared/chart/values.yaml. This file
only carries the SKS-specific bit: enabling Rancher local-path-provisioner
because SKS doesn't ship a default StorageClass."
```

### Task 6: Update `demo/exoscale/README.md` for the new layout

**Files:**
- Modify: `demo/exoscale/README.md` (Layout section only)

- [ ] **Step 1: Replace the Layout section**

Open `demo/exoscale/README.md`. Find the section beginning `## Layout` and the code fence that follows. Replace the whole fence (lines 110–127 in the current file) with this fence:

```
demo/
├── _shared/                       # cloud-agnostic chart + helpers (see ../_shared/)
│   ├── chart/                     # umbrella chart (Chart.yaml, values.yaml, templates/, charts/)
│   ├── manifests/ubuntu/          # demo workload manifests
│   └── lib.sh                     # all ./demo verb implementations
└── exoscale/
    ├── demo                       # thin wrapper: sets KUBECONFIG_GLOB and calls lib_dispatch
    ├── values.yaml                # SKS-specific overrides (localPath.enabled=true)
    └── README.md
```

Also: anywhere the README mentions `charts/kobe-0.19.1.tgz` as a *path the user touches*, change it to `../_shared/chart/charts/kobe-0.19.1.tgz`. (Line 97 troubleshooting bullet and line 88 in the "Bumping kobe" section.) The text in the walkthrough that just says `charts/kobe-0.19.1.tgz` inside narrative is fine to leave with the prefix added for clarity.

- [ ] **Step 2: Smoke-check**

```bash
grep -n 'charts/kobe-0.19.1.tgz' demo/exoscale/README.md
```

Each match should reference the path under `_shared/chart/` (or be absent — if a sentence used the path purely to name a file conceptually it can stay).

- [ ] **Step 3: Commit**

```bash
git add demo/exoscale/README.md
git commit -m "docs(demo/exoscale): update layout section + chart paths for _shared/ split"
```

### Task 7: Parity check — `helm template` and `./demo lint` must succeed and match baseline

**Files:** none (validation only)

The shared-chart refactor moves files but should NOT change rendered output. We compare against the baseline from Task 0 Step 3.

- [ ] **Step 1: Render the new layout**

```bash
cd demo/exoscale
./demo template > /tmp/exoscale-template-after.yaml
cd ../..
```

Expected: exits 0; output file populated.

- [ ] **Step 2: Diff against the baseline**

```bash
diff /tmp/exoscale-template-before.yaml /tmp/exoscale-template-after.yaml | head -80
```

Expected diff: ONLY the kobe operator's own `values.yaml`-derived defaults. Specifically, two known-acceptable categories:

1. **None** is the goal. The Exoscale values.yaml override re-enables `localPath` (matching old behavior), and every other value is inherited from `_shared/chart/values.yaml` which carries the same defaults as the old `demo/exoscale/values.yaml`. → Expect zero diff.

If the diff is non-empty:
- Inspect each block and identify the value that drifted.
- Most likely cause: a default in `demo/_shared/chart/values.yaml` differs from the pre-refactor `demo/exoscale/values.yaml`. Fix by editing the shared default or the Exoscale override.
- Re-run Step 1+2 until the diff is empty (or only contains a documented expected change).

- [ ] **Step 3: `./demo lint`**

```bash
cd demo/exoscale
./demo lint
cd ../..
```

Expected: `1 chart(s) linted, 0 chart(s) failed`.

- [ ] **Step 4: Commit (only if Task 7 fixed values to achieve parity; otherwise nothing to commit)**

```bash
git status
# If clean, skip. If files changed to fix parity:
git add demo/_shared/chart/values.yaml demo/exoscale/values.yaml
git commit -m "fix(demo/_shared): align shared chart defaults with pre-refactor SKS behavior"
```

---

## Phase 3 — Hetzner skeleton (no Terraform yet)

### Task 8: Create `demo/hetzner/` skeleton + `values.yaml`

**Files:**
- Create: `demo/hetzner/values.yaml`
- Create: `demo/hetzner/terraform/.gitignore`

- [ ] **Step 1: Create dirs**

```bash
mkdir -p demo/hetzner/terraform
```

- [ ] **Step 2: Write `demo/hetzner/values.yaml`**

```yaml
# Hetzner Cloud-specific overrides on top of demo/_shared/chart/values.yaml.
# k3s ships local-path-provisioner as the default StorageClass already; do
# not install Rancher's copy on top.
localPath:
  enabled: false
  setAsDefault: false
```

- [ ] **Step 3: Write `demo/hetzner/terraform/.gitignore`**

```gitignore
# Local Terraform state — contains the k3s join token (sensitive).
*.tfstate
*.tfstate.*
.terraform/
.terraform.lock.hcl   # remove this line if you want to commit the lock file for reproducibility
# Local overrides
terraform.tfvars
*.auto.tfvars
```

Actually — per spec §10, we DO want to commit `.terraform.lock.hcl` for reproducibility. Correct the file:

```gitignore
# Local Terraform state — contains the k3s join token (sensitive).
*.tfstate
*.tfstate.*
.terraform/
# Local overrides
terraform.tfvars
*.auto.tfvars
# Note: .terraform.lock.hcl IS committed (provider-version reproducibility).
```

Write that final version to `demo/hetzner/terraform/.gitignore`.

- [ ] **Step 4: Commit**

```bash
git add demo/hetzner/values.yaml demo/hetzner/terraform/.gitignore
git commit -m "feat(demo/hetzner): add skeleton values.yaml + terraform/.gitignore

values.yaml overrides localPath.enabled=false (k3s ships local-path as
the default StorageClass). .gitignore keeps local terraform state out
of git but DOES commit .terraform.lock.hcl for provider pinning."
```

---

## Phase 4 — Terraform module

### Task 9: Write `terraform/variables.tf`

**Files:**
- Create: `demo/hetzner/terraform/variables.tf`

- [ ] **Step 1: Write the file**

```hcl
variable "name" {
  description = "Prefix for all Hetzner Cloud resources and the local kubeconfig filename."
  type        = string
  default     = "kobe-demo"
}

variable "location" {
  description = "Hetzner Cloud datacenter (nbg1=Nuremberg, fsn1=Falkenstein, hel1=Helsinki, ash=Ashburn, hil=Hillsboro)."
  type        = string
  default     = "nbg1"
}

variable "server_type" {
  description = "Hetzner Cloud server type. cx22 = 2 vCPU / 4 GB / ~4 EUR/mo, enough for the demo."
  type        = string
  default     = "cx22"
}

variable "node_count" {
  description = "Total k3s nodes. 1 = single-node (server only). >1 = 1 server + (node_count - 1) agents."
  type        = number
  default     = 1
  validation {
    condition     = var.node_count >= 1
    error_message = "node_count must be at least 1."
  }
}

variable "ssh_public_key_path" {
  description = "Path to the Ed25519 SSH public key authorized on the VM. Same key the kobe AccessPolicy expects."
  type        = string
  default     = "~/.ssh/id_ed25519.pub"
}

variable "k3s_version" {
  description = "k3s release channel/tag (INSTALL_K3S_VERSION). Matches the demo pool's inner k3s."
  type        = string
  default     = "v1.31.3+k3s1"
}

variable "allowed_api_cidr" {
  description = "CIDR allowed on ports 22 + 6443. Empty = auto-detect caller's public IP via icanhazip.com. Set to \"0.0.0.0/0\" for public access (NOT recommended)."
  type        = string
  default     = ""
}
```

- [ ] **Step 2: `terraform fmt`**

```bash
terraform -chdir=demo/hetzner/terraform fmt
```

Expected: no output (file already formatted) or a single filename printed.

- [ ] **Step 3: Commit**

```bash
git add demo/hetzner/terraform/variables.tf
git commit -m "feat(demo/hetzner): add terraform variables"
```

### Task 10: Write `terraform/main.tf` — providers, ssh key, network, firewall, token

**Files:**
- Create: `demo/hetzner/terraform/main.tf`

This is the bulk of the terraform. Servers and the kubeconfig-fetch resource come in subsequent tasks; this one establishes the supporting infra.

- [ ] **Step 1: Write the file**

```hcl
terraform {
  required_version = ">= 1.5.0"
  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.48"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    http = {
      source  = "hashicorp/http"
      version = "~> 3.4"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2"
    }
  }
}

provider "hcloud" {
  # HCLOUD_TOKEN env var is read automatically.
}

# Auto-detect caller's public IP unless allowed_api_cidr is set explicitly.
data "http" "my_ip" {
  count = var.allowed_api_cidr == "" ? 1 : 0
  url   = "https://icanhazip.com"
}

locals {
  api_cidr = var.allowed_api_cidr != "" ? var.allowed_api_cidr : "${trimspace(data.http.my_ip[0].response_body)}/32"
}

resource "hcloud_ssh_key" "demo" {
  name       = "${var.name}-key"
  public_key = file(pathexpand(var.ssh_public_key_path))
}

# Shared k3s token: server installs as the cluster secret; agents present it to join.
resource "random_password" "k3s_token" {
  length  = 32
  special = false
}

# Private network so agents can reach the server on a stable internal IP.
resource "hcloud_network" "demo" {
  name     = "${var.name}-net"
  ip_range = "10.0.0.0/16"
}

resource "hcloud_network_subnet" "demo" {
  network_id   = hcloud_network.demo.id
  type         = "cloud"
  network_zone = "eu-central"
  ip_range     = "10.0.1.0/24"
}

resource "hcloud_firewall" "demo" {
  name = "${var.name}-fw"

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "22"
    source_ips = [local.api_cidr]
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "6443"
    source_ips = [local.api_cidr]
  }

  # ICMP for diagnostics
  rule {
    direction  = "in"
    protocol   = "icmp"
    source_ips = [local.api_cidr]
  }
}
```

> **Note:** `network_zone = "eu-central"` covers `nbg1`/`fsn1`/`hel1`. If you change `var.location` to `ash` or `hil`, also change this to `us-east`/`us-west` respectively. We hardcode `eu-central` because the default location is `nbg1`; documented in the README.

- [ ] **Step 2: `terraform fmt` and `init`**

```bash
terraform -chdir=demo/hetzner/terraform fmt
terraform -chdir=demo/hetzner/terraform init
```

Expected: providers downloaded, `.terraform.lock.hcl` written.

- [ ] **Step 3: `terraform validate`**

```bash
terraform -chdir=demo/hetzner/terraform validate
```

Expected: `Success! The configuration is valid.` (Warnings about server/agent referencing not-yet-defined resources are not yet possible — those go in the next task.)

- [ ] **Step 4: Commit**

```bash
git add demo/hetzner/terraform/main.tf demo/hetzner/terraform/.terraform.lock.hcl
git commit -m "feat(demo/hetzner): terraform - provider, ssh key, network, firewall, token

Establishes the supporting infra: hcloud + random + http + null providers,
hcloud_ssh_key from ~/.ssh/id_ed25519.pub, hcloud_network 10.0.0.0/16
with one eu-central subnet, hcloud_firewall locking 22+6443 to the
caller's auto-detected /32 (override via var.allowed_api_cidr), and a
random_password as the k3s join token."
```

### Task 11: Write cloud-init templates

**Files:**
- Create: `demo/hetzner/terraform/cloud-init.server.yaml.tftpl`
- Create: `demo/hetzner/terraform/cloud-init.agent.yaml.tftpl`

- [ ] **Step 1: Write the server template**

```yaml
#cloud-config
# k3s server bootstrap. package_update intentionally skipped: the k3s
# install script is self-contained and apt-update would cost ~60s of demo
# wall time. If your image needs upgrades, do them out of band.
package_update: false
runcmd:
  - |
    curl -sfL https://get.k3s.io | \
      INSTALL_K3S_VERSION=${k3s_version} \
      K3S_TOKEN=${k3s_token} \
      sh -s - server \
        --write-kubeconfig-mode=644 \
        --tls-san=${server_public_ip} \
        --node-external-ip=${server_public_ip} \
        --disable=traefik
```

- [ ] **Step 2: Write the agent template**

```yaml
#cloud-config
package_update: false
runcmd:
  - |
    curl -sfL https://get.k3s.io | \
      INSTALL_K3S_VERSION=${k3s_version} \
      K3S_URL=https://${server_private_ip}:6443 \
      K3S_TOKEN=${k3s_token} \
      sh -
```

- [ ] **Step 3: Commit**

```bash
git add demo/hetzner/terraform/cloud-init.server.yaml.tftpl demo/hetzner/terraform/cloud-init.agent.yaml.tftpl
git commit -m "feat(demo/hetzner): terraform cloud-init templates for k3s server/agent

Server: installs k3s with --tls-san on the public IP (so kubeconfig with
the public address passes TLS), --disable=traefik (demo doesn't need
ingress), --write-kubeconfig-mode=644 (so non-root scp can read it).
Agent: joins via private network IP using the shared token."
```

### Task 12: Add `hcloud_server` resources for k3s server + agents

**Files:**
- Modify: `demo/hetzner/terraform/main.tf` (append)

- [ ] **Step 1: Append to `main.tf`**

```hcl
# --- k3s server (count = 1) --------------------------------------------------
resource "hcloud_server" "k3s_server" {
  count = 1

  name        = "${var.name}-server"
  server_type = var.server_type
  image       = "ubuntu-24.04"
  location    = var.location

  ssh_keys     = [hcloud_ssh_key.demo.id]
  firewall_ids = [hcloud_firewall.demo.id]

  network {
    network_id = hcloud_network.demo.id
    ip         = "10.0.1.10"
  }

  user_data = templatefile("${path.module}/cloud-init.server.yaml.tftpl", {
    k3s_version      = var.k3s_version
    k3s_token        = random_password.k3s_token.result
    server_public_ip = "PLACEHOLDER_SELF_REFERENCE"
  })

  depends_on = [hcloud_network_subnet.demo]

  lifecycle {
    # user_data changes here would force a destroy/recreate. The server_public_ip
    # is the server's own assigned address, which we can't reference inside the
    # same resource without a cycle. We write the IP into the kubeconfig at
    # fetch time instead of into the kubelet cert. Keeping --tls-san on a
    # placeholder string would break TLS though; see the null_resource below
    # which patches the cert after the fact (Task 13).
    ignore_changes = [user_data]
  }
}

# --- k3s agents (count = node_count - 1) -------------------------------------
resource "hcloud_server" "k3s_agent" {
  count = var.node_count - 1

  name        = "${var.name}-agent-${count.index + 1}"
  server_type = var.server_type
  image       = "ubuntu-24.04"
  location    = var.location

  ssh_keys     = [hcloud_ssh_key.demo.id]
  firewall_ids = [hcloud_firewall.demo.id]

  network {
    network_id = hcloud_network.demo.id
    ip         = "10.0.1.${20 + count.index}"
  }

  user_data = templatefile("${path.module}/cloud-init.agent.yaml.tftpl", {
    k3s_version       = var.k3s_version
    k3s_token         = random_password.k3s_token.result
    server_private_ip = hcloud_server.k3s_server[0].network[*].ip[0]
  })

  depends_on = [hcloud_server.k3s_server]
}
```

> **Self-reference problem:** k3s needs `--tls-san=<public-ip>` so the cert signs the public address. But the public IP is assigned by Hetzner *after* the server is created — we can't reference it inside the same resource's `user_data` without a cycle. Two clean solutions exist:
>
> 1. **Use a `null_resource` with `remote-exec` after the server is up:** rerun the k3s install with the now-known public IP as a `--tls-san`. Costs ~30s.
> 2. **Skip `--tls-san` in cloud-init and patch the kubeconfig instead:** set `insecure-skip-tls-verify: true` on the cluster entry in the local kubeconfig. Simpler, slightly less hygienic.
>
> **We pick (2)** — it matches what the Exoscale demo already does for leased clusters via `patch_lease_kubeconfig`. The trade-off is documented in the README ("the local kubeconfig skips TLS verify; the connection still hits a private firewall'd 6443").
>
> Update the server cloud-init template to drop `--tls-san` and `--node-external-ip`:

- [ ] **Step 2: Simplify the server template (drop SAN/external-ip)**

Edit `demo/hetzner/terraform/cloud-init.server.yaml.tftpl`:

```yaml
#cloud-config
package_update: false
runcmd:
  - |
    curl -sfL https://get.k3s.io | \
      INSTALL_K3S_VERSION=${k3s_version} \
      K3S_TOKEN=${k3s_token} \
      sh -s - server \
        --write-kubeconfig-mode=644 \
        --disable=traefik
```

And drop the now-unused `server_public_ip` from the `templatefile()` call. Edit `main.tf` accordingly — replace the `templatefile(...)` block for the server with:

```hcl
  user_data = templatefile("${path.module}/cloud-init.server.yaml.tftpl", {
    k3s_version = var.k3s_version
    k3s_token   = random_password.k3s_token.result
  })
```

And drop the `lifecycle { ignore_changes = [user_data] }` block (no longer needed).

- [ ] **Step 3: `terraform fmt` + `validate`**

```bash
terraform -chdir=demo/hetzner/terraform fmt
terraform -chdir=demo/hetzner/terraform validate
```

Expected: `Success! The configuration is valid.`

- [ ] **Step 4: Commit**

```bash
git add demo/hetzner/terraform/main.tf demo/hetzner/terraform/cloud-init.server.yaml.tftpl
git commit -m "feat(demo/hetzner): terraform hcloud_server resources for k3s

One k3s server (always present), zero-to-many k3s agents based on
var.node_count. Server cert deliberately does not include the public IP
as a SAN — the kubeconfig fetcher (next commit) marks the cluster
insecure-skip-tls-verify, matching how the existing demo handles leased
clusters. Documented in the README."
```

### Task 13: Add `null_resource.fetch_kubeconfig`

**Files:**
- Modify: `demo/hetzner/terraform/main.tf` (append)

- [ ] **Step 1: Append to `main.tf`**

```hcl
# --- Fetch kubeconfig from server to local ~/.kube/hetzner-<name>-config -----
# Polls SSH up to ~3 min, scp's the k3s kubeconfig, and rewrites:
#   - 127.0.0.1 → <public-ip>
#   - cluster.insecure-skip-tls-verify: true (server cert doesn't include the
#     public IP; firewall already restricts 6443 to caller IP).
resource "null_resource" "fetch_kubeconfig" {
  triggers = {
    server_id  = hcloud_server.k3s_server[0].id
    public_ip  = hcloud_server.k3s_server[0].ipv4_address
    config_out = pathexpand("~/.kube/hetzner-${var.name}-config")
  }

  provisioner "local-exec" {
    interpreter = ["bash", "-c"]
    command     = <<-EOT
      set -euo pipefail
      IP="${self.triggers.public_ip}"
      OUT="${self.triggers.config_out}"
      echo "Waiting for SSH on $IP (up to 180s)..."
      for i in $(seq 1 60); do
        if ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
               -o ConnectTimeout=3 root@"$IP" 'exit 0' 2>/dev/null; then
          echo "SSH ready (attempt $i)."
          break
        fi
        sleep 3
      done

      echo "Waiting for /etc/rancher/k3s/k3s.yaml on $IP (up to 180s)..."
      for i in $(seq 1 60); do
        if ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
               root@"$IP" 'test -f /etc/rancher/k3s/k3s.yaml' 2>/dev/null; then
          echo "k3s kubeconfig present (attempt $i)."
          break
        fi
        sleep 3
      done

      mkdir -p "$(dirname "$OUT")"
      ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
          root@"$IP" 'cat /etc/rancher/k3s/k3s.yaml' \
        | sed "s|127.0.0.1|$IP|" \
        | yq '.clusters[].cluster."insecure-skip-tls-verify" = true' \
        > "$OUT"
      chmod 0600 "$OUT"
      echo "Wrote $OUT"
    EOT
  }

  provisioner "local-exec" {
    when    = destroy
    command = "rm -f ${self.triggers.config_out}"
  }

  depends_on = [hcloud_server.k3s_server]
}
```

- [ ] **Step 2: `terraform fmt` + `validate`**

```bash
terraform -chdir=demo/hetzner/terraform fmt
terraform -chdir=demo/hetzner/terraform validate
```

Expected: `Success! The configuration is valid.`

- [ ] **Step 3: Commit**

```bash
git add demo/hetzner/terraform/main.tf
git commit -m "feat(demo/hetzner): terraform null_resource to fetch + patch kubeconfig

After the k3s server is up, scp /etc/rancher/k3s/k3s.yaml, rewrite the
server URL to the public IP, mark insecure-skip-tls-verify, and write
to ~/.kube/hetzner-\${name}-config (mode 0600). A destroy-time
provisioner removes the kubeconfig when terraform destroy runs."
```

### Task 14: Write `terraform/outputs.tf`

**Files:**
- Create: `demo/hetzner/terraform/outputs.tf`

- [ ] **Step 1: Write the file**

```hcl
output "server_ip" {
  description = "Public IPv4 of the k3s server."
  value       = hcloud_server.k3s_server[0].ipv4_address
}

output "agent_ips" {
  description = "Public IPv4s of k3s agents (empty if node_count = 1)."
  value       = hcloud_server.k3s_agent[*].ipv4_address
}

output "kubeconfig_path" {
  description = "Local path where the cluster kubeconfig was written."
  value       = pathexpand("~/.kube/hetzner-${var.name}-config")
}

output "ssh_command" {
  description = "Convenience SSH command to the k3s server."
  value       = "ssh root@${hcloud_server.k3s_server[0].ipv4_address}"
}

output "join_token" {
  description = "k3s shared token. Already in state; surfaced for debugging multi-node joins."
  value       = nonsensitive(random_password.k3s_token.result)
}
```

- [ ] **Step 2: `terraform fmt` + `validate`**

```bash
terraform -chdir=demo/hetzner/terraform fmt
terraform -chdir=demo/hetzner/terraform validate
```

Expected: `Success! The configuration is valid.`

- [ ] **Step 3: Commit**

```bash
git add demo/hetzner/terraform/outputs.tf
git commit -m "feat(demo/hetzner): terraform outputs - server IP, kubeconfig path, ssh, token"
```

---

## Phase 5 — Wire `./demo` tf verbs

### Task 15: Write `demo/hetzner/demo`

**Files:**
- Create: `demo/hetzner/demo`

- [ ] **Step 1: Write the script**

```bash
cat > demo/hetzner/demo <<'DEMO_EOF'
#!/usr/bin/env bash
# Orchestrates the kobe-on-Hetzner-Cloud demo end-to-end.
# Subcommands:
#   tf up | tf down | tf output     (Hetzner-specific — terraform wrappers)
#   up | down | lease | release | deploy-ubuntu | forward | tunnel |
#   patch-lease | status | pull-secret | refresh | lint | template
# Run ./demo help for full usage.
set -euo pipefail

CLOUD_DIR="$(cd "$(dirname "$0")" && pwd)"
KUBECONFIG_GLOB="hetzner-*-config"
TF_DIR="$CLOUD_DIR/terraform"

# shellcheck source=../_shared/lib.sh
source "$CLOUD_DIR/../_shared/lib.sh"

# --- Hetzner-specific verbs --------------------------------------------------
cmd_tf_up() {
  step "Terraform up - provision Hetzner k3s cluster"
  [[ -n "${HCLOUD_TOKEN:-}" ]] || err "HCLOUD_TOKEN env var not set.
       Generate one at https://console.hetzner.cloud/projects → Security → API Tokens
       (Read & Write), then: export HCLOUD_TOKEN=..."
  command -v terraform >/dev/null 2>&1 || err "terraform not installed (brew install terraform)."
  local key_path="${TF_SSH_PUBLIC_KEY_PATH:-$HOME/.ssh/id_ed25519.pub}"
  [[ -f "$key_path" ]] || err "SSH public key not found at $key_path.
       Generate one: ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -C \"you@example.com\""

  step "terraform init"
  cmd terraform -chdir="$TF_DIR" init -upgrade

  step "terraform apply"
  cmd terraform -chdir="$TF_DIR" apply -auto-approve

  step "Outputs"
  cmd terraform -chdir="$TF_DIR" output
  bold "Done. Next:"
  echo "  export HCLOUD_TOKEN=...                         # already set"
  echo "  ./demo pull-secret <docker-user> <docker-pat>   # one-time per cluster"
  echo "  ./demo up                                       # helm install"
  echo "  ./demo tunnel                                   # terminal B"
}

cmd_tf_down() {
  step "Terraform down - destroy Hetzner k3s cluster"
  [[ -n "${HCLOUD_TOKEN:-}" ]] || err "HCLOUD_TOKEN env var not set."

  # Warn if helm release is still installed.
  if [[ -f "$HOME/.kube/hetzner-kobe-demo-config" ]]; then
    if KUBECONFIG="$HOME/.kube/hetzner-kobe-demo-config" \
       helm -n "$NAMESPACE" list -q 2>/dev/null | grep -qx "$RELEASE"; then
      note "Helm release '$RELEASE' is still installed. Run './demo down' first,"
      note "or pass --force to destroy infra anyway (helm cleanup will be skipped)."
      if [[ "${1:-}" != "--force" ]]; then
        err "Aborting. Re-run with --force to override."
      fi
      note "--force given; proceeding with destroy."
    fi
  fi

  cmd terraform -chdir="$TF_DIR" destroy -auto-approve
}

cmd_tf_output() {
  cmd terraform -chdir="$TF_DIR" output
}

# Called by lib_dispatch before its own case statement. Return 0 if handled.
dispatch_extra() {
  case "${1:-}" in
    tf)
      shift
      case "${1:-}" in
        up)      cmd_tf_up ;;
        down)    shift; cmd_tf_down "$@" ;;
        output)  cmd_tf_output ;;
        ""|help) printf "Usage: ./demo tf {up|down|output}\n" ;;
        *) err "Unknown 'tf' subcommand: $1" ;;
      esac
      return 0
      ;;
  esac
  return 1
}

# Extra usage block appended by lib_usage.
usage_extra() {
  cat <<EOF

Hetzner-specific subcommands:
  tf up          terraform init + apply + fetch kubeconfig (~90s)
  tf down        terraform destroy (~30s). Pass --force to skip helm-release check.
  tf output      terraform output (server IP, kubeconfig path, SSH command)

Hetzner env: HCLOUD_TOKEN (required), TF_SSH_PUBLIC_KEY_PATH (default ~/.ssh/id_ed25519.pub)
EOF
}

lib_dispatch "$@"
DEMO_EOF
chmod +x demo/hetzner/demo
```

- [ ] **Step 2: Syntax + help check**

```bash
bash -n demo/hetzner/demo
demo/hetzner/demo help | head -40
```

Expected: help text includes both the shared verbs (from `lib_usage`) AND the Hetzner-specific block (from `usage_extra`). No syntax errors.

- [ ] **Step 3: `./demo lint` should work without any terraform state**

```bash
cd demo/hetzner
./demo lint
cd ../..
```

Expected: `1 chart(s) linted, 0 chart(s) failed`.

- [ ] **Step 4: `./demo template` should render**

```bash
cd demo/hetzner
./demo template > /tmp/hetzner-template.yaml
cd ../..
wc -l /tmp/hetzner-template.yaml
```

Expected: similar line count to `/tmp/exoscale-template-after.yaml` minus the local-path-provisioner block (because Hetzner's values.yaml disables it).

- [ ] **Step 5: Commit**

```bash
git add demo/hetzner/demo
git commit -m "feat(demo/hetzner): add ./demo wrapper with tf up/down/output verbs

Inherits every cloud-agnostic verb from _shared/lib.sh. Adds three
Hetzner-specific verbs (tf up, tf down, tf output) via dispatch_extra.
Fails fast with clear hints if HCLOUD_TOKEN unset, terraform missing,
or ~/.ssh/id_ed25519.pub absent."
```

---

## Phase 6 — Documentation

### Task 16: Write `demo/hetzner/README.md`

**Files:**
- Create: `demo/hetzner/README.md`

- [ ] **Step 1: Write the file**

```markdown
# kobe demo on Hetzner Cloud

Self-contained Helm umbrella chart + Terraform module that:

1. Provisions a small k3s cluster on Hetzner Cloud (single-node by default; multi-node by setting `node_count`).
2. Installs the kobe operator on it, with a `ClusterPool` pre-warming 2 k3s clusters as pods and an `AccessPolicy` that authenticates the kobe HTTP API against your SSH public key.

The whole demo is driven by one script — `./demo` — that narrates each step as it runs. Cloud-agnostic logic lives in [`../_shared/`](../_shared/); this folder contains only Hetzner-specific bits (Terraform + a values override for `localPath`).

## What you get

After `./demo tf up` followed by `./demo up`, your Hetzner project has:

- 1 Hetzner Cloud server (`cx22` by default, ~4 €/mo prorated to ~0.006 €/h).
- 1 private network (`10.0.0.0/16`) and a firewall locking SSH + Kubernetes API to your caller IP.
- k3s `v1.31.3+k3s1` running as the only node.
- `~/.kube/hetzner-kobe-demo-config` — a local kubeconfig pointing at the server's public IP (with `insecure-skip-tls-verify: true`, see "Security model" below).
- After `./demo up`: `kobe-system` namespace with the kobe operator (1 replica), the `demo-ssh` `AccessPolicy`, and the `demo-k3s-small` `ClusterPool` (2 warm k3s clusters as pods, max 3).

## Prerequisites

- `helm` v3.14+ (verified on v4), `kubectl` v1.31+, GNU `bash` v3+, `socat` (for `./demo tunnel`), `yq` (for `./demo deploy-ubuntu`), and `terraform` v1.5+ on your laptop.
- A Hetzner Cloud project + API token (Read & Write) exported as `HCLOUD_TOKEN`.
- An **Ed25519** SSH keypair on disk (`~/.ssh/id_ed25519` by default). The kobe operator rejects RSA keys at AccessPolicy load time.
- The `kobe` CLI installed (`cargo install --path . --bin kobe` from the repo root).
- Docker Hub credentials with read access to the `zondax/kobe-operator` and `zondax/kobe-sync` images (today both are private). See `./demo pull-secret`.

## Walkthrough

```bash
cd demo/hetzner

# One-time
export HCLOUD_TOKEN=...                       # from console.hetzner.cloud

./demo tf up                                  # ~90 s: VM + k3s + kubeconfig
./demo pull-secret <docker-user> <docker-pat> # so cluster can pull zondax/kobe-operator
./demo up                                     # helm install
./demo tunnel                                 # terminal B — keep running

kobe config set demo --endpoint http://localhost:8080 --auth ssh
kobe config use demo
./demo lease                                  # leases a k3s cluster from the pool
KUBECONFIG=<that-path> kubectl get nodes      # works (TLS tunnel)
./demo deploy-ubuntu                          # SSA an ubuntu pod into the lease

./demo release                                # release leases
./demo down                                   # helm uninstall (~5 s)
./demo tf down                                # destroy infra (~30 s) - MANDATORY
```

> ⚠️ **`./demo tf down` is mandatory** to avoid bill drift. The Hetzner server keeps billing as long as it exists.

## Terraform variables (override via `terraform.tfvars` or `-var`)

| Variable | Default | Notes |
|---|---|---|
| `name` | `kobe-demo` | Prefixes all Hetzner resources + the kubeconfig filename. |
| `location` | `nbg1` | Hetzner DC. `fsn1`, `hel1` also work; `ash` / `hil` need a matching `network_zone` change in `main.tf`. |
| `server_type` | `cx22` | 2 vCPU / 4 GB. Step up to `cx32` if you push the pool larger. |
| `node_count` | `1` | 1 = single-node. >1 = 1 server + (n-1) agents. |
| `ssh_public_key_path` | `~/.ssh/id_ed25519.pub` | Same key the kobe AccessPolicy expects. |
| `k3s_version` | `v1.31.3+k3s1` | Match the inner pool's k3s. |
| `allowed_api_cidr` | (auto-detect) | Restricts 22 + 6443 to caller IP. Set to `0.0.0.0/0` for public access (not recommended). |

To use a `terraform.tfvars`:

```hcl
# demo/hetzner/terraform/terraform.tfvars (gitignored)
name             = "demo-emm"
location         = "fsn1"
node_count       = 3
```

## Subcommand reference

Hetzner-specific:

| Command | What it does |
|---|---|
| `./demo tf up` | `terraform init` + `apply` + fetch + patch kubeconfig |
| `./demo tf down` | `terraform destroy` (warns if helm release still installed; `--force` to skip the check) |
| `./demo tf output` | `terraform output` (server IP, kubeconfig path, SSH command, join token) |

Inherited from `_shared/lib.sh` (same as the Exoscale demo):

| Command | What it does |
|---|---|
| `./demo up` | Pick kubeconfig, verify cluster, helm install kobe-demo, wait for pool Ready |
| `./demo forward` | `kubectl port-forward svc/kobe-demo 8080:8080` (HTTP — kobe CLI only) |
| `./demo tunnel` | port-forward + socat TLS terminator on `:8443` (HTTPS — for kubectl/Kunobi against leased clusters) |
| `./demo lease` | `kobe lease demo-k3s-small --ttl 30m` (auto-patches lease kubeconfig to https://localhost:8443) |
| `./demo release [LEASE_ID]` | `kobe release <id>` if id given, else `kobe purge` |
| `./demo deploy-ubuntu [KUBECONFIG]` | Server-side-apply `_shared/manifests/ubuntu/*.yaml` into the leased cluster |
| `./demo status` | `kubectl get clusterpool,clusterinstance,clusterlease` |
| `./demo pull-secret <user> <token>` | Create `regcred` docker-registry secret in `kobe-system` |
| `./demo down` | `helm uninstall kobe-demo` |
| `./demo refresh` | Re-package `_shared/chart/charts/kobe-X.Y.Z.tgz` from `$KOBE_REPO` |
| `./demo lint`, `./demo template` | Local-only helm checks |

## Security model

The local kubeconfig that Terraform writes (`~/.kube/hetzner-${name}-config`) uses **`insecure-skip-tls-verify: true`** on the cluster entry. This is deliberate:

- The k3s server certificate is signed for `127.0.0.1` and internal addresses, not the Hetzner public IP. Adding the public IP as a SAN requires either a chicken-and-egg cloud-init reference (cyclic) or a post-apply `remote-exec` rerun (extra ~30 s of demo wall time).
- 6443 is restricted by `hcloud_firewall` to your caller IP only (auto-detected). Network-level access is gated; TLS verify-skip just means your kubectl doesn't cross-check the cert.
- For a short-lived demo this is fine. If you want a properly-verified cluster, bring your own DNS + cert-manager + a Let's Encrypt server cert.

**Do not commit `terraform.tfstate`** — it contains the k3s join token in cleartext. The `.gitignore` in `terraform/` already excludes it.

## Bumping kobe

```bash
cd demo/hetzner
./demo refresh                          # repackages _shared/chart/charts/kobe-X.Y.Z.tgz
git add ../_shared/chart/charts/
git commit -m "chore(demo): bump vendored kobe chart"
```

If the chart's `Chart.yaml` `version:` bumps, also update `KOBE_VERSION` at the top of `_shared/lib.sh`, `dependencies[0].version` in `_shared/chart/Chart.yaml`, and the chart filename references in this README.

## Troubleshooting

- **`./demo tf up` hangs at "Waiting for SSH":** the firewall is denying your caller IP. Cause: your egress IP changed since terraform plan (e.g. VPN, CGNAT). Re-run `./demo tf up` (terraform will re-detect) or set `var.allowed_api_cidr` explicitly.
- **`./demo up` errors with "No kubeconfigs found (looking for hetzner-*-config)":** the `null_resource.fetch_kubeconfig` didn't run or was destroyed. Run `terraform -chdir=terraform apply -replace=null_resource.fetch_kubeconfig`.
- **`./demo up` errors with `Pull-secret 'regcred' missing`:** run `./demo pull-secret <docker-user> <docker-pat>` first.
- **Pool stays `Pending`:** `kubectl -n kobe-system logs deploy/kobe-demo --tail=200`. Common causes on a fresh k3s: image pull failure (pull-secret), or the pool's k3s-in-pod can't find a StorageClass — but k3s ships `local-path` as default, so this is unusual. Check `kubectl get sc`.
- **`./demo tunnel` dies repeatedly:** Hetzner doesn't have aggressive timeouts like SKS, but `kubectl port-forward` itself is fragile. Re-run.
- **`kobe lease` returns 401 Unauthorized:** confirm your private SSH key matches the public key uploaded to Hetzner AND configured in the AccessPolicy. Override with `KOBE_SSH_KEY=...` if your active key isn't auto-discovered.
- **`kobe lease ...` returns "no SSH auth method configured":** the kobe operator only accepts **Ed25519** SSH keys. Check the operator logs (`kubectl -n kobe-system logs deploy/kobe-demo | grep "only Ed25519"`); if you see RSA keys being skipped, regenerate or override with an Ed25519 key.

## Layout

```
demo/
├── _shared/                       # cloud-agnostic chart + helpers (see ../_shared/)
│   ├── chart/
│   ├── manifests/ubuntu/
│   └── lib.sh
└── hetzner/
    ├── demo                       # thin wrapper: KUBECONFIG_GLOB='hetzner-*-config' + tf verbs
    ├── values.yaml                # localPath.enabled=false (k3s ships it)
    ├── README.md
    └── terraform/
        ├── main.tf
        ├── variables.tf
        ├── outputs.tf
        ├── cloud-init.server.yaml.tftpl
        ├── cloud-init.agent.yaml.tftpl
        └── .gitignore
```

## Out of scope

- HA control plane (`node_count=3` joins agents to a single server, not embedded etcd HA).
- Hetzner Load Balancer for the kobe API (port-forward is the demo path).
- Ingress / TLS / DNS for the kobe API.
- CSI / persistent volumes beyond local-path.
- Prometheus / Grafana.
- Cluster autoscaling.
```

- [ ] **Step 2: Commit**

```bash
git add demo/hetzner/README.md
git commit -m "docs(demo/hetzner): README with walkthrough, variables, security notes"
```

---

## Phase 7 — Final validation

### Task 17: Whole-tree sanity check

**Files:** none (validation only)

- [ ] **Step 1: Shell-script syntax checks**

```bash
bash -n demo/_shared/lib.sh
bash -n demo/exoscale/demo
bash -n demo/hetzner/demo
```

Expected: no output, exit 0 each.

- [ ] **Step 2: Optional shellcheck**

```bash
command -v shellcheck >/dev/null && shellcheck demo/_shared/lib.sh demo/exoscale/demo demo/hetzner/demo || echo "shellcheck not installed; skipped"
```

Address any errors (not warnings). Common harmless warnings: SC2155 (declare and assign separately) — fine to ignore for this style of script.

- [ ] **Step 3: Helm lint both clouds**

```bash
cd demo/exoscale && ./demo lint && cd ../..
cd demo/hetzner  && ./demo lint && cd ../..
```

Expected: `1 chart(s) linted, 0 chart(s) failed` from each.

- [ ] **Step 4: Helm template both clouds**

```bash
cd demo/exoscale && ./demo template > /tmp/exoscale-final.yaml && cd ../..
cd demo/hetzner  && ./demo template > /tmp/hetzner-final.yaml  && cd ../..
diff <(grep -v 'local-path-storage' /tmp/exoscale-final.yaml) /tmp/hetzner-final.yaml | head -40
```

Expected: the two outputs differ only in the local-path-provisioner block (present on Exoscale, absent on Hetzner). Once you strip lines containing `local-path-storage` from the Exoscale output, the rest should match byte-for-byte.

- [ ] **Step 5: Terraform fmt + validate**

```bash
terraform -chdir=demo/hetzner/terraform fmt -check
terraform -chdir=demo/hetzner/terraform validate
```

Expected: `fmt -check` produces no output; `validate` says `Success! The configuration is valid.`

- [ ] **Step 6: Inventory of new and modified files**

```bash
git log --stat origin/main..HEAD
```

Expected: a tidy list of commits, each touching focused files. No surprises like changes outside `demo/`, `docs/superpowers/`.

### Task 18: (Optional, cost-bearing) Manual end-to-end

> **Gate:** Only run this if the user authorizes. Provisions a real Hetzner server (~4 €/mo prorated).

- [ ] **Step 1: Pre-check**

```bash
[[ -n "${HCLOUD_TOKEN:-}" ]] || { echo "set HCLOUD_TOKEN first"; exit 1; }
[[ -f ~/.ssh/id_ed25519.pub ]] || { echo "no ed25519 pubkey"; exit 1; }
```

- [ ] **Step 2: Provision**

```bash
cd demo/hetzner
./demo tf up
```

Expected within ~3 min: terraform apply completes; `~/.kube/hetzner-kobe-demo-config` written; `kubectl --kubeconfig ~/.kube/hetzner-kobe-demo-config get nodes` shows one Ready node.

- [ ] **Step 3: Install kobe**

```bash
./demo pull-secret <docker-user> <docker-pat>
./demo up
```

Expected: helm rolls out; pool reaches `ready >= 1` within ~3 min.

- [ ] **Step 4: Exercise lease/deploy**

In terminal B:

```bash
cd demo/hetzner
./demo tunnel
```

Back in terminal A:

```bash
kobe config set demo --endpoint http://localhost:8080 --auth ssh
kobe config use demo
./demo lease
./demo deploy-ubuntu
```

Expected: lease kubeconfig written; `demo-workloads/demo-ubuntu` pod scheduled inside the leased k3s cluster.

- [ ] **Step 5: Tear down**

```bash
./demo release
./demo down
./demo tf down
hcloud server list 2>/dev/null && echo "or check Hetzner console" || true
```

Expected: nothing prefixed with `kobe-demo-` left in the Hetzner project.

### Task 19: Final commit + push for PR review

- [ ] **Step 1: Verify branch state**

```bash
git log --oneline origin/main..HEAD
```

Expected: a focused list of commits (one per task), spec commit first.

- [ ] **Step 2: Push**

```bash
git push -u origin feat/hetzner-demo
```

- [ ] **Step 3: Open PR** (text suggestion — actual PR creation is user's call)

PR title: `feat(demo): kobe-on-Hetzner-Cloud demo with shared chart + lib.sh`

PR body:

```
## Summary
- Extracts the umbrella chart + bash helpers from demo/exoscale/ into demo/_shared/
  so cloud-specific demos can share them.
- Adds demo/hetzner/ — a Terraform module (hcloud, single CX22 by default, extensible
  to multi-node via var.node_count) plus a thin ./demo wrapper that inherits every
  cloud-agnostic verb from _shared/lib.sh and adds tf up/down/output.
- Demo cost: ~4 €/mo prorated to ~0.006 €/h. ./demo tf down is mandatory.
- Spec: docs/superpowers/specs/2026-05-14-kobe-on-hetzner-demo-design.md

## Test plan
- [x] helm template parity check (Exoscale before vs after extraction): zero diff
- [x] helm lint passes for both demos
- [x] terraform fmt -check + validate clean
- [x] bash -n passes on all three scripts
- [ ] Manual end-to-end on Hetzner (user-gated; see plan Task 18)
```

---

## Self-review notes (filled in during plan writing)

**Spec coverage matrix:**

| Spec section | Implemented by |
|---|---|
| §3 Layout | Tasks 1, 2, 4, 8, 15 (creates every directory listed) |
| §4.1 Variables | Task 9 |
| §4.2 Resources | Tasks 10, 12, 13 |
| §4.3 Outputs | Task 14 |
| §5 Cloud-init | Task 11 + correction in Task 12 |
| §6 lib.sh surface | Task 3 |
| §7 Hetzner verbs | Task 15 |
| §8 Defaults differing from Exoscale | Tasks 1 (shared default), 5 (Exoscale override), 8 (Hetzner override) |
| §9 Walkthrough | Tested in Task 18 (manual) |
| §10 Public-repo safety | Tasks 8 (.gitignore), 16 (README warnings), spec doc itself |
| §11 Error gates | Built into Tasks 3 (lib.sh up/down), 13 (kubeconfig fetch poll), 15 (tf up/down preconditions) |
| §12 Testing | Tasks 7 (parity), 17 (final sanity), 18 (manual e2e) |
| §13 Risks | Refactor break-risk addressed in Tasks 0 (baseline) + 7 (parity diff) |

**Known intentional deviation from spec:**

- Spec §5 cloud-init said `--tls-san=<public-ip>` + `--node-external-ip=<public-ip>`. Task 12 drops both, switching to the simpler "mark kubeconfig insecure-skip-tls-verify" approach (mirrors how the existing demo's `patch_lease_kubeconfig` already handles the same problem for leased clusters). The rationale and security implication are documented in Task 16's README "Security model" section. If this trade-off is unacceptable, replace Task 13's null_resource with a remote-exec rerun of the k3s install that adds the public IP as a `--tls-san` — costs ~30 s of additional wall time on `./demo tf up`.

**Placeholder scan:** No `TBD`, `TODO`, or "implement later" in any code block.

**Type consistency:** Function names (`pick_kubeconfig`, `cmd_up`, etc.) match between lib.sh definition (Task 3) and cloud scripts (Tasks 4, 15). Terraform resource names (`hcloud_server.k3s_server`, `random_password.k3s_token`, `null_resource.fetch_kubeconfig`) used consistently across Tasks 10, 12, 13, 14.

**Ambiguity check:** The `.terraform.lock.hcl` keep-or-ignore question is resolved in Task 8 Step 3 (we keep it; the .gitignore omits it explicitly).
