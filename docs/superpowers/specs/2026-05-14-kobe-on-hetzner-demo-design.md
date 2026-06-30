# kobe-on-Hetzner-Cloud demo — design

**Status:** draft / approved-by-user, pending implementation plan
**Date:** 2026-05-14
**Companion:** existing `demo/exoscale/` (commit `fb46097`, "feat(demo): self-contained kobe-on-Exoscale-SKS demo (#86)")

## 1. Goal

Extend the existing kobe demo so it runs end-to-end on Hetzner Cloud, where there is **no managed Kubernetes offering**. The Exoscale demo assumes a pre-existing SKS cluster; the Hetzner variant must provision its own cluster first, then run the same kobe install / lease / deploy-ubuntu flow on top.

Constraints:

- Public-repo-safe: no secrets in git, no required external accounts beyond a Hetzner API token.
- Reuse as much of the Exoscale demo as is honestly cloud-agnostic.
- Keep the live-narration `./demo` UX (each step prints `==> <what>` and `$ <command>`).
- Small and cheap: a single Hetzner CX22 (~4 €/mo prorated to ~0.006 €/h) is enough.
- Default to single-node, but leave a zero-refactor path to multi-node.

## 2. Decisions (locked during brainstorming)

| Decision | Choice | Rationale |
|---|---|---|
| k8s distribution on Hetzner | **k3s** | Single binary, `curl \| sh` install, ships local-path-provisioner + ServiceLB, fits CX22 easily. |
| Topology | **Single VM, single k3s server**, extensible | kobe pool members are *pods*, not nodes — one node hosts the entire demo. `node_count` variable enables 1-server + (N-1)-agents later without code changes. |
| Reuse strategy | **Factor shared bits into `demo/_shared/`** | Helm chart, manifests, post-cluster bash logic are cloud-agnostic. Each cloud dir keeps only its kubeconfig-discovery glob and (for Hetzner) terraform. |
| Terraform state | **Local, gitignored** | One user, one cluster at a time. No remote backend setup overhead. |
| Orchestration | **Split `./demo tf up` then `./demo up`** | Mirrors the existing live-demo style; failure recovery is per-step. |
| SSH key | **Reuse `~/.ssh/id_ed25519`** | Same Ed25519 key authorized by the kobe AccessPolicy is registered with Hetzner and authorized on the VM. One key end-to-end. |
| Firewall default | **Auto-detect caller IP** (override → `0.0.0.0/0`) | Sane public-repo default. |
| Private network | **Always create `hcloud_network`** | Even at `node_count=1`, so adding agents later requires no refactor. |
| `./demo all` chain | **Out of scope** | YAGNI; trivial to add later. |

## 3. Layout

```
demo/
  _shared/                                 # NEW — extracted from demo/exoscale/
    chart/
      Chart.yaml
      values.yaml                          # cloud-agnostic defaults
      templates/
        access-policy.yaml
        cluster-pool.yaml
        local-path.yaml                    # rendered only when localPath.enabled
        NOTES.txt
      charts/kobe-0.19.1.tgz
    manifests/ubuntu/
      00-namespace.yaml
      10-deployment.yaml
    lib.sh                                 # see §6 for surface

  exoscale/
    README.md                              # trimmed to the SKS-specific story
    demo                                   # thin: glob='exoscale-*-config' + lib.sh
    values.yaml                            # SKS overrides (localPath.enabled=true)

  hetzner/                                 # NEW
    README.md
    demo                                   # adds `tf up/down/output` verbs
    values.yaml                            # Hetzner overrides (localPath.enabled=false)
    terraform/
      main.tf
      variables.tf
      outputs.tf
      cloud-init.server.yaml.tftpl
      cloud-init.agent.yaml.tftpl
      .gitignore                           # *.tfstate*, .terraform/, terraform.tfvars
```

## 4. Terraform module

### 4.1 Variables (`variables.tf`)

| Variable | Default | Purpose |
|---|---|---|
| `name` | `"kobe-demo"` | Prefix for all Hetzner resources and the kubeconfig filename. |
| `location` | `"nbg1"` | Hetzner datacenter (Nuremberg). |
| `server_type` | `"cx22"` | 2 vCPU / 4 GB / ~4 €/mo. |
| `node_count` | `1` | 1 = single-node k3s. >1 = 1 server + (N-1) agents. |
| `ssh_public_key_path` | `"~/.ssh/id_ed25519.pub"` | Ed25519 key authorized on the VM and (typically) on the kobe AccessPolicy. |
| `k3s_version` | `"v1.31.3+k3s1"` | Matches the inner pool's k3s version. |
| `allowed_api_cidr` | `null` (auto-detect via `data.http "icanhazip"`) | Restricts ingress to caller IP. Override to `"0.0.0.0/0"` for portability. |

### 4.2 Resources

| Resource | Notes |
|---|---|
| `hcloud_ssh_key.demo` | Reads `file(var.ssh_public_key_path)`. |
| `random_password.k3s_token` | length=32, special=false. Generated once, persisted in state. |
| `hcloud_network.demo` | `10.0.0.0/16`. |
| `hcloud_network_subnet.demo` | `10.0.1.0/24`, type=`cloud`. |
| `hcloud_firewall.demo` | Inbound: `22/tcp` and `6443/tcp` from `allowed_api_cidr`. Outbound: default-allow. |
| `hcloud_server.k3s_server` (`count=1`) | `user_data = templatefile("cloud-init.server.yaml.tftpl", {...})`. Attached to firewall + network. |
| `hcloud_server.k3s_agent` (`count=var.node_count - 1`) | `user_data = templatefile("cloud-init.agent.yaml.tftpl", {...})`. Depends on server. |
| `hcloud_server_network.*` | Attaches each server to `hcloud_network.demo`. |
| `null_resource.fetch_kubeconfig` | `depends_on=[hcloud_server.k3s_server]`. `local-exec` does: poll port 22 until reachable, `ssh-keyscan` to `~/.ssh/known_hosts`, `scp root@<public-ip>:/etc/rancher/k3s/k3s.yaml -`, `sed 's\|127.0.0.1\|<public-ip>\|'`, write to `~/.kube/hetzner-${name}-config` (mode 0600). |

### 4.3 Outputs (`outputs.tf`)

```hcl
server_ip       = hcloud_server.k3s_server[0].ipv4_address
kubeconfig_path = pathexpand("~/.kube/hetzner-${var.name}-config")
ssh_command     = "ssh root@${hcloud_server.k3s_server[0].ipv4_address}"
join_token      = nonsensitive(random_password.k3s_token.result)   # for debugging multi-node
```

`join_token` marked nonsensitive because (a) it's already in state, (b) the firewall fronts 6443. Documented in README as "do not commit state".

## 5. Cloud-init templates

### 5.1 `cloud-init.server.yaml.tftpl`

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
        --tls-san=${server_public_ip} \
        --node-external-ip=${server_public_ip} \
        --disable=traefik
```

- `--tls-san=<public-ip>` ensures the kubeconfig (which uses the public IP) doesn't fail TLS verification.
- `--node-external-ip` makes the node addressable from outside the private net.
- `--disable=traefik` because the demo doesn't use ingress.
- `package_update: false` avoids ~60 s of `apt update`; the k3s install script is self-contained.

### 5.2 `cloud-init.agent.yaml.tftpl` (only rendered when `node_count > 1`)

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

Agents reach the server via the private network (10.0.1.x); 6443 doesn't need a public firewall hole for them.

## 6. `_shared/lib.sh` surface

Functions extracted verbatim from today's `demo/exoscale/demo` (lines preserved 1:1, then parameterized where needed):

| Function | Parameterization |
|---|---|
| `pick_kubeconfig <glob>` | `glob` argument (was hardcoded `exoscale-*-config`). |
| `step`, `note`, `bold`, `err` | Unchanged. |
| `wait_for_pool_ready` | Unchanged. |
| `tunnel`, `forward` | Unchanged. |
| `lease`, `release`, `patch_lease_kubeconfig`, `pick_leased_kubeconfig` | Unchanged. |
| `deploy_ubuntu` | Unchanged. |
| `pull_secret` | Unchanged. |
| `status` | Unchanged. |
| `refresh_chart` | Path becomes `../_shared/chart/charts/kobe-${KOBE_VERSION}.tgz`. |
| `lint`, `template` | `helm` invoked with `-f ../_shared/chart/values.yaml -f values.yaml` chart path = `../_shared/chart`. |

Each cloud's `./demo` becomes:

```bash
#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SHARED="$HERE/../_shared"
KUBECONFIG_GLOB="hetzner-*-config"        # or "exoscale-*-config"
KOBE_VERSION="0.19.1"
# shellcheck source=../_shared/lib.sh
source "$SHARED/lib.sh"

# Cloud-specific verbs (Hetzner only): tf_up, tf_down, tf_output
# (Exoscale's ./demo has no extras here.)

dispatch "$@"
```

`dispatch` is a small case-block in `lib.sh` that routes to the cloud's local function or to a shared one.

## 7. `./demo` verbs (Hetzner)

| Verb | Behavior |
|---|---|
| `./demo tf up` | `terraform -chdir=terraform init -upgrade` + `apply -auto-approve`. After apply, the `null_resource.fetch_kubeconfig` has already written `~/.kube/hetzner-${name}-config`. Prints SSH command + kubeconfig path. |
| `./demo tf down` | Confirm prompt → `terraform -chdir=terraform destroy -auto-approve` → `rm -f ~/.kube/hetzner-${name}-config`. |
| `./demo tf output` | `terraform -chdir=terraform output`. |
| `./demo up` | `pick_kubeconfig 'hetzner-*-config'` → ensure `regcred` secret → `helm upgrade --install kobe-demo ../_shared/chart -f ../_shared/chart/values.yaml -f values.yaml --set sshPublicKey="$SSH_PUBKEY"` → `wait_for_pool_ready`. |
| `./demo down` | `helm uninstall kobe-demo`. (Does NOT destroy infra — separate step.) |
| `./demo tunnel`, `lease`, `release`, `deploy-ubuntu`, `forward`, `patch-lease`, `pull-secret`, `status`, `refresh`, `lint`, `template`, `help` | Inherited from `_shared/lib.sh`, unchanged. |

## 8. Defaults that differ from Exoscale

| Key | Exoscale | Hetzner | Why |
|---|---|---|---|
| `localPath.enabled` | `true` | `false` | k3s ships local-path-provisioner as the default StorageClass already. |
| Kubeconfig glob | `exoscale-*-config` | `hetzner-*-config` | Disambiguate for users with both clouds. |
| Pull-secret target | `regcred` in `kobe-system` | same | The kobe-operator + kobe-sync images are private Docker Hub repos either way. |
| Pool sizing (`pool.size`, `minReady`, `maxClusters`) | `2 / 1 / 3` | same | One CX22 handles this comfortably. |

## 9. End-to-end walkthrough (README excerpt)

```bash
cd demo/hetzner

export HCLOUD_TOKEN=...                       # one-time

./demo tf up                                  # ~90 s: VM up, k3s up, kubeconfig written
./demo pull-secret <docker-user> <docker-pat> # so cluster can pull zondax/kobe-operator
./demo up                                     # helm install kobe-demo
./demo tunnel                                 # terminal B — keep running

kobe config set demo --endpoint http://localhost:8080 --auth ssh
kobe config use demo
./demo lease                                  # leases a k3s cluster from the pool
./demo deploy-ubuntu                          # SSA an ubuntu pod into the lease
./demo release
./demo down                                   # helm uninstall (~5 s)
./demo tf down                                # destroy infra (~30 s)
```

## 10. Public-repo safety

- `demo/hetzner/terraform/.gitignore` excludes `*.tfstate*`, `*.tfstate.backup`, `.terraform/`, and `terraform.tfvars` (so users can put local overrides without leaking). **`.terraform.lock.hcl` IS committed** for provider-version reproducibility.
- No secrets in TF code. `HCLOUD_TOKEN` from env. SSH key is a **path** to the user's existing public key, never the key material.
- README front-and-centers:
  - **Cost**: ~4 €/mo prorated to ~0.006 €/h for CX22 + free private network + free firewall.
  - **`./demo tf down` is mandatory** to avoid bill drift.
  - **Warning**: `terraform.tfstate` contains the k3s join token — do not commit it.
- Firewall defaults to caller-IP-only (auto-detected via `icanhazip.com`). Override to `0.0.0.0/0` is documented in `variables.tf` and the README, but not the default.

## 11. Error-handling gates

- `./demo tf up`:
  - Fail fast if `HCLOUD_TOKEN` unset.
  - Fail fast if `${ssh_public_key_path}` missing (with hint to `ssh-keygen -t ed25519`).
  - Fail fast if `terraform` binary missing (with hint).
- `./demo up`:
  - Fail clearly if no `hetzner-*-config` found, with the exact hint: `run "./demo tf up" first, then re-run "./demo up"`.
- `./demo tf down`:
  - Detect if `helm list -n kobe-system` shows `kobe-demo` and warn: `helm release still installed — run "./demo down" first, or pass --force to destroy anyway`.
- All `kubectl`/SSH operations have explicit timeouts; the existing 5-minute pool-ready loop from Exoscale is inherited unchanged.
- `null_resource.fetch_kubeconfig` polls port 22 with a 5-minute timeout (cloud-init can take 60–90 s; we want a clear error if it never comes up).

## 12. Testing

- `terraform fmt -check` + `terraform validate` in CI (no `apply` — would burn money).
- `helm lint` and `helm template` against both `demo/exoscale` and `demo/hetzner` to catch regressions from the `_shared/chart` extraction.
- Manual end-to-end happy path: the walkthrough in §9, executed once before merge.
- Manual cleanup-regression: `./demo tf up` → `./demo tf down` → `hcloud server list` shows nothing prefixed with `${name}-`.

## 13. Risks & open questions

| Risk | Mitigation |
|---|---|
| `_shared/` refactor breaks Exoscale demo | `helm template` parity check before/after; manual `./demo up` on SKS once. |
| `icanhazip.com` rate-limited or down | Make the auto-detect best-effort; on failure, error with a clear hint to set `allowed_api_cidr` explicitly. |
| Cloud-init `runcmd` failures invisible to `terraform apply` | `null_resource.fetch_kubeconfig` polls SSH+kubeconfig; surfaces install failure within 5 min with a clear error. |
| k3s API cert TTL (12 months) for long-lived demos | Not in scope — these clusters live <1 day in normal use. Document in README. |
| Public IP exposure for 6443 | Caller-IP-only firewall default. README explicitly notes the production caveats. |

## 14. Out of scope

- Multi-cloud kubeconfig router / unified `./demo --provider X`.
- HA control plane on Hetzner (the variable hook exists; the demo doesn't ship it).
- Hetzner Load Balancer for the kobe API (port-forward is the demo path, same as Exoscale).
- CSI / persistent volumes beyond local-path.
- Ingress / TLS / DNS for kobe API.
- Cluster autoscaling.
- Prometheus / Grafana.
