# kobe demo on Hetzner Cloud

A Terraform module and a `./demo` script that:

1. Provisions a small k3s cluster on Hetzner Cloud (single-node by default; multi-node by setting `node_count`).
2. Installs the kobe operator on it, with a `ClusterPool` pre-warming 2 k3s clusters as pods and an `AccessPolicy` that authenticates the kobe HTTP API against your SSH public key.

The whole demo is driven by one script — `./demo` — that narrates each step as it runs. It installs the kobe operator from the official chart (`charts/kobe`) with a minimal `values.yaml`, then applies the `ClusterPool` and `AccessPolicy` with `kubectl`. Cloud-agnostic logic lives in [`../_shared/`](../_shared/); this folder contains only the Hetzner-specific bits (the Terraform module).

## What you get

After `./demo tf up` followed by `./demo up`, your Hetzner project has:

- 1 Hetzner Cloud server (`cpx22` by default, prorated hourly).
- 1 private network (`10.0.0.0/16`) and a firewall locking SSH + Kubernetes API to your caller IP.
- k3s `v1.31.3+k3s1` running as the only node.
- `~/.kube/hetzner-kobe-demo-config` — a local kubeconfig pointing at the server's public IP (with `insecure-skip-tls-verify: true`, see "Security model" below).
- After `./demo up`: `kobe-system` namespace with the kobe operator (1 replica), the `demo-ssh` `AccessPolicy`, and the `demo-k3s-small` `ClusterPool` (2 warm k3s clusters as pods, max 3).

## Prerequisites

- `helm` v3.14+ (verified on v4), `kubectl` v1.31+, GNU `bash` v3+, `socat` (for `./demo tunnel`), `yq` (for `./demo up` and `./demo deploy-ubuntu`), and `terraform` v1.5+ **or** OpenTofu v1.6+ (`brew install opentofu`) on your laptop. The `./demo` script auto-detects whichever is on PATH.
- A Hetzner Cloud project + API token (Read & Write) exported as `HCLOUD_TOKEN`.
- An **Ed25519** SSH keypair on disk (`~/.ssh/id_ed25519` by default). The kobe operator rejects RSA keys at AccessPolicy load time.
- The `kobe` CLI installed (`cargo install --path crates/kobectl` from the repo root).

## Walkthrough

```bash
cd demo/hetzner

# One-time
export HCLOUD_TOKEN=...                       # from console.hetzner.cloud

./demo tf up                                  # ~90 s: VM + k3s + kubeconfig
./demo up                                     # helm install + apply CRs
./demo tunnel                                 # terminal B — keep running

kobe config set demo --endpoint http://localhost:8080 --auth ssh
./demo lease                                  # leases a k3s cluster from the pool (target 'demo'; override with KOBE_TARGET)
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
| `server_type` | `cpx22` | 2 vCPU / 4 GB. Step up to `cpx32` if you push the pool larger. |
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
| `./demo up` | Pick kubeconfig, install the kobe chart + apply the ClusterPool/AccessPolicy, wait for pool Ready |
| `./demo forward` | `kubectl port-forward svc/kobe-demo 8080:8080` (HTTP — kobe CLI only) |
| `./demo tunnel` | port-forward + socat TLS terminator on `:8443` (HTTPS — for kubectl/Kunobi against leased clusters) |
| `./demo lease` | `kobe lease demo-k3s-small --ttl 30m` (auto-patches lease kubeconfig to https://localhost:8443) |
| `./demo release [LEASE_ID]` | `kobe release <id>` if id given, else `kobe purge` |
| `./demo deploy-ubuntu [KUBECONFIG]` | Server-side-apply `_shared/manifests/ubuntu/*.yaml` into the leased cluster |
| `./demo status` | `kubectl get clusterpool,clusterinstance,clusterlease` |
| `./demo down` | Delete the CRs + `helm uninstall kobe-demo` |
| `./demo lint`, `./demo template` | Local-only helm checks on the kobe chart |

## Security model

The local kubeconfig that Terraform writes (`~/.kube/hetzner-${name}-config`) uses **`insecure-skip-tls-verify: true`** on the cluster entry. This is deliberate:

- The k3s server certificate is signed for `127.0.0.1` and internal addresses, not the Hetzner public IP. Adding the public IP as a SAN requires either a chicken-and-egg cloud-init reference (cyclic) or a post-apply `remote-exec` rerun (extra ~30 s of demo wall time).
- 6443 is restricted by `hcloud_firewall` to your caller IP only (auto-detected). Network-level access is gated; TLS verify-skip just means your kubectl doesn't cross-check the cert.
- For a short-lived demo this is fine. If you want a properly-verified cluster, bring your own DNS + cert-manager + a Let's Encrypt server cert.

**Do not commit `terraform.tfstate`** — it contains the k3s join token in cleartext. The `.gitignore` in `terraform/` already excludes it.

## Bumping kobe

`./demo up` installs the operator straight from `charts/kobe` in this repo, so the
demo always tracks the chart in your checkout — there is nothing to re-vendor. To
pin a specific operator image, set `image.tag` in `_shared/values.yaml`.

## Troubleshooting

- **`./demo tf up` hangs at "Waiting for SSH":** the firewall is denying your caller IP. Cause: your egress IP changed since terraform plan (e.g. VPN, CGNAT). Re-run `./demo tf up` (terraform will re-detect) or set `var.allowed_api_cidr` explicitly.
- **`./demo up` errors with "No kubeconfigs found (looking for hetzner-*-config)":** the `null_resource.fetch_kubeconfig` didn't run or was destroyed. Run `terraform -chdir=terraform apply -replace=null_resource.fetch_kubeconfig`.
- **Pool stays `Pending`:** `kubectl -n kobe-system logs deploy/kobe-demo --tail=200`. Common cause on a fresh k3s: the pool's k3s-in-pod can't find a StorageClass — but k3s ships `local-path` as default, so this is unusual. Check `kubectl get sc`.
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
