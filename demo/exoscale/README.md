# kobe demo on Exoscale SKS

Self-contained Helm umbrella chart that brings up the kobe operator on a vanilla Exoscale SKS cluster, with a small k3s `ClusterPool` pre-warmed and an `AccessPolicy` that authenticates the kobe HTTP API against your SSH public key.

The whole demo is driven by one script — `./demo` — that narrates each step as it runs.

## What you get

After `./demo up`, the target SKS cluster has:

- `kobe-system` namespace with the kobe operator (1 replica, image `v0.9.1`).
- One `AccessPolicy` named `demo-ssh` accepting your SSH key.
- One `ClusterPool` named `demo-k3s-small` pre-warming **2 k3s clusters** as pods on the SKS worker nodes (1 always Ready, max 3 total). Leasing one takes seconds.
- `local-path-storage` namespace with Rancher's local-path-provisioner installed as the default StorageClass (since SKS doesn't ship one).

## Prerequisites

- `helm` v3.14+ or v4 (verified working on v4.0.4), `kubectl` v1.31+, GNU `bash` v3+, `socat` (for `./demo tunnel`), `yq` (for `./demo deploy-ubuntu`) on your laptop.
- An Exoscale SKS kubeconfig in `~/.kube/exoscale-*-config` (e.g. one downloaded by Kunobi desktop). The script auto-discovers it; you don't `export KUBECONFIG=...` yourself.
- The `kobe` CLI installed (`cargo install --path . --bin kobe` from the repo root).
- An **Ed25519** SSH keypair on disk (`~/.ssh/id_ed25519` by default; override with `SSH_PUBKEY="$(cat /path/to/key.pub)" ./demo up`). The kobe operator rejects RSA keys at AccessPolicy load time.
- Docker Hub credentials with read access to the `zondax/kobe-operator` and `zondax/kobe-sync` images (today both are private). See `./demo pull-secret` below.

## Walkthrough

```bash
cd demo/exoscale

# One-time, on a fresh clone of the kobe repo:
./demo refresh                           # repackages ../_shared/chart/charts/kobe-0.19.1.tgz from this repo
./demo pull-secret <user> <docker-pat>   # so SKS can pull zondax/kobe-operator

# Demo proper (terminal A):
./demo up                                # picks SKS kubeconfig, helm install, wait for Ready

# Terminal B — keep this running for the whole demo:
./demo tunnel                            # port-forward + TLS terminator on :8443

# Back in A — kobe CLI config:
kobe config set demo --endpoint http://localhost:8080 --auth ssh
kobe config use demo

./demo lease                             # leases a k3s cluster, auto-patches kubeconfig to https://localhost:8443
KUBECONFIG=<that-path> kubectl get nodes # works (over the TLS tunnel)
./demo deploy-ubuntu                     # server-side-applies a sandbox ubuntu pod into the leased cluster

./demo release                           # kobe purge: drops all leases + cleans local kubeconfigs
./demo down                              # helm uninstall kobe-demo
```

The `./demo up` flow:
1. Picks the SKS kubeconfig — auto-selected if there's only one in `~/.kube/exoscale-*-config`, otherwise prompts. Inherited `KUBECONFIG` env is ignored unless its basename matches `exoscale-*-config`.
2. `kubectl get nodes` — sanity check the cluster is reachable.
3. Verifies `../_shared/chart/charts/kobe-0.19.1.tgz` is present.
4. Verifies the `regcred` pull-secret exists in `kobe-system` (errors with a clear instruction to run `./demo pull-secret` if missing — avoids silent ImagePullBackOff).
5. `helm upgrade --install kobe-demo .` with your SSH pubkey passed via `--set sshPublicKey=...`.
6. Polls until the kobe Deployment rolls out and the ClusterPool reaches `status.ready >= spec.scaling.minReady` (timeout 5 min).

Each step prints `==> <what>` and `$ <command>` before running, so a live audience can follow along.

## Subcommand reference

| Command | What it does |
|---|---|
| `./demo up` | End-to-end install + wait for pool Ready |
| `./demo forward` | `kubectl port-forward svc/kobe-demo 8080:8080` (HTTP — for kobe CLI only) |
| `./demo tunnel` | port-forward + socat TLS terminator on `:8443` (HTTPS — needed for kubectl/Kunobi against leased clusters; bearer tokens are stripped over plain HTTP by kubectl ≥1.31) |
| `./demo patch-lease [PATH]` | Rewrite a leased kubeconfig's server URL from `http://localhost:8080` to `https://localhost:8443` and add `insecure-skip-tls-verify: true` |
| `./demo pull-secret <user> <token>` | Create a `regcred` docker-registry Secret in `kobe-system` so the cluster can pull `zondax/kobe-operator` |
| `./demo lease` | `kobe lease demo-k3s-small --ttl 30m` (auto-patches the resulting kubeconfig to use `https://localhost:8443`) |
| `./demo release [LEASE_ID]` | `kobe release <id>` if id given, else `kobe purge` (release all) |
| `./demo deploy-ubuntu [KUBECONFIG]` | Server-side-apply `manifests/ubuntu/*.yaml` into the leased cluster via curl (kubectl can't because of the bearer-over-HTTP/TLS-tunnel split). Defaults to the most-recent leased kubeconfig. |
| `./demo status` | `kubectl get clusterpool,clusterinstance,clusterlease` |
| `./demo down` | `helm uninstall kobe-demo` |
| `./demo refresh` | Re-package `charts/kobe-X.Y.Z.tgz` from `$KOBE_REPO` (defaults to repo root) |
| `./demo lint` | `helm lint .` |
| `./demo template` | `helm template .` (local render, no cluster) |
| `./demo help` | Usage |

## Drive it from a UI (e.g. Kunobi desktop)

Any tool that speaks to a kobe API endpoint with `auth: ssh` will see the same pools/instances/leases. Point it at `http://localhost:8080` (the kobe API) with your Ed25519 key configured. With `./demo tunnel` running, kubectl/Lens/k9s can also drive the **leased** cluster via `https://localhost:8443/connect/lease-…` (the tunnel terminates TLS so bearer tokens survive the hop).

## Bumping kobe

```bash
cd demo/exoscale
./demo refresh                          # repackages ../_shared/chart/charts/kobe-X.Y.Z.tgz from this repo
git add ../_shared/chart/charts/
git commit -m "chore(demo): bump vendored kobe chart"
```

If `charts/kobe/Chart.yaml` `version:` bumps, also update `KOBE_VERSION` at the top of `../_shared/lib.sh`, `dependencies[0].version` in `../_shared/chart/Chart.yaml`, and the chart filename references in this README.

## Troubleshooting

- **Vendored chart tarball missing:** run `./demo refresh` first. Expected only if the vendored tarball is somehow absent.
- **Pool stays `Pending`:** `kubectl -n kobe-system logs deploy/kobe --tail=200`. Common causes: image pull failure, missing RBAC for the pool service account, `local-path-provisioner` not Ready (PVCs stuck `Pending`).
- **`kobe lease` returns 401 Unauthorized:** confirm your private SSH key matches the public key in `values.yaml` (or the override). Set `KOBE_SSH_KEY=...` if your active key isn't auto-discovered.
- **Port-forward dies:** SKS has aggressive idle timeouts. Re-run `./demo forward`.
- **`./demo up` errors with "No SKS kubeconfigs found":** drop an Exoscale SKS kubeconfig at `~/.kube/exoscale-*-config` (any tool that fetches one from Exoscale will use that name pattern, including the Exoscale CLI's `exo compute sks kubeconfig` and the Kunobi desktop app).
- **`kobe lease ...` returns "no SSH auth method configured":** the kobe operator only accepts **Ed25519** SSH keys. Check the operator logs (`kubectl -n kobe-system logs deploy/kobe-demo | grep "only Ed25519"`); if you see RSA keys being skipped, regenerate or override with an Ed25519 key:
  ```bash
  ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -C "you@example.com"
  SSH_PUBKEY="$(cat ~/.ssh/id_ed25519.pub)" ./demo up   # re-applies AccessPolicy
  ```

## Layout

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

## Out of scope

- Ingress, TLS, DNS for the kobe API (port-forward is the demo path).
- OIDC / multi-tenant authz (one SSH identity).
- Prometheus / ServiceMonitor / Grafana.
- Automated SKS provisioning. Bring your own SKS via Kunobi desktop.
