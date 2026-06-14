# Kobe

**Premium cattle, managed by ninjas.**

Kobe is a Kubernetes operator that manages fleets of ephemeral clusters. It pre-warms pools across multiple backends (k3s, k0s, [vcluster](https://www.vcluster.com/), CAPI) so your CI pipelines and developers get fully functional, isolated Kubernetes clusters instantly — leased via a simple HTTP API.

## Why

| Without Kobe | With Kobe |
|---------------|-----------|
| Spin up Kind/vcluster on demand (~30-360s) | Claim a pre-warmed cluster (<5s) |
| Distribute kubeconfigs or K8s API access | Simple `curl` with a JWT |
| DinD hacks in CI, fragile networking | No Docker needed, just an HTTP call |
| Static secrets to rotate | OIDC, SSH keys, or tokens — zero static secrets |

## Quick Start

```bash
# Create a lease — returns 202 with a Pending lease
curl -X POST https://pool.kunobi.ninja/v1/leases \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"profile": "ci-small", "ttl": "30m"}'
# { "id": "lease-a1b2c3d4e5f6", "phase": "Pending", "profile": "ci-small", "effective_ttl": "30m" }

# Poll until phase=Bound, then read the ready-to-use kubeconfig
curl https://pool.kunobi.ninja/v1/leases/lease-a1b2c3d4e5f6 \
  -H "Authorization: Bearer $TOKEN"
# { "id": "lease-...", "phase": "Bound", "kubeconfig": "apiVersion: v1\n...", "expires_at": "2026-04-09T15:00:00Z" }

# Use it
KUBECONFIG=/tmp/kube.yaml kubectl get nodes

# Release when done (the cluster is destroyed and a fresh one is recycled)
curl -X DELETE https://pool.kunobi.ninja/v1/leases/lease-a1b2c3d4e5f6 \
  -H "Authorization: Bearer $TOKEN"
```

> Prefer the CLI? `kobe login` → `kobe lease ci-small` → `kobe release <lease-id>`. See the [quick start](docs/kobe-docs/getting-started/quick-start.mdx).

## How It Works

Kobe runs as an operator in a host Kubernetes cluster. It maintains warm **pools** of clusters, each defined by a `ClusterPool` (a backend + cluster template with specific configuration, addons, and resource limits).

When a client leases a cluster, Kobe binds one from the warm pool instantly. When released — or on TTL expiry — the cluster is destroyed and a fresh replacement is recycled in the background, so every lease gets a clean, isolated environment.

```
┌──────────────────────────────────┐
│  Host K8s Cluster                │
│                                  │
│  ┌────────────────────────────┐  │
│  │  kobe-operator            │  │
│  │  - Pool management         │  │
│  │  - HTTP API + JWT auth     │  │
│  │  - TTL enforcement         │  │
│  └────────────────────────────┘  │
│                                  │
│  ┌─────┐ ┌─────┐ ┌─────┐       │
│  │vc-1 │ │vc-2 │ │vc-3 │ warm  │
│  └─────┘ └─────┘ └─────┘       │
└──────────────┬───────────────────┘
               │ HTTPS
       ┌───────┼───────┐
       │       │       │
      CI    App     Dev
```

## API

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/v1/leases` | Create a lease from a pool (returns `202` + a `Pending` lease) |
| `GET` | `/v1/leases` | List your active leases |
| `GET` | `/v1/leases/:id` | Get a lease (includes the kubeconfig once `Bound`) |
| `DELETE` | `/v1/leases/:id` | Release a lease |
| `PATCH` | `/v1/leases/:id` | Extend a lease TTL |
| `GET` | `/v1/pools` | List available pools with status |
| `GET` | `/v1/pools/:name` | Get a specific pool's status |
| `GET` | `/v1/status` | Endpoint status + auth methods (no auth required) |

See [docs/kobe-docs/api/reference.mdx](docs/kobe-docs/api/reference.mdx) for full request/response shapes.

## CRDs

Kobe is driven by a small set of CRDs (group `kobe.kunobi.ninja/v1alpha1`):

- **`ClusterPool`** — a pool of warm clusters with a backend, sizing, and default TTL.
- **`ClusterInstance`** — one provisioned cluster, managed by a pool.
- **`ClusterLease`** — binds a requester to an instance (created by the HTTP API, not authored directly).
- **`AccessPolicy`** — who may lease which pools, with TTL / concurrency / extension caps.
- **`KobeStore`** — datastore config for backends that externalize control-plane state.

### ClusterPool

Defines a pool of clusters with a specific backend and configuration:

```yaml
apiVersion: kobe.kunobi.ninja/v1alpha1
kind: ClusterPool
metadata:
  name: ci-small
  namespace: kunobi-pool
spec:
  size: 3                 # warm clusters to keep ready
  ttl: "1h"               # default lease duration
  backend:
    type: k3s             # k3s | k0s | vcluster | capi
  cluster:
    version: "v1.31.3+k3s1"
    servers: 1
  scaling:
    minReady: 0
    maxClusters: 6
    scaleDownAfter: "5m"
    queueTimeout: "5m"
  resources:
    limits:
      cpu: "1"
      memory: "1Gi"
```

### ClusterLease

Created internally by the HTTP API when a caller leases a cluster (not authored by users directly):

```yaml
apiVersion: kobe.kunobi.ninja/v1alpha1
kind: ClusterLease
metadata:
  name: lease-a1b2c3d4e5f6
spec:
  poolRef: ci-small
  ttl: "1h"
  requester:
    type: "github-actions:ci"
    identity: "repo:org/repo:ref:refs/heads/main"
status:
  phase: Bound               # Pending | Bound | Released | Expired | Recycling
  clusterName: pool-ci-small-0
  boundAt: "2026-04-09T14:00:00Z"
  expiresAt: "2026-04-09T15:00:00Z"
```

## Security

- **Authentication:** OIDC, SSH keys (Ed25519 via your agent), and bearer tokens — no long-lived secrets
- **Authorization:** Scoped by identity via `AccessPolicy` — pool access, TTL caps, concurrency limits
- **Kubeconfig:** Short-lived client certificates that expire with the lease TTL
- **Network:** TLS everywhere, rate limiting, optional IP allowlisting

## Built With

- **Rust** — kube-rs for the operator, axum for the HTTP API
- **vcluster** — virtual cluster runtime (via Helm)
- **Flux** — GitOps deployment

## Documentation

See [docs/kobe-docs/](docs/kobe-docs/) for the user-facing documentation site.

## License

Apache-2.0
