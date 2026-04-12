# Kobe

**Premium cattle, managed by ninjas.**

Kobe is a Kubernetes operator that manages fleets of virtual clusters. It pre-warms pools of [vclusters](https://www.vcluster.com/) so your CI pipelines and developers get fully functional Kubernetes clusters instantly — via a simple HTTP API.

## Why

| Without Kobe | With Kobe |
|---------------|-----------|
| Spin up Kind/vcluster on demand (~30-360s) | Claim a pre-warmed cluster (<5s) |
| Distribute kubeconfigs or K8s API access | Simple `curl` with a JWT |
| DinD hacks in CI, fragile networking | No Docker needed, just an HTTP call |
| Static secrets to rotate | GitHub OIDC + Clerk JWTs, zero secrets |

## Quick Start

```bash
# Claim a cluster
curl -X POST https://pool.kunobi.ninja/v1/claims \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"profile": "e2e-basic"}'

# Response includes a ready-to-use kubeconfig
{
  "id": "claim-a1b2c3",
  "kubeconfig": "apiVersion: v1\nclusters: ...",
  "expiresAt": "2026-02-15T15:00:00Z"
}

# Use it
echo "$KUBECONFIG" > /tmp/kube.yaml
KUBECONFIG=/tmp/kube.yaml kubectl get nodes

# Release when done
curl -X DELETE https://pool.kunobi.ninja/v1/claims/claim-a1b2c3 \
  -H "Authorization: Bearer $TOKEN"
```

## How It Works

Kobe runs as an operator in a host Kubernetes cluster. It maintains pools of virtual clusters organized by **profiles** (cluster templates with specific configurations, addons, and resource limits).

When a client claims a cluster, Kobe assigns one from the warm pool instantly. When released, the vcluster is destroyed and a fresh replacement is created in the background — ensuring every claim gets a clean, isolated environment.

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
| `POST` | `/v1/claims` | Claim a cluster from a profile's pool |
| `DELETE` | `/v1/claims/:id` | Release a leased cluster |
| `GET` | `/v1/profiles` | List available profiles with pool status |
| `GET` | `/v1/profiles/:name` | Get a specific profile's pool status |

## CRDs

Kobe uses two Custom Resource Definitions internally to manage pool state:

### ClusterPoolProfile

Defines a pool of virtual clusters with a specific configuration:

```yaml
apiVersion: kunobi.ninja/v1alpha1
kind: ClusterPoolProfile
metadata:
  name: e2e-basic
spec:
  poolSize: 3                    # keep 3 warm vclusters ready
  ttl: 2h                       # max claim duration
  vcluster:
    chartVersion: "0.24.1"
    values: |
      sync:
        toHost:
          pods:
            enabled: true
  addons:
    - name: metrics-server
      manifest: |
        # inline manifest or URL
  resources:
    limits:
      cpu: "1"
      memory: "1Gi"
status:
  ready: 2
  leased: 1
  creating: 0
```

### ClusterClaim

Represents a leased cluster (created internally by the HTTP API, not by users directly):

```yaml
apiVersion: kunobi.ninja/v1alpha1
kind: ClusterClaim
metadata:
  name: claim-a1b2c3
spec:
  profileRef: e2e-basic
  ttl: 1h
  requester:
    type: github-ci
    identity: "repo:org/repo:ref:refs/heads/main"
status:
  phase: Bound               # Pending | Bound | Released | Expired | Recycling
  vclusterName: pool-e2e-basic-2
  boundAt: "2026-02-15T14:00:00Z"
  expiresAt: "2026-02-15T15:00:00Z"
```

## Security

- **Authentication:** GitHub OIDC (CI) and Clerk JWTs (app/dev) — no long-lived secrets
- **Authorization:** Scoped by identity — profile access, TTL caps, concurrency limits
- **Kubeconfig:** Short-lived client certificates that expire with the claim TTL
- **Network:** TLS everywhere, rate limiting, optional IP allowlisting

## Built With

- **Rust** — kube-rs for the operator, axum for the HTTP API
- **vcluster** — virtual cluster runtime (via Helm)
- **Flux** — GitOps deployment

## Documentation

- [K3k + Velero Backend](docs/plans/2026-02-25-k3k-velero-backend.md)
- [Direct K0s & CAPI Backends](docs/plans/2026-02-27-direct-k0s-and-capi-backends.md)
- [OpenTelemetry Traces](docs/plans/2026-02-26-otel-traces-design.md)
- [Docker CI Maturity](docs/plans/2026-02-26-docker-ci-maturity-design.md)

## License

Apache-2.0
