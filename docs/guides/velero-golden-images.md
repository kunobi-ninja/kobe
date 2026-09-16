# Velero Golden Images

This page is also on the docs site: [Operate → Golden images](../kobe-docs/operate/golden-images.mdx).

Golden images let the operator pre-build a fully configured cluster once, back it
up with Velero, and restore copies in seconds instead of provisioning from scratch.

## How It Works

1. **Operator creates a temporary golden cluster** matching the pool's
   `cluster` spec (version, servers, persistence), using that pool's backend.
2. **Addons are installed** from the pool's `addons` list.
3. **Readiness gates are evaluated** — the operator waits until all gates pass
   (e.g. `AddonsReady`).
4. **Velero backs up the golden cluster's namespace** using the configured
   `storageLocation`. The backup is named `<goldenPrefix>-<pool>-<generation>`.
5. **The temporary cluster is destroyed.** Only the Velero backup artifact
   (stored in S3 / compatible object storage) remains.
6. **Pool scaling restores from the backup.** Each new pool member is a Velero
   `Restore` with namespace remapping (`golden-ns` -> `pool-member-ns`),
   bypassing addon installation and readiness wait entirely.

When the pool spec changes (generation bump) and `refreshOn` is `ProfileChange`,
the operator detects the mismatch, creates a new golden backup, and marks the
old one for expiry.

Velero CRDs must be present in the host cluster. If they are missing, the
operator logs that snapshot support is disabled and ignores `spec.snapshot`.

## Timing Comparison

| Operation              | Fresh Provision | Restore from Golden |
|------------------------|-----------------|---------------------|
| Cluster create         | 30-60s          | ~5s (PVC restore)   |
| Addon installation     | 30-120s         | 0s (already in image)|
| Readiness gate check   | 10-30s          | ~5s (pods starting) |
| **Total**              | **1-4 min**     | **~10s**            |

The exact numbers depend on cluster size, addon complexity, and storage backend
performance. Addon installation is the step this feature skips.

## Prerequisites

- **Velero v1.13+** installed in the host cluster (the `velero` namespace by
  default).
- **S3-compatible object storage** configured as a Velero `BackupStorageLocation`.
  MinIO, AWS S3, GCS, and Azure Blob are all supported.
- **CSI snapshot support** if the pool uses `persistence.storageType: dynamic`.
  The Velero CSI plugin must be installed and your StorageClass must have a
  matching VolumeSnapshotClass.
- **RBAC:** The kobe operator's ServiceAccount needs permission to create
  `Backup` and `Restore` resources in the Velero namespace.

### Minimal Velero Setup

```bash
velero install \
  --provider aws \
  --bucket my-kobe-backups \
  --secret-file ./credentials-velero \
  --plugins velero/velero-plugin-for-aws:v1.10.0 \
  --use-volume-snapshots=true \
  --features=EnableCSI
```

## Configuration Reference

The `snapshot` field on a `ClusterPool` spec accepts the following:

| Field              | Type     | Default          | Description                                                  |
|--------------------|----------|------------------|--------------------------------------------------------------|
| `enabled`          | `bool`   | `false`          | Enable golden image snapshotting.                            |
| `veleroNamespace`  | `string` | `"velero"`       | Namespace where Velero is installed.                         |
| `storageLocation`  | `string` | `"default"`      | Name of the Velero `BackupStorageLocation` to use.           |
| `goldenPrefix`     | `string` | `"golden"`       | Prefix for backup names: `<prefix>-<pool>-<generation>`.     |
| `ttl`              | `string` | `"720h"`         | Retention duration for Velero backups.                       |
| `refreshOn`        | `enum`   | `ProfileChange`  | When to rebuild the golden image.                            |

### `refreshOn` values

- **`ProfileChange`** (default) — Rebuild whenever the pool's `.metadata.generation`
  increments (any spec change). A backup already in progress for that generation
  is not spawned again.
- **`Manual`** — Do not auto-rebuild. The operator only creates a golden backup
  on `ProfileChange`; there is no annotation trigger.

## Example

```yaml
apiVersion: kobe.kunobi.ninja/v1alpha1
kind: ClusterPool
metadata:
  name: ci-small
  namespace: kobe-system
spec:
  size: 3
  ttl: 1h
  backend:
    type: k3s
  cluster:
    version: v1.31.3+k3s1
    servers: 1
  snapshot:
    enabled: true
    veleroNamespace: velero
    storageLocation: default
    goldenPrefix: golden
    ttl: 720h
    refreshOn: ProfileChange
```

k3s with CSI persistence is the path this feature was built for. The restore
sets `restorePVs: true`. Watch `kobe_golden_backup_total` and
`kobe_provision_method_total{method="restore"}`.
