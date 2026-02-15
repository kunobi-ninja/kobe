# Velero Golden Images

Golden images let the operator pre-build a fully configured cluster once, back it
up with Velero, and restore copies in seconds instead of provisioning from scratch.

## How It Works

1. **Operator creates a temporary "golden" k3k cluster** matching the profile's
   `cluster` spec (version, servers, persistence).
2. **Addons are installed** from the profile's `addons` list.
3. **Readiness gates are evaluated** -- the operator waits until all gates pass
   (e.g. `DeploymentReady` for metrics-server).
4. **Velero backs up the golden cluster's namespace** using the configured
   `storageLocation`. The backup is named `<goldenPrefix>-<profile>-<generation>`.
5. **The temporary cluster is destroyed.** Only the Velero backup artifact
   (stored in S3 / compatible object storage) remains.
6. **Pool scaling restores from the backup.** Each new pool member is a Velero
   `Restore` with namespace remapping (`golden-ns` -> `pool-member-ns`),
   bypassing addon installation and readiness wait entirely.

When the profile spec changes (generation bump), the operator detects the
mismatch, creates a new golden backup, and marks the old one for expiry.

## Timing Comparison

| Operation              | Fresh Provision | Restore from Golden |
|------------------------|-----------------|---------------------|
| k3k cluster create     | 30-60s          | ~5s (PVC restore)   |
| Addon installation     | 30-120s         | 0s (already in image)|
| Readiness gate check   | 10-30s          | ~5s (pods starting) |
| **Total**              | **1-4 min**     | **~10s**            |

The exact numbers depend on cluster size, addon complexity, and storage backend
performance. The key win is that addon installation -- often the slowest step --
is completely skipped.

## Prerequisites

- **Velero v1.13+** installed in the host cluster (the `velero` namespace by
  default).
- **S3-compatible object storage** configured as a Velero `BackupStorageLocation`.
  MinIO, AWS S3, GCS, and Azure Blob are all supported.
- **CSI snapshot support** if your profile uses `persistence.storageType: dynamic`.
  The Velero CSI plugin must be installed and your StorageClass must have a
  matching VolumeSnapshotClass.
- **RBAC:** The wagyu operator's ServiceAccount needs permission to create
  `Backup` and `Restore` resources in the Velero namespace.

### Minimal Velero Setup

```bash
velero install \
  --provider aws \
  --bucket my-kunobi-backups \
  --secret-file ./credentials-velero \
  --plugins velero/velero-plugin-for-aws:v1.10.0 \
  --use-volume-snapshots=true \
  --features=EnableCSI
```

## Configuration Reference

The `snapshot` field in a `ClusterPoolProfile` spec accepts the following:

| Field              | Type     | Default          | Description                                                  |
|--------------------|----------|------------------|--------------------------------------------------------------|
| `enabled`          | `bool`   | `false`          | Enable golden image snapshotting.                            |
| `veleroNamespace`  | `string` | `"velero"`       | Namespace where Velero is installed.                         |
| `storageLocation`  | `string` | `"default"`      | Name of the Velero `BackupStorageLocation` to use.           |
| `goldenPrefix`     | `string` | `"golden"`       | Prefix for backup names: `<prefix>-<profile>-<generation>`.  |
| `ttl`              | `string` | `"720h"`         | Retention duration for Velero backups.                       |
| `refreshOn`        | `enum`   | `ProfileChange`  | When to rebuild the golden image.                            |

### `refreshOn` values

- **`ProfileChange`** (default) -- Rebuild whenever the profile's `.metadata.generation`
  increments (i.e., any spec change).
- **`Manual`** -- Only rebuild when the annotation
  `kunobi.ninja/refresh-snapshot: "true"` is set on the profile.

## Example Profile

See [`deploy/profiles/e2e-k3k-snapshot.yaml`](../../deploy/profiles/e2e-k3k-snapshot.yaml)
for a complete working example.
