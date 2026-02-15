# Cross-Host Migration

When multiple wagyu hosts share the same Velero `BackupStorageLocation`, golden
image backups become portable. This enables live migration, cloud bursting, and
disaster recovery across independent Kubernetes clusters.

## Architecture

```
                      +------------------+
                      |   Git / Flux     |
                      | (profile specs)  |
                      +--------+---------+
                               |
                 +-------------+-------------+
                 |                           |
          +------v------+            +------v------+
          |   Host A    |            |   Host B    |
          | (wagyu +    |            | (wagyu +    |
          |  k3k +      |            |  k3k +      |
          |  Velero)    |            |  Velero)    |
          +------+------+            +------+------+
                 |                           |
                 +-------------+-------------+
                               |
                      +--------v---------+
                      |  Shared S3 Bucket |
                      | (Velero backups)  |
                      +------------------+
```

Both hosts run wagyu, k3k, and Velero. Both point their Velero
`BackupStorageLocation` at the same S3 bucket (or compatible store). Golden
backups created on Host A are visible to Host B and vice versa.

## Migration Steps

### 1. Share Velero Storage

Configure both hosts to use the same `BackupStorageLocation`:

```yaml
apiVersion: velero.io/v1
kind: BackupStorageLocation
metadata:
  name: default
  namespace: velero
spec:
  provider: aws
  objectStorage:
    bucket: kunobi-shared-backups
    prefix: velero
  config:
    region: us-east-1
```

Run `velero backup get` on Host B to confirm it can see backups created by
Host A.

### 2. Deploy the Same Profiles on Host B

Apply identical `ClusterPoolProfile` resources on Host B. Because the golden
backup already exists in S3, Host B will skip the golden build step and
immediately start restoring pool members from the existing backup.

### 3. Drain Host A

Set Host A's profiles to scale down:

```yaml
spec:
  scaling:
    minReady: 0
    maxClusters: 0
```

Existing leases will continue until their TTL expires. No new leases are
issued.

### 4. Scale Up Host B

Set Host B's profiles to the desired capacity:

```yaml
spec:
  scaling:
    minReady: 3
    maxClusters: 10
```

Host B restores clusters from the shared golden backup. New leases are served
from Host B's pool.

### 5. Update DNS / Load Balancer

Point the wagyu API endpoint to Host B. If you use a load balancer in front of
both hosts, remove Host A from the backend pool.

### 6. Decommission Host A

Once all active leases on Host A have expired (check with
`kubectl get clusterlease -n kunobi-pool`), tear down Host A's wagyu
deployment.

## Cloud Bursting Pattern

Use cross-host migration to handle demand spikes:

1. Run a baseline pool on an on-prem host (Host A).
2. When queue depth exceeds `scaleUpThreshold` and Host A has hit
   `maxClusters`, deploy the same profile on a cloud host (Host B) with a
   higher `maxClusters`.
3. Host B restores from the shared golden backup -- no need to rebuild.
4. When demand drops, scale Host B back to zero. On-prem Host A continues
   serving the baseline.

This works because both hosts share the S3 bucket. The golden backup only
needs to be built once.

## Disaster Recovery Pattern

Protect against host failure with a standby:

1. Host A is the primary. Host B runs wagyu but with `minReady: 0` (standby).
2. Both share the same Velero `BackupStorageLocation`.
3. Monitoring detects Host A is down.
4. Automation (or manual action) sets Host B's `minReady` to the desired
   count.
5. Host B restores pool members from the golden backup within seconds.
6. DNS is updated to point to Host B.

### Recovery Time

| Step                       | Duration     |
|----------------------------|--------------|
| Failure detection          | 30-60s       |
| Profile update on Host B   | < 5s         |
| Cluster restore (per unit) | ~10s         |
| DNS propagation            | 30-300s (TTL)|
| **Total**                  | **~1-5 min** |

The bottleneck is typically DNS propagation. Use low TTLs or a health-check
aware load balancer to minimize this.
