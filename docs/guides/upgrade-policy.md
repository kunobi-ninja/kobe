# Rolling Upgrade Policy

When you bump the kobe operator (or anything that flows into a
ClusterPool's spec hash), existing pool members on the old hash
need to rotate out. Without policy, they all rotate at once and the
pool drops to zero capacity until the refill catches up. With
`spec.upgradePolicy`, the rotation is rolling — analogous to
`Deployment.maxSurge` and `Deployment.maxUnavailable` in core
Kubernetes.

This guide explains when an upgrade fires, how to choose the knobs
for your pool shape, and what to expect operationally.

## When does an upgrade fire?

Any change that flips the pool's `spec_hash` makes existing members
"drifted" and eligible for recycle. Three sources flow into the hash:

1. **User-visible spec edits** to the `ClusterPool` CR — cluster
   config, addons, bootstrap *names*.
2. **Operator-level config bumps** — currently just
   `KOBE_SYNC_IMAGE`, which only affects vkobe-backend pools.
3. **`BootstrapConfig` content edits** — the install manifest, the
   shell script, anything inside the referenced bootstrap CRs. This
   catches the case where you rev the bootstrap content without
   renaming the bootstrap reference.

To diff actual hashes against the operator's current expectation:

```sh
kubectl get clusterinstance -n kobe-system \
  -l 'app.kubernetes.io/managed-by=kobe-operator' \
  -o custom-columns=NAME:.metadata.name,HASH:.status.specHash,PHASE:.status.phase
```

Mismatched hashes between members of the same pool indicate an
in-flight upgrade or a stalled one.

## The three knobs

```yaml
apiVersion: kobe.kunobi.ninja/v1alpha1
kind: ClusterPool
metadata:
  name: ci-vkobe-small
spec:
  size: 4
  upgradePolicy:
    maxRecycling: 1            # drift Deletes per reconcile
    maxSurge: 1                # extra clusters above min_ready during upgrade
    minReadyDuringUpgrade: 3   # floor on total Ready (any version)
```

### `maxRecycling` (default 1)

Maximum drifted instances to recycle in one reconcile pass. Higher
values upgrade faster but spike create-traffic on the host cluster.
**Set to `0` to pause** drift recycling entirely — the kill switch
when an upgrade is going sideways and you want to halt it without
redeploying the operator. Drift detection still runs; only the
Deletes are suppressed.

### `maxSurge` (default 1)

Extra clusters allowed above `min_ready` (or `spec.size`) while at
least one drifted Ready remains. The scale-up loop overshoots the
warm target by this much during an upgrade so a fresh replacement
lands BEFORE the next drifted one is Deleted. Without surge, a
size-1 pool would have to drop to 0 capacity to upgrade. Surge
disappears the moment all drift is cleared — back to baseline.

### `minReadyDuringUpgrade` (default `min_ready`)

Floor on **total Ready** (clean *or* drifted) during the upgrade.
Drifted Ready still serves claims, so what users tune for is
"available capacity right now." This matches `Deployment.maxUnavailable`
semantics in core k8s.

When unset, defaults to `min_ready` (from `scaling.min_ready`, or
`spec.size` for fixed pools): "never drop below the warm target."
Set to `0` to recycle as fast as `maxRecycling` allows regardless
of available capacity — appropriate for pools that can tolerate
brief downtime.

Setting it higher than `min_ready` is allowed but achieves nothing
useful: the recycler just never acts because the floor cannot be
satisfied with the existing pool.

## Choosing knobs by pool shape

### Size 1 (dev/CI)

```yaml
spec:
  size: 1
  upgradePolicy:
    maxRecycling: 1
    maxSurge: 1
    minReadyDuringUpgrade: 0   # OK, surge handles it; explicit for clarity
```

Zero downtime requires the host cluster to have headroom for 2× the
pool size during cutover. The sequence on each upgrade:

1. T0: surge create lands (pool grows to 2). No Delete yet — total
   Ready is still 1, equal to the floor.
2. T1 (replacement Ready): drifted original is Deleted. Pool back
   to size 1, all on the new hash.

### Fixed `size=4` prod-shaped (typical CI vkobe pool)

```yaml
spec:
  size: 4
  upgradePolicy:
    maxRecycling: 1
    maxSurge: 1
    minReadyDuringUpgrade: 3
```

~25% capacity overhead for ~4 reconciles (4-instance pool at 1
recycle per reconcile). Total upgrade time: roughly
`size × backend_boot_time` per pool. For vkobe (~3-5 min boot),
that's 12-20 minutes for the full rotation. CI claims continue
landing on the 3 healthy clusters throughout.

### Larger fleets (`size >= 8`)

```yaml
spec:
  size: 8
  upgradePolicy:
    maxRecycling: 2
    maxSurge: 2
    minReadyDuringUpgrade: 6
```

Faster but bumpier. With 25% surge and 25% recycle in flight,
upgrade completes in roughly half the time. Watch host-cluster
resource limits.

### Scaling pools (`spec.scaling` set)

The default for `minReadyDuringUpgrade` is `scaling.min_ready` —
not `spec.size`. So a scaling pool with `min_ready: 2,
max_clusters: 8` defaults to `minReadyDuringUpgrade: 2`. Override
explicitly only if you want a different floor.

### Scale-to-zero pools (`min_ready: 0`)

```yaml
spec:
  scaling:
    min_ready: 0
    max_clusters: 4
  upgradePolicy:
    maxRecycling: 1
    maxSurge: 1
    minReadyDuringUpgrade: 0   # nothing to preserve; default would be 0 anyway
```

Drift is detected only when at least one instance is Ready (a
scale-to-zero pool with no claims is invisible to drift). Ratchet
through the pool the next time a claim warms it up.

## Watching an upgrade

### Metrics

`kobe_instance_recycles_total{reason="SpecDrift"}` increments per
drift Delete. Tap into your Prometheus to track upgrade velocity:

```promql
rate(kobe_instance_recycles_total{reason="SpecDrift"}[5m])
```

### Pool phase

`status.phase` stays `Healthy` throughout a normal upgrade —
scale-down doesn't fire while drift is in flight, and the surge
keeps total Ready above the floor. If you see `ScalingDown` or
`Failing`, something is off.

### Per-instance hash diff

```sh
kubectl get clusterinstance -n kobe-system \
  -l 'app.kubernetes.io/managed-by=kobe-operator' \
  -o custom-columns=NAME:.metadata.name,HASH:.status.specHash,PHASE:.status.phase \
  | grep <pool-name>
```

While the upgrade is in flight, you'll see a mix of hashes —
the old hash on the drifted-but-still-Ready members, the new hash
on the surge replacement and on whatever already rotated. As
recycles complete, the old hash disappears.

## Pause / abort

### Pause an in-flight upgrade

Edit the pool to set `maxRecycling: 0`:

```sh
kubectl patch clusterpool <pool> -n kobe-system --type=merge \
  -p '{"spec":{"upgradePolicy":{"maxRecycling":0}}}'
```

Drift detection continues, no Deletes ship. Resume by setting back
to your normal value (default 1). In-flight surge replacements
finish creating; the next reconcile after resume picks up where it
left off.

### Roll back the spec

If the upgrade itself was the problem (the new operator version is
buggy, the new bootstrap config breaks installs), rolling the spec
back flips the hash back to the old value. In-flight Creating
instances with the bad intermediate hash get caught as "drifted
Creating" and Deleted on the next reconcile (no surge cost, no
rate cap), so the rollback proceeds quickly.

## Anti-patterns

- **`maxSurge: 0` AND `minReadyDuringUpgrade >= size`**.
  The recycle can never make progress: any Delete would dip below
  the floor, and there's no surge to provide headroom. Always pair
  `maxSurge: 0` with `minReadyDuringUpgrade < size`.

- **`maxSurge` higher than `max_clusters - size`**.
  Ineffective — the `max_clusters` ceiling binds first. The surge
  scale-up will refuse to overshoot the ceiling. Either raise
  `max_clusters` or keep `maxSurge` modest.

- **Zero-TTL claims hammering a `size=1` upgrading pool**.
  Every recycle bounces a brand-new claim. Not a correctness bug,
  but extends the upgrade window and creates noisy phase
  transitions. Either raise pool size or let CI quiet down before
  bumping the operator.

## Forensics

When something goes sideways:

1. **`status.consecutiveFailures` and `status.nextAttemptAt`** — if
   non-zero, the pool is in failure backoff. Drift recycle and
   scale-up are both suppressed during backoff (intentional, see
   the `pool::manager` module doc); only Unhealthy and stuck-Creating
   timeouts still ship. Investigate the bootstrap or backend before
   resuming.

2. **`kobe-operator` logs filtered by cluster name**:
   ```sh
   kubectl logs -n kobe-system deploy/kobe -c kobe-operator \
     --tail=10000 | grep <cluster-name>
   ```
   Look for `Drifted Ready: rolling recycle`,
   `Holding drift recycle: floor would be violated`, and
   `Drifted Creating: recycling without waiting for timeout`.

3. **`kubectl describe clusterinstance <name>`** — events surface
   provision-failure reasons, OOM kills, bootstrap timeouts, etc.

4. **Hash mismatch persistence**. If a drifted member never gets
   recycled despite the pool not being in backoff and not at floor,
   check whether it's `Leased` (won't recycle until released by
   design) or stuck `Recycling` (the Delete shipped but the
   underlying resources are slow to clean up).
