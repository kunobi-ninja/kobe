//! kobe-host-reaper: unmounts and removes stale subtrees under the
//! kobe lease-root host path (`/var/lib/kobe/leases/` by default), and reaps
//! aged empty cgroups left by nested k3s containerd instances.

pub mod cgroups;
pub mod classify;
pub mod metrics;
pub mod mounts;
pub mod sweep;
pub mod unmount;
