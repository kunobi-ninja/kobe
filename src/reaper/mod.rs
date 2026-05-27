//! kobe-host-reaper: unmounts and removes stale subtrees under the
//! kobe lease-root host path (`/var/lib/kobe/leases/` by default).
//!
//! See `docs/superpowers/specs/2026-05-26-kobe-host-reaper-design.md`.

pub mod classify;
pub mod mounts;
pub mod sweep;
pub mod unmount;
