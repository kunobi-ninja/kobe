//! CIDR slot allocator for pool-managed ClusterInstances.
//!
//! Each leased k3s/k0s cluster runs as a workload pod inside a host
//! Kubernetes cluster. Both backends spin up their own apiserver +
//! kube-proxy and need their own service-CIDR / cluster-CIDR ranges.
//! Two constraints have to be satisfied at the same time:
//!
//! 1. **No collision with the host cluster.** k3s, RKE2, and kubeadm
//!    all default to `10.43.0.0/16` for services and `10.42.0.0/16`
//!    for pods. A leased k3s pool member that inherits those defaults
//!    sets up in-pod iptables for `10.43.0.1` that race with the
//!    host's identical rule; the in-pod `kubernetes` Service then
//!    resolves to the *host's* apiserver, not its own. CoreDNS sees
//!    a cert signed by an unknown CA and never goes ready. Every
//!    in-cluster controller breaks the same way.
//!
//! 2. **No collision between two leased pool members.** Two clusters
//!    that share the same service-CIDR can't be peered: traffic to
//!    `10.243.0.1` from cluster A is ambiguous w.r.t. cluster B's
//!    apiserver service. Some flows (cross-cluster federation tests,
//!    multi-tenant CI matrix) genuinely peer pool members; assigning
//!    each a unique slot prevents the conflict.
//!
//! ## Allocation
//!
//! We reserve `10.240.0.0/12` (≈ 1 M addresses) for kobe pool
//! clusters. Each ClusterInstance gets two non-overlapping `/20`
//! ranges — one for services, one for pods — drawn from disjoint
//! halves of the parent `/12`:
//!
//! ```text
//! 10.240.0.0/12
//! ├── 10.240.0.0/13  ← service CIDRs (slot · /20)
//! └── 10.248.0.0/13  ← cluster (pod) CIDRs (slot · /20)
//! ```
//!
//! Slot `s ∈ 0..128` maps to:
//!
//! - `service_cidr = 10.{240 + (s/16)}.{(s%16)*16}.0/20`
//! - `cluster_cidr = 10.{248 + (s/16)}.{(s%16)*16}.0/20`
//!
//! Each `/20` is 4096 addresses — comfortable for ephemeral CI
//! clusters running ≤ a few hundred services and pods. 128 slots is
//! more than the realistic concurrent-pool-member ceiling for kobe.
//!
//! ## Allocation strategy
//!
//! Stateless: the source of truth is the live ClusterInstance
//! inventory. To pick a slot for a new instance:
//!
//! 1. List all ClusterInstances in the operator namespace.
//! 2. Collect every `status.network.serviceCidr` already in use.
//! 3. Walk slots `0..MAX_SLOTS` and return the first whose service
//!    CIDR is not in the used set.
//!
//! Allocation is decided once at the instance's first reconcile (when
//! `status.network` is `None`), persisted to status, and never
//! changed afterwards. If somehow two reconciles race and pick the
//! same slot, the JSON Merge Patch on status will land sequentially
//! — the loser sees its slot already taken on the next pass and
//! re-allocates.

use crate::crd::ClusterInstanceNetwork;

/// Maximum number of concurrently-allocated network slots. Each slot
/// claims one service CIDR + one cluster CIDR, both `/20` (4096 IPs).
/// 128 slots fit inside the reserved `10.240.0.0/12` parent block
/// twice over (once for service, once for cluster).
pub const MAX_SLOTS: u16 = 128;

/// Compute the (service_cidr, cluster_cidr) pair assigned to slot
/// `slot`. Pure function; the allocator's only stateful part is which
/// slot to pick.
pub fn cidrs_for_slot(slot: u16) -> ClusterInstanceNetwork {
    debug_assert!(slot < MAX_SLOTS, "slot {slot} out of range 0..{MAX_SLOTS}");
    let high = (slot / 16) as u8;
    let low = ((slot % 16) * 16) as u8;
    ClusterInstanceNetwork {
        service_cidr: format!("10.{}.{}.0/20", 240 + high, low),
        cluster_cidr: format!("10.{}.{}.0/20", 248 + high, low),
    }
}

/// Pick the first slot whose service CIDR is not in `used_service_cidrs`.
/// Returns `None` if every slot in `0..MAX_SLOTS` is taken.
///
/// Caller is responsible for sourcing `used_service_cidrs` from the
/// live CRD inventory. Comparing on `service_cidr` alone is sufficient
/// because slots map service↔cluster bijectively — same slot means
/// same pair.
pub fn allocate_slot<I, S>(used_service_cidrs: I) -> Option<(u16, ClusterInstanceNetwork)>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let used: std::collections::HashSet<String> = used_service_cidrs
        .into_iter()
        .map(|s| s.as_ref().to_string())
        .collect();
    (0..MAX_SLOTS).find_map(|slot| {
        let net = cidrs_for_slot(slot);
        if used.contains(&net.service_cidr) {
            None
        } else {
            Some((slot, net))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_zero_is_outside_common_defaults() {
        let n = cidrs_for_slot(0);
        assert_eq!(n.service_cidr, "10.240.0.0/20");
        assert_eq!(n.cluster_cidr, "10.248.0.0/20");
        // Confirm it's clear of every common k8s default.
        for collision in &[
            "10.42.0.0/16", // k3s pod default
            "10.43.0.0/16", // k3s service / rke2 default
            "10.96.0.0/12", // kubeadm service default
            "10.0.0.0/16",  // various
        ] {
            assert_ne!(&n.service_cidr, collision);
            assert_ne!(&n.cluster_cidr, collision);
        }
    }

    #[test]
    fn slots_are_unique_and_non_overlapping() {
        // Every slot's service CIDR must differ from every other
        // slot's, and same for cluster CIDRs. /20 ranges in
        // 10.240.0.0/13 don't overlap because they're 4096 apart on
        // the third octet (or roll over to a fresh second octet).
        let mut svc = std::collections::HashSet::new();
        let mut cls = std::collections::HashSet::new();
        for slot in 0..MAX_SLOTS {
            let n = cidrs_for_slot(slot);
            assert!(
                svc.insert(n.service_cidr.clone()),
                "duplicate svc at slot {slot}"
            );
            assert!(
                cls.insert(n.cluster_cidr.clone()),
                "duplicate cls at slot {slot}"
            );
        }
        assert_eq!(svc.len(), MAX_SLOTS as usize);
        assert_eq!(cls.len(), MAX_SLOTS as usize);
    }

    #[test]
    fn service_and_cluster_cidrs_never_overlap() {
        // The two halves of the /12 are disjoint by construction:
        // service is 10.240.0.0/13, cluster is 10.248.0.0/13.
        for slot in 0..MAX_SLOTS {
            let n = cidrs_for_slot(slot);
            assert_ne!(n.service_cidr, n.cluster_cidr, "slot {slot}");
            assert!(n.service_cidr.starts_with("10.24"));
            assert!(n.cluster_cidr.starts_with("10.2"));
            // Service in 10.240..10.247, cluster in 10.248..10.255.
            let svc_octet: u8 = n.service_cidr.split('.').nth(1).unwrap().parse().unwrap();
            let cls_octet: u8 = n.cluster_cidr.split('.').nth(1).unwrap().parse().unwrap();
            assert!(
                (240..=247).contains(&svc_octet),
                "service octet {svc_octet} outside 240..=247"
            );
            assert!(
                (248..=255).contains(&cls_octet),
                "cluster octet {cls_octet} outside 248..=255"
            );
        }
    }

    #[test]
    fn allocate_picks_zero_when_nothing_used() {
        let (slot, net) = allocate_slot::<_, &str>(std::iter::empty()).unwrap();
        assert_eq!(slot, 0);
        assert_eq!(net.service_cidr, "10.240.0.0/20");
    }

    #[test]
    fn allocate_skips_used_slots() {
        // Slot 0 is taken; allocator returns slot 1.
        let used = vec!["10.240.0.0/20"];
        let (slot, net) = allocate_slot(used).unwrap();
        assert_eq!(slot, 1);
        assert_eq!(net.service_cidr, "10.240.16.0/20");
    }

    #[test]
    fn allocate_finds_first_hole() {
        // Slots 0, 1, 2, 4 taken — allocator must return 3, not 5.
        let used = vec![
            "10.240.0.0/20",
            "10.240.16.0/20",
            "10.240.32.0/20",
            "10.240.64.0/20",
        ];
        let (slot, _) = allocate_slot(used).unwrap();
        assert_eq!(slot, 3, "allocator must fill the lowest free slot");
    }

    #[test]
    fn allocate_returns_none_when_all_slots_taken() {
        let all: Vec<String> = (0..MAX_SLOTS)
            .map(|s| cidrs_for_slot(s).service_cidr)
            .collect();
        assert!(allocate_slot(all).is_none());
    }

    #[test]
    fn unrecognised_used_cidrs_do_not_block_allocation() {
        // Stale or hand-set values outside our reserved /12 must not
        // confuse the allocator — they can't possibly collide with
        // any slot we issue.
        let used = vec!["192.168.1.0/24", "172.16.0.0/16"];
        let (slot, _) = allocate_slot(used).unwrap();
        assert_eq!(slot, 0);
    }
}
