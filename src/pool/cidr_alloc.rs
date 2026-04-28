//! CIDR slot allocator for IPAM-style pools.
//!
//! Each `CIDRPool` describes a parent block plus a per-slot prefix. The
//! allocator carves the parent into equally-sized slots aligned at slot
//! boundaries and exposes:
//!
//! - [`PoolPlan::new`] — parses a pool spec into a queryable plan,
//! - [`PoolPlan::cidr_at`] — slot index → CIDR string,
//! - [`PoolPlan::slot_of`] — CIDR string → slot index (for matching
//!   user-supplied static reservations to a slot),
//! - [`PoolPlan::pick_first_free`] — pick the lowest-numbered slot whose
//!   service+cluster CIDRs are not already in `used`.
//!
//! ## Why slot-based, not arbitrary CIDRs?
//!
//! We could let claims request arbitrary CIDRs and bookkeep the result
//! as a list of intervals, with merging, splitting, etc. Slot-based
//! allocation is simpler and good enough: every assignment lands at a
//! slot boundary, so there's a finite, enumerable set of possible
//! allocations and "is it taken?" reduces to set membership. The only
//! cost is that a manual reservation has to land on a slot boundary —
//! which is a feature, not a bug, since misaligned reservations would
//! create permanently-unallocatable holes.
//!
//! ## Why two parallel block axes (service + cluster)?
//!
//! Each leased k3s/k0s pool member needs **two** non-overlapping CIDRs
//! — one for `--service-cidr`, one for `--cluster-cidr`. Most uses pair
//! them 1:1 (slot N of service block ↔ slot N of cluster block). The
//! allocator exposes the two axes separately so that:
//!
//! - A single `CIDRPool` carves both axes from the same physical IP
//!   space (no dual-pool dance for simple cases).
//! - Manual reservations can pin one axis without forcing the other to
//!   share a slot index.

use std::net::Ipv4Addr;

/// A pool's CIDR layout, parsed from `CIDRPoolSpec`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolPlan {
    pub service: Block,
    pub cluster: Block,
}

/// One axis of a `PoolPlan` (service xor cluster).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    /// Network address of the parent block, in host byte order.
    pub network: u32,
    /// Prefix of the parent block (e.g. 13 for `10.240.0.0/13`).
    pub block_prefix: u8,
    /// Prefix carved per slot (e.g. 20 for `/20` slots).
    pub slot_prefix: u8,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PoolPlanError {
    #[error("CIDR is not in `a.b.c.d/p` form: {0}")]
    Malformed(String),
    #[error("invalid IP address `{0}`")]
    BadAddr(String),
    #[error("invalid prefix `{0}`")]
    BadPrefix(String),
    #[error("slot prefix {slot} must be >= block prefix {block}")]
    SlotPrefixTooSmall { block: u8, slot: u8 },
    #[error("slot prefix {0} > 32")]
    SlotPrefixTooBig(u8),
    #[error("block prefix {0} > 32")]
    BlockPrefixTooBig(u8),
    #[error("CIDR `{0}` is not aligned to its prefix")]
    Unaligned(String),
}

impl Block {
    /// Parse a parent block (`"10.240.0.0/13"`) and slot prefix.
    pub fn parse(block: &str, slot_prefix: u8) -> Result<Self, PoolPlanError> {
        let (addr, prefix) = parse_cidr(block)?;
        if prefix > 32 {
            return Err(PoolPlanError::BlockPrefixTooBig(prefix));
        }
        if slot_prefix > 32 {
            return Err(PoolPlanError::SlotPrefixTooBig(slot_prefix));
        }
        if slot_prefix < prefix {
            return Err(PoolPlanError::SlotPrefixTooSmall {
                block: prefix,
                slot: slot_prefix,
            });
        }
        if addr & block_mask(prefix) != addr {
            return Err(PoolPlanError::Unaligned(block.to_string()));
        }
        Ok(Block {
            network: addr,
            block_prefix: prefix,
            slot_prefix,
        })
    }

    /// Total number of slots that fit in this block.
    pub fn capacity(&self) -> u32 {
        // `1 << (slot_prefix - block_prefix)`. Saturate at u32::MAX to
        // avoid overflow when (e.g.) someone defines a /0 block carved
        // into /32 slots — that's 2^32 slots, doesn't fit in u32.
        let bits = self.slot_prefix - self.block_prefix;
        if bits >= 32 { u32::MAX } else { 1u32 << bits }
    }

    /// CIDR string for slot `s`. Caller must ensure `s < capacity()`;
    /// out-of-range slots return a CIDR outside the parent block, which
    /// every other layer rejects.
    pub fn cidr_at(&self, slot: u32) -> String {
        // Each slot is `2^(32 - slot_prefix)` addresses wide.
        let stride = 1u32 << (32 - self.slot_prefix);
        let net = self.network.wrapping_add(slot.wrapping_mul(stride));
        let ip = Ipv4Addr::from(net);
        format!("{ip}/{}", self.slot_prefix)
    }

    /// Reverse of `cidr_at`. Returns `None` when the input is malformed,
    /// outside the parent block, or not aligned to a slot boundary.
    pub fn slot_of(&self, cidr: &str) -> Option<u32> {
        let (addr, prefix) = parse_cidr(cidr).ok()?;
        if prefix != self.slot_prefix {
            return None;
        }
        // Must be inside the parent block.
        if addr & block_mask(self.block_prefix) != self.network {
            return None;
        }
        let stride = 1u32 << (32 - self.slot_prefix);
        let offset = addr.wrapping_sub(self.network);
        if offset % stride != 0 {
            return None;
        }
        Some(offset / stride)
    }
}

impl PoolPlan {
    pub fn new(
        service_block: &str,
        service_prefix: u8,
        cluster_block: &str,
        cluster_prefix: u8,
    ) -> Result<Self, PoolPlanError> {
        Ok(Self {
            service: Block::parse(service_block, service_prefix)?,
            cluster: Block::parse(cluster_block, cluster_prefix)?,
        })
    }

    /// Number of slots usable for a paired (service, cluster) allocation.
    /// We assume slot N of service pairs with slot N of cluster, so
    /// capacity is the smaller of the two. (`u32::MAX` for both → MAX.)
    pub fn capacity(&self) -> u32 {
        std::cmp::min(self.service.capacity(), self.cluster.capacity())
    }

    /// Find the lowest-indexed slot whose service CIDR is not in
    /// `used_service` AND whose cluster CIDR is not in `used_cluster`.
    /// Returns `(slot, service_cidr, cluster_cidr)`.
    pub fn pick_first_free<I, J, S, T>(
        &self,
        used_service: I,
        used_cluster: J,
    ) -> Option<(u32, String, String)>
    where
        I: IntoIterator<Item = S>,
        J: IntoIterator<Item = T>,
        S: AsRef<str>,
        T: AsRef<str>,
    {
        let used_svc: std::collections::HashSet<String> = used_service
            .into_iter()
            .map(|s| s.as_ref().to_string())
            .collect();
        let used_cls: std::collections::HashSet<String> = used_cluster
            .into_iter()
            .map(|s| s.as_ref().to_string())
            .collect();
        let cap = self.capacity();
        (0..cap).find_map(|slot| {
            let svc = self.service.cidr_at(slot);
            let cls = self.cluster.cidr_at(slot);
            if used_svc.contains(&svc) || used_cls.contains(&cls) {
                None
            } else {
                Some((slot, svc, cls))
            }
        })
    }
}

/// `0xff..ff << (32 - prefix)`. Returns 0 for prefix==0 (entire space).
fn block_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn parse_cidr(s: &str) -> Result<(u32, u8), PoolPlanError> {
    let (addr_s, prefix_s) = s
        .split_once('/')
        .ok_or_else(|| PoolPlanError::Malformed(s.to_string()))?;
    let addr: Ipv4Addr = addr_s
        .parse()
        .map_err(|_| PoolPlanError::BadAddr(addr_s.to_string()))?;
    let prefix: u8 = prefix_s
        .parse()
        .map_err(|_| PoolPlanError::BadPrefix(prefix_s.to_string()))?;
    Ok((u32::from(addr), prefix))
}

/// The single, hardcoded IPAM plan kobe uses for guest k3s/k0s
/// clusters. `10.240.0.0/13` for service CIDRs and `10.248.0.0/13` for
/// cluster (pod) CIDRs, both carved into `/20` slots (4096 IPs each,
/// 128 slots total).
///
/// Why hardcoded? Because every kobe deployment to date has used this
/// layout, the parent block is well outside every common k8s default
/// (10.42/10.43/10.96), and adding configuration for a value that
/// doesn't change in practice would be speculative flexibility we'd
/// have to test, document, and support. If a future deployment
/// genuinely needs a different layout, this becomes a `CIDRPool` CRD
/// at that point — the `CIDRClaim` API is unchanged either way.
pub fn ipam_plan() -> PoolPlan {
    PoolPlan::new("10.240.0.0/13", 20, "10.248.0.0/13", 20)
        .expect("ipam_plan is a constant; arguments are valid by construction")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Plan matching the default `CIDRPool` the helm chart ships, so
    /// migration tests can assert continuity with the pre-IPAM
    /// allocator's slot layout.
    fn default_plan() -> PoolPlan {
        PoolPlan::new("10.240.0.0/13", 20, "10.248.0.0/13", 20).unwrap()
    }

    /// Slot count of the default plan: 2^(20 - 13) = 128.
    const DEFAULT_SLOTS: u32 = 128;

    #[test]
    fn parse_block_validates_prefix() {
        assert!(Block::parse("10.0.0.0/8", 16).is_ok());
        assert_eq!(
            Block::parse("10.0.0.0/16", 8).unwrap_err(),
            PoolPlanError::SlotPrefixTooSmall { block: 16, slot: 8 }
        );
        assert!(matches!(
            Block::parse("not-a-cidr", 16).unwrap_err(),
            PoolPlanError::Malformed(_)
        ));
        assert!(matches!(
            Block::parse("10.0.0.5/8", 16).unwrap_err(),
            PoolPlanError::Unaligned(_)
        ));
    }

    #[test]
    fn slot_zero_is_outside_common_defaults() {
        let plan = default_plan();
        assert_eq!(plan.service.cidr_at(0), "10.240.0.0/20");
        assert_eq!(plan.cluster.cidr_at(0), "10.248.0.0/20");
        for collision in &[
            "10.42.0.0/16", // k3s pod default
            "10.43.0.0/16", // k3s service / rke2 default
            "10.96.0.0/12", // kubeadm service default
            "10.0.0.0/16",
        ] {
            assert_ne!(&plan.service.cidr_at(0), collision);
            assert_ne!(&plan.cluster.cidr_at(0), collision);
        }
    }

    #[test]
    fn slots_are_unique_and_non_overlapping() {
        let plan = default_plan();
        let mut svc = std::collections::HashSet::new();
        let mut cls = std::collections::HashSet::new();
        for slot in 0..DEFAULT_SLOTS {
            assert!(svc.insert(plan.service.cidr_at(slot)), "dup svc {slot}");
            assert!(cls.insert(plan.cluster.cidr_at(slot)), "dup cls {slot}");
        }
        assert_eq!(svc.len(), DEFAULT_SLOTS as usize);
        assert_eq!(cls.len(), DEFAULT_SLOTS as usize);
    }

    #[test]
    fn slot_of_round_trips_cidr_at() {
        let plan = default_plan();
        for slot in 0..DEFAULT_SLOTS {
            let s = plan.service.cidr_at(slot);
            assert_eq!(plan.service.slot_of(&s), Some(slot));
            let c = plan.cluster.cidr_at(slot);
            assert_eq!(plan.cluster.slot_of(&c), Some(slot));
        }
    }

    #[test]
    fn slot_of_rejects_outside_parent_block() {
        let plan = default_plan();
        // `/20` slice in 10.43.x.x is outside 10.240.0.0/13.
        assert_eq!(plan.service.slot_of("10.43.0.0/20"), None);
        // Right block, wrong prefix.
        assert_eq!(plan.service.slot_of("10.240.0.0/16"), None);
        // Right block, right prefix, but unaligned.
        assert_eq!(plan.service.slot_of("10.240.0.5/20"), None);
    }

    #[test]
    fn pick_first_free_picks_zero_when_nothing_used() {
        let plan = default_plan();
        let (slot, svc, _) = plan
            .pick_first_free(std::iter::empty::<&str>(), std::iter::empty::<&str>())
            .unwrap();
        assert_eq!(slot, 0);
        assert_eq!(svc, "10.240.0.0/20");
    }

    #[test]
    fn pick_first_free_skips_used_slots() {
        let plan = default_plan();
        let (slot, svc, _) = plan
            .pick_first_free(vec!["10.240.0.0/20"], std::iter::empty::<&str>())
            .unwrap();
        assert_eq!(slot, 1);
        assert_eq!(svc, "10.240.16.0/20");
    }

    #[test]
    fn pick_first_free_finds_first_hole() {
        let plan = default_plan();
        let used = vec![
            "10.240.0.0/20",
            "10.240.16.0/20",
            "10.240.32.0/20",
            "10.240.64.0/20",
        ];
        let (slot, _, _) = plan
            .pick_first_free(used, std::iter::empty::<&str>())
            .unwrap();
        assert_eq!(slot, 3);
    }

    #[test]
    fn pick_first_free_returns_none_when_all_slots_taken() {
        let plan = default_plan();
        let all: Vec<String> = (0..DEFAULT_SLOTS)
            .map(|s| plan.service.cidr_at(s))
            .collect();
        assert!(
            plan.pick_first_free(all, std::iter::empty::<&str>())
                .is_none()
        );
    }

    #[test]
    fn unrecognised_used_cidrs_do_not_block_allocation() {
        let plan = default_plan();
        let (slot, _, _) = plan
            .pick_first_free(
                vec!["192.168.1.0/24", "172.16.0.0/16"],
                std::iter::empty::<&str>(),
            )
            .unwrap();
        assert_eq!(slot, 0);
    }

    #[test]
    fn pick_first_free_honors_both_axes() {
        let plan = default_plan();
        // Slot 0: cluster CIDR taken via the *cluster* used-set.
        // Even though service is free at slot 0, allocator skips to 1.
        let (slot, _, _) = plan
            .pick_first_free(std::iter::empty::<&str>(), vec!["10.248.0.0/20"])
            .unwrap();
        assert_eq!(slot, 1);
    }

    #[test]
    fn capacity_clamps_to_u32_max_for_huge_blocks() {
        // /0 carved into /32 slots = 2^32 slots; doesn't fit in u32.
        // We should saturate, not overflow.
        let plan = PoolPlan::new("0.0.0.0/0", 32, "0.0.0.0/0", 32).unwrap();
        assert_eq!(plan.capacity(), u32::MAX);
    }

    #[test]
    fn capacity_is_smaller_of_two_axes() {
        // Service: /16 carved /20 = 16 slots; Cluster: /14 carved /20 = 64 slots.
        let plan = PoolPlan::new("10.240.0.0/16", 20, "10.244.0.0/14", 20).unwrap();
        assert_eq!(plan.capacity(), 16);
    }
}
