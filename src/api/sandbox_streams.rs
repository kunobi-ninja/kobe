//! Lease-scoped stream revocation (#83).
//!
//! # The problem a token expiry does not solve
//!
//! Kubernetes authenticates an upgraded connection **once**, at upgrade time.
//! After that the stream is authenticated for as long as it stays open — a
//! ten-minute token does not close an hour-old exec session, and neither does
//! deleting the ServiceAccount behind it.
//!
//! So a lease that is released, expires, or quarantines has to *actively*
//! cancel its streams. Otherwise the caller keeps a live shell into a workload
//! whose lease has ended, and — worse — teardown proceeds underneath them, so
//! the "verified absent" a receipt reports was verified while somebody was
//! still typing into it.
//!
//! # Per-replica, on purpose
//!
//! Each API replica registers the streams *it* is serving. A replica cannot
//! cancel a connection it does not hold — the socket lives in one process — so
//! revocation has to happen everywhere, driven by each replica's own watch of
//! the same lease objects. There is no leader here, and there must not be: a
//! leader that lost its lock would leave live streams nobody was watching.
//!
//! # Cancel first, then tear down
//!
//! Registration is keyed by lease UID, not lease name. A recreated same-named
//! lease is a different lease with different streams, and cancelling by name
//! would either miss the ones that matter or kill a new caller's session.

use std::collections::HashMap;
use std::sync::Arc;

use futures::StreamExt;
use kube::runtime::watcher;
use kube::{Api, Client, ResourceExt};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::crd::{SandboxLease, SandboxLeasePhase};

/// Live streams this replica is serving, by lease UID.
///
/// `Arc`-shared with the API handlers, which register on upgrade and
/// deregister on close.
#[derive(Debug, Default)]
pub struct StreamRegistry {
    /// Lease UID -> registration id -> cancellation token.
    ///
    /// Keyed by an id rather than held in a `Vec` because a cancellation token
    /// has no identity to compare on: two streams of the same lease are
    /// indistinguishable by value, and removing "one of them" would deregister
    /// somebody else's.
    streams: RwLock<HashMap<String, HashMap<u64, CancellationToken>>>,
    next_id: std::sync::atomic::AtomicU64,
}

/// A registered stream, cancelled when the lease ends and deregistered when it
/// closes on its own.
///
/// Deregistration happens in `Drop` rather than at the end of the handler, so a
/// panicking or early-returning handler cannot leak a registration that would
/// later be "cancelled" long after the socket was gone.
pub struct StreamGuard {
    registry: Arc<StreamRegistry>,
    lease_uid: String,
    id: u64,
    token: CancellationToken,
}

impl StreamGuard {
    /// The token to select on. Cancelled when the lease stops permitting
    /// access, or when this guard is dropped.
    pub fn cancelled(&self) -> CancellationToken {
        self.token.clone()
    }
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        let registry = self.registry.clone();
        let lease_uid = self.lease_uid.clone();
        let id = self.id;
        // The registry lock is async; the guard's drop is not. Detaching is
        // safe because the token is cancelled first: even if the removal runs
        // late, the entry it removes is already dead.
        self.token.cancel();
        tokio::spawn(async move {
            registry.deregister(&lease_uid, id).await;
        });
    }
}

impl StreamRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Register one stream against its lease UID, ignoring the limit.
    ///
    /// Test-only on purpose: every production path must go through
    /// [`register_bounded`], and an unbounded registration in a handler is
    /// precisely the bug that let durable executions escape the per-lease
    /// bound.
    #[cfg(test)]
    pub async fn register(self: &Arc<Self>, lease_uid: &str) -> StreamGuard {
        self.try_register(lease_uid, usize::MAX)
            .await
            .expect("an unbounded registration cannot be refused")
    }

    /// Register only if the lease is under `limit`, deciding both under ONE
    /// lock.
    ///
    /// Checking capacity and then registering as two steps is a race, not a
    /// limit: N concurrent upgrades all observe "under the limit" before any of
    /// them registers, and all N proceed. The count and the insert have to be
    /// the same critical section or the bound is decorative.
    pub async fn try_register(
        self: &Arc<Self>,
        lease_uid: &str,
        limit: usize,
    ) -> Option<StreamGuard> {
        let token = CancellationToken::new();
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let mut streams = self.streams.write().await;
        let held = streams.entry(lease_uid.to_string()).or_default();
        if held.len() >= limit {
            return None;
        }
        held.insert(id, token.clone());
        drop(streams);

        Some(StreamGuard {
            registry: self.clone(),
            lease_uid: lease_uid.to_string(),
            id,
            token,
        })
    }

    async fn deregister(&self, lease_uid: &str, id: u64) {
        let mut streams = self.streams.write().await;
        if let Some(tokens) = streams.get_mut(lease_uid) {
            tokens.remove(&id);
            if tokens.is_empty() {
                streams.remove(lease_uid);
            }
        }
    }

    /// Cancel every stream this replica is serving for one lease.
    ///
    /// Returns how many were cancelled, so the caller can log a revocation that
    /// actually did something rather than one that merely ran.
    pub async fn revoke(&self, lease_uid: &str) -> usize {
        let tokens = self.streams.write().await.remove(lease_uid);
        let Some(tokens) = tokens else {
            return 0;
        };
        for token in tokens.values() {
            token.cancel();
        }
        tokens.len()
    }

    /// How many streams are currently registered for a lease.
    ///
    /// Test-only: enforcing the limit reads the count under the SAME lock that
    /// inserts, so exposing a standalone count would just invite the
    /// check-then-act race back.
    #[cfg(test)]
    pub async fn live_count(&self, lease_uid: &str) -> usize {
        self.streams
            .read()
            .await
            .get(lease_uid)
            .map(HashMap::len)
            .unwrap_or(0)
    }
}

/// How many operations one lease may have in flight on this replica.
///
/// A lease is one Sandbox with one container. Concurrency beyond a handful is
/// not a caller doing something reasonable faster — it is a caller turning
/// their lease into a way to occupy the operator's worker pool, and every
/// in-flight operation holds a connection to the target cluster.
///
/// Per-replica rather than global: the count is of connections *this* process
/// is holding, which is the resource actually being protected. A global count
/// would need coordination that could fail open.
pub const MAX_STREAMS_PER_LEASE: usize = 8;

/// Register one operation for this lease, or refuse because it is at its limit.
///
/// Replaces a separate "may I?" check: asking and then registering is a race
/// that lets every concurrent request pass a limit none of them has taken yet.
pub async fn register_bounded(
    registry: &Arc<StreamRegistry>,
    lease_uid: &str,
) -> Option<StreamGuard> {
    registry
        .try_register(lease_uid, MAX_STREAMS_PER_LEASE)
        .await
}

/// This replica's registry.
///
/// A process global because "per-replica" *is* per-process: the sockets live
/// here, and a registry threaded through request state would be the same
/// object reached by a longer path. Nothing else in the process may hold a
/// second one — two registries would each revoke half the streams.
static REGISTRY: std::sync::OnceLock<Arc<StreamRegistry>> = std::sync::OnceLock::new();

pub fn registry() -> &'static Arc<StreamRegistry> {
    REGISTRY.get_or_init(StreamRegistry::new)
}

/// Whether a lease in this state may keep its streams open.
///
/// Only `Ready` does. `Releasing` in particular must not: teardown has begun,
/// and a stream that outlives its start means cleanup is verifying the absence
/// of something a caller is still using.
pub fn phase_permits_open_streams(phase: SandboxLeasePhase) -> bool {
    phase == SandboxLeasePhase::Ready
}

/// Watch Sandbox leases and cancel this replica's streams when one ends.
///
/// Runs on **every** API replica. A replica cannot cancel a connection it does
/// not hold, so there is no leader to elect and electing one would be actively
/// wrong: a leader that lost its lock would leave live streams nobody was
/// watching.
pub async fn run_stream_revoker(
    client: Client,
    namespace: &str,
    registry: Arc<StreamRegistry>,
    shutdown: tokio_util::sync::CancellationToken,
) {
    let leases: Api<SandboxLease> = Api::namespaced(client, namespace);
    let stream = watcher(leases, watcher::Config::default());
    futures::pin_mut!(stream);

    info!("Starting Sandbox stream revoker");
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            event = stream.next() => {
                match event {
                    Some(Ok(event)) => handle_watch_event(&registry, event).await,
                    Some(Err(error)) => {
                        // The watch restarts itself; log and keep going. Giving
                        // up here would silently stop revoking.
                        warn!(error = %error, "Sandbox lease watch error");
                    }
                    None => break,
                }
            }
        }
    }
    info!("Sandbox stream revoker shut down");
}

/// Act on one watch event.
///
/// Extracted so the EVENT MAPPING is testable, not just the action. Testing
/// `revoke_if_ended` directly proves nothing about which events reach it —
/// which is exactly where this went wrong: handling only `Apply` meant a
/// re-listed lease was silently ignored.
async fn handle_watch_event(registry: &Arc<StreamRegistry>, event: watcher::Event<SandboxLease>) {
    match event {
        // `Apply` AND `InitApply`. A watch that reconnects — after an etcd
        // compaction, an apiserver restart, a network blip — re-lists every
        // object as `InitApply`, and a lease that transitioned to Releasing
        // during the gap arrives ONLY that way. Handling just `Apply` meant
        // revocation quietly stopped working across a reconnect, while the
        // revoker went on looking healthy — worse than not having one.
        watcher::Event::Apply(lease) | watcher::Event::InitApply(lease) => {
            revoke_if_ended(registry, &lease).await;
        }
        // A deleted lease has no phase left to read. Everything it was serving
        // is over by definition.
        watcher::Event::Delete(lease) => {
            if let Some(uid) = lease.uid() {
                let cancelled = registry.revoke(&uid).await;
                if cancelled > 0 {
                    info!(
                        lease = %lease.name_any(),
                        cancelled,
                        "cancelled streams for a deleted Sandbox lease"
                    );
                }
            }
        }
        // `Init`/`InitDone` carry no object.
        watcher::Event::Init | watcher::Event::InitDone => {}
    }
}

async fn revoke_if_ended(registry: &Arc<StreamRegistry>, lease: &SandboxLease) {
    let Some(uid) = lease.uid() else {
        return;
    };
    let phase = lease
        .status
        .as_ref()
        .map(|status| status.phase)
        .unwrap_or_default();
    if phase_permits_open_streams(phase) {
        return;
    }
    let cancelled = registry.revoke(&uid).await;
    if cancelled > 0 {
        info!(
            lease = %lease.name_any(),
            phase = %phase,
            cancelled,
            "cancelled streams for a Sandbox lease that stopped permitting access"
        );
    } else {
        debug!(lease = %lease.name_any(), phase = %phase, "no streams to cancel here");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every phase but Ready closes streams.
    ///
    /// `Releasing` is the one that matters and the least obvious: the Pod may
    /// still be up, so a check that only looked at terminal phases would leave
    /// a caller typing into a workload while teardown verified its absence —
    /// producing a receipt that says "gone" about something in use.
    #[test]
    fn only_a_ready_lease_may_keep_streams_open() {
        assert!(phase_permits_open_streams(SandboxLeasePhase::Ready));
        for phase in [
            SandboxLeasePhase::Pending,
            SandboxLeasePhase::Provisioning,
            SandboxLeasePhase::Releasing,
            SandboxLeasePhase::Released,
            SandboxLeasePhase::Expired,
            SandboxLeasePhase::Quarantined,
        ] {
            assert!(
                !phase_permits_open_streams(phase),
                "{phase} must close streams"
            );
        }
    }

    #[tokio::test]
    async fn revoking_a_lease_cancels_exactly_its_own_streams() {
        let registry = StreamRegistry::new();
        let mine = registry.register("lease-a").await;
        let also_mine = registry.register("lease-a").await;
        let someone_else = registry.register("lease-b").await;

        assert_eq!(registry.live_count("lease-a").await, 2);

        assert_eq!(registry.revoke("lease-a").await, 2);
        assert!(mine.cancelled().is_cancelled());
        assert!(also_mine.cancelled().is_cancelled());
        assert!(
            !someone_else.cancelled().is_cancelled(),
            "another lease's stream must survive"
        );

        // Revoking again is a no-op rather than an error: a replica may see the
        // same terminal phase several times.
        assert_eq!(registry.revoke("lease-a").await, 0);
    }

    /// Registration is keyed by UID, not name.
    ///
    /// A recreated same-named lease is a different lease with different
    /// streams. Keyed by name, revoking the old one would kill the new
    /// caller's session — and revoking the new one would leave the old
    /// caller's shell open through teardown.
    #[tokio::test]
    async fn a_recreated_lease_does_not_inherit_or_destroy_streams() {
        let registry = StreamRegistry::new();
        let old = registry.register("uid-old").await;
        let new = registry.register("uid-new").await;

        assert_eq!(registry.revoke("uid-old").await, 1);
        assert!(old.cancelled().is_cancelled());
        assert!(
            !new.cancelled().is_cancelled(),
            "the successor's stream is not the predecessor's"
        );
    }

    /// A closed stream deregisters itself.
    ///
    /// Otherwise the registry grows for the life of the process, and a later
    /// revocation reports cancelling streams that ended hours ago — which is
    /// worse than useless in an audit trail.
    #[tokio::test]
    async fn a_closed_stream_stops_being_tracked() {
        let registry = StreamRegistry::new();
        {
            let _guard = registry.register("lease-a").await;
            assert_eq!(registry.live_count("lease-a").await, 1);
        }
        // Deregistration is spawned; give it a turn.
        tokio::task::yield_now().await;
        for _ in 0..10 {
            if registry.live_count("lease-a").await == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(registry.live_count("lease-a").await, 0);
        assert_eq!(registry.revoke("lease-a").await, 0);
    }

    /// One lease cannot occupy the replica's worker pool.
    ///
    /// A lease is one Sandbox with one container; concurrency past a handful
    /// is not a caller working faster, it is a caller holding connections. The
    /// limit is per-replica because the connections being protected are the
    /// ones this process holds — a global count would need coordination that
    /// could fail open.
    #[tokio::test]
    async fn one_lease_cannot_open_unbounded_streams() {
        let registry = StreamRegistry::new();
        let mut guards = Vec::new();
        for _ in 0..MAX_STREAMS_PER_LEASE {
            guards.push(
                register_bounded(&registry, "lease-a")
                    .await
                    .expect("under the limit"),
            );
        }
        assert!(
            register_bounded(&registry, "lease-a").await.is_none(),
            "the limit must actually bind"
        );
        // Another lease is unaffected: the limit is per-lease, so one busy
        // caller cannot lock everybody else out.
        assert!(register_bounded(&registry, "lease-b").await.is_some());

        // Closing one frees a slot.
        guards.pop();
        for _ in 0..10 {
            if registry.live_count("lease-a").await < MAX_STREAMS_PER_LEASE {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(register_bounded(&registry, "lease-a").await.is_some());
    }

    /// The bound holds under concurrency, which is the only case that matters.
    ///
    /// Checking capacity and then registering as two steps is a race, not a
    /// limit: every concurrent request observes "under the limit" before any of
    /// them has taken a slot, and all of them proceed. This is the test that
    /// fails if the count and the insert ever stop sharing one critical
    /// section.
    #[tokio::test]
    async fn concurrent_registrations_cannot_overshoot_the_limit() {
        let registry = StreamRegistry::new();
        let attempts: Vec<_> = (0..MAX_STREAMS_PER_LEASE * 4)
            .map(|_| {
                let registry = registry.clone();
                tokio::spawn(async move { register_bounded(&registry, "lease-a").await })
            })
            .collect();

        let mut admitted = Vec::new();
        for attempt in attempts {
            if let Ok(Some(guard)) = attempt.await {
                admitted.push(guard);
            }
        }
        assert_eq!(
            admitted.len(),
            MAX_STREAMS_PER_LEASE,
            "exactly the limit may be admitted, however many race for it"
        );
        assert_eq!(registry.live_count("lease-a").await, MAX_STREAMS_PER_LEASE);
    }

    /// A watch that reconnects must not silently stop revoking.
    ///
    /// After an etcd compaction or an apiserver restart the watcher re-lists
    /// every object as `InitApply`. A lease that transitioned to Releasing
    /// during the gap arrives ONLY that way, so handling just `Apply` meant
    /// revocation quietly stopped working across a reconnect — while the
    /// revoker went on looking healthy, which is worse than not having one.
    ///
    /// Drives the event MAPPING, not `revoke_if_ended`: calling the action
    /// directly would pass no matter which events actually reach it, which is
    /// precisely how this was missed the first time.
    #[tokio::test]
    async fn a_lease_seen_only_on_resync_still_revokes() {
        let ended = || {
            let mut lease = crate::controllers::sandbox::tests::admitted_lease();
            lease.status.as_mut().unwrap().phase = SandboxLeasePhase::Releasing;
            lease
        };

        for event in [
            watcher::Event::InitApply(ended()),
            watcher::Event::Apply(ended()),
            watcher::Event::Delete(ended()),
        ] {
            let registry = StreamRegistry::new();
            let guard = registry.register("lease-uid-1").await;
            handle_watch_event(&registry, event).await;
            assert!(
                guard.cancelled().is_cancelled(),
                "every event carrying an ended lease must cancel its streams"
            );
        }

        // And a LIVE lease is left alone, however it arrives — otherwise the fix
        // would make every resync tear down healthy sessions, which is a worse
        // bug than the one it repairs.
        let ready = || {
            let mut lease = crate::controllers::sandbox::tests::admitted_lease();
            lease.status.as_mut().unwrap().phase = SandboxLeasePhase::Ready;
            lease
        };
        for event in [
            watcher::Event::InitApply(ready()),
            watcher::Event::Apply(ready()),
        ] {
            let registry = StreamRegistry::new();
            let guard = registry.register("lease-uid-1").await;
            handle_watch_event(&registry, event).await;
            assert!(!guard.cancelled().is_cancelled());
        }
    }

    /// A lease that ends cancels its streams; one that is merely updated does
    /// not.
    ///
    /// Leases are patched constantly — conditions, observed generation — and a
    /// revoker that cancelled on every update would make streams unusable
    /// rather than merely revocable.
    #[tokio::test]
    async fn only_an_ended_lease_triggers_revocation() {
        let registry = StreamRegistry::new();
        let guard = registry.register("lease-uid-1").await;

        let mut lease = crate::controllers::sandbox::tests::admitted_lease();
        lease.status.as_mut().unwrap().phase = SandboxLeasePhase::Ready;
        revoke_if_ended(&registry, &lease).await;
        assert!(
            !guard.cancelled().is_cancelled(),
            "a healthy update must not cancel anything"
        );

        lease.status.as_mut().unwrap().phase = SandboxLeasePhase::Releasing;
        revoke_if_ended(&registry, &lease).await;
        assert!(guard.cancelled().is_cancelled());
    }

    /// A lease with no UID cannot be matched to anything, and must not be
    /// treated as matching everything.
    #[tokio::test]
    async fn a_lease_without_a_uid_revokes_nothing() {
        let registry = StreamRegistry::new();
        let guard = registry.register("lease-uid-1").await;

        let mut lease = crate::controllers::sandbox::tests::admitted_lease();
        lease.metadata.uid = None;
        lease.status.as_mut().unwrap().phase = SandboxLeasePhase::Released;
        revoke_if_ended(&registry, &lease).await;

        assert!(!guard.cancelled().is_cancelled());
    }
}
