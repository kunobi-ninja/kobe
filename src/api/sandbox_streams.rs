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

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use futures::StreamExt;
use kube::runtime::watcher;
use kube::{Api, Client, ResourceExt};
use tokio::sync::{RwLock, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::crd::{
    ResolvedSandboxPlacement, SandboxLease, SandboxLeasePhase, SandboxLeaseSpec,
    SandboxTargetProvenance,
};

/// Immutable access identity one upgraded operation was authorized against.
///
/// A stream is not merely owned by a lease UID. The same object can be patched
/// by an administrator while a socket is open, so the requester, admitted pool,
/// placement, exact target and expiry are all retained and compared on every
/// lease watch event. Any drift revokes the old capability instead of silently
/// retargeting it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamIdentity {
    spec: SandboxLeaseSpec,
    observed_generation: Option<i64>,
    ready_at: String,
    expires_at: String,
    placement: ResolvedSandboxPlacement,
    target: SandboxTargetProvenance,
}

impl StreamIdentity {
    /// Snapshot the complete Ready-lease authority used by an operation.
    ///
    /// Missing or elapsed timestamps and incomplete provenance are not an
    /// identity: callers must deny before registering in those states.
    pub fn from_ready_lease(lease: &SandboxLease) -> Option<Self> {
        let status = lease.status.as_ref()?;
        if status.phase != SandboxLeasePhase::Ready {
            return None;
        }
        let ready_at = status.ready_at.clone()?;
        chrono::DateTime::parse_from_rfc3339(&ready_at).ok()?;
        let expires_at = status.expires_at.clone()?;
        let expiry = chrono::DateTime::parse_from_rfc3339(&expires_at).ok()?;
        if expiry <= chrono::Utc::now() {
            return None;
        }
        Some(Self {
            spec: lease.spec.clone(),
            observed_generation: status.observed_generation,
            ready_at,
            expires_at,
            placement: status.placement.clone()?,
            target: status.target.clone()?,
        })
    }

    fn principal_key(&self) -> String {
        crate::api::sandbox::principal_hash_for(&self.spec.requester)
    }

    fn remaining_lifetime(&self) -> Option<std::time::Duration> {
        let expiry = chrono::DateTime::parse_from_rfc3339(&self.expires_at)
            .ok()?
            .with_timezone(&chrono::Utc);
        (expiry - chrono::Utc::now()).to_std().ok()
    }
}

#[derive(Debug)]
struct RegisteredStream {
    identity: StreamIdentity,
    token: CancellationToken,
}

#[derive(Debug, Default)]
struct RegistryState {
    /// Lease UID -> registration id -> exact authority and cancellation token.
    streams: HashMap<String, HashMap<u64, RegisteredStream>>,
    /// Stable principal hash -> number of this replica's active operations.
    principal_counts: HashMap<String, usize>,
}

/// Live streams this replica is serving, indexed by lease UID and accounted
/// atomically by authenticated principal.
///
/// `Arc`-shared with the API handlers, which register on upgrade and
/// deregister on close.
#[derive(Debug, Default)]
pub struct StreamRegistry {
    /// Lease UID -> registration id -> exact authority and cancellation token.
    ///
    /// Keyed by an id rather than held in a `Vec` because a cancellation token
    /// has no identity to compare on: two streams of the same lease are
    /// indistinguishable by value, and removing "one of them" would deregister
    /// somebody else's.
    state: RwLock<RegistryState>,
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
    pub async fn register(
        self: &Arc<Self>,
        lease_uid: &str,
        identity: &StreamIdentity,
    ) -> StreamGuard {
        self.try_register(lease_uid, identity, usize::MAX, usize::MAX)
            .await
            .expect("an unbounded registration cannot be refused")
    }

    /// Register only if the lease and principal are both under their limits,
    /// deciding both under ONE lock.
    ///
    /// Checking capacity and then registering as two steps is a race, not a
    /// limit: N concurrent upgrades all observe "under the limit" before any of
    /// them registers, and all N proceed. The count and the insert have to be
    /// the same critical section or the bound is decorative.
    pub async fn try_register(
        self: &Arc<Self>,
        lease_uid: &str,
        identity: &StreamIdentity,
        lease_limit: usize,
        principal_limit: usize,
    ) -> Option<StreamGuard> {
        // Construction already parsed a future expiry, but the deadline can
        // pass while this request waits for the registry lock. Register with
        // an immediate cancellation in that race so the caller reports an
        // ended lease, not a misleading concurrency-limit response.
        let remaining_lifetime = identity.remaining_lifetime().unwrap_or_default();
        let token = CancellationToken::new();
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let principal_key = identity.principal_key();

        let mut state = self.state.write().await;
        let lease_count = state
            .streams
            .get(lease_uid)
            .map(HashMap::len)
            .unwrap_or_default();
        let principal_count = state
            .principal_counts
            .get(&principal_key)
            .copied()
            .unwrap_or_default();
        if lease_count >= lease_limit || principal_count >= principal_limit {
            return None;
        }
        state
            .streams
            .entry(lease_uid.to_string())
            .or_default()
            .insert(
                id,
                RegisteredStream {
                    identity: identity.clone(),
                    token: token.clone(),
                },
            );
        *state.principal_counts.entry(principal_key).or_default() += 1;
        drop(state);

        // Expiry is a point in time, not a watch event. If the lifecycle
        // controller is delayed, no object update is guaranteed at that exact
        // instant, so every registered operation carries its own local timer.
        let expiry_token = token.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = tokio::time::sleep(remaining_lifetime) => expiry_token.cancel(),
                _ = expiry_token.cancelled() => {}
            }
        });

        Some(StreamGuard {
            registry: self.clone(),
            lease_uid: lease_uid.to_string(),
            id,
            token,
        })
    }

    async fn deregister(&self, lease_uid: &str, id: u64) {
        let mut state = self.state.write().await;
        let removed = if let Some(registrations) = state.streams.get_mut(lease_uid) {
            let removed = registrations.remove(&id);
            if registrations.is_empty() {
                state.streams.remove(lease_uid);
            }
            removed
        } else {
            None
        };
        if let Some(removed) = removed {
            decrement_principal_count(&mut state, &removed.identity.principal_key());
        }
    }

    /// Cancel every stream this replica is serving for one lease.
    ///
    /// Returns how many were cancelled, so the caller can log a revocation that
    /// actually did something rather than one that merely ran.
    pub async fn revoke(&self, lease_uid: &str) -> usize {
        let registrations = {
            let mut state = self.state.write().await;
            let registrations = state.streams.remove(lease_uid);
            if let Some(registrations) = registrations.as_ref() {
                for registration in registrations.values() {
                    decrement_principal_count(&mut state, &registration.identity.principal_key());
                }
            }
            registrations
        };
        let Some(registrations) = registrations else {
            return 0;
        };
        for registration in registrations.values() {
            registration.token.cancel();
        }
        registrations.len()
    }

    /// Cancel registrations whose lease UID disappeared from a complete
    /// apiserver relist.
    ///
    /// A watch reconnect can lose the original `Delete` event. Treating
    /// `InitApply` objects individually is insufficient in that case because
    /// the ended UID is represented by its absence, not by an object. Only an
    /// `InitDone`-bounded set is complete enough to make this decision.
    async fn revoke_absent_from_relist(&self, live_uids: &HashSet<String>) -> usize {
        let registrations = {
            let mut state = self.state.write().await;
            let stale_uids: Vec<_> = state
                .streams
                .keys()
                .filter(|uid| !live_uids.contains(*uid))
                .cloned()
                .collect();
            let registrations: Vec<_> = stale_uids
                .into_iter()
                .filter_map(|uid| state.streams.remove(&uid))
                .collect();
            for by_id in &registrations {
                for registration in by_id.values() {
                    decrement_principal_count(&mut state, &registration.identity.principal_key());
                }
            }
            registrations
        };
        let mut cancelled = 0;
        for by_id in registrations {
            cancelled += by_id.len();
            for registration in by_id.into_values() {
                registration.token.cancel();
            }
        }
        cancelled
    }

    /// Whether every live registration for this lease still names the same
    /// authority observed on the latest watch event.
    async fn lease_matches(&self, lease_uid: &str, identity: &StreamIdentity) -> bool {
        self.state
            .read()
            .await
            .streams
            .get(lease_uid)
            .is_none_or(|registrations| {
                registrations
                    .values()
                    .all(|registration| registration.identity == *identity)
            })
    }

    /// How many streams are currently registered for a lease.
    ///
    /// Test-only: enforcing the limit reads the count under the SAME lock that
    /// inserts, so exposing a standalone count would just invite the
    /// check-then-act race back.
    #[cfg(test)]
    pub async fn live_count(&self, lease_uid: &str) -> usize {
        self.state
            .read()
            .await
            .streams
            .get(lease_uid)
            .map(HashMap::len)
            .unwrap_or(0)
    }

    #[cfg(test)]
    async fn live_principal_count(&self, principal_key: &str) -> usize {
        self.state
            .read()
            .await
            .principal_counts
            .get(principal_key)
            .copied()
            .unwrap_or_default()
    }
}

fn decrement_principal_count(state: &mut RegistryState, principal_key: &str) {
    let Some(count) = state.principal_counts.get_mut(principal_key) else {
        return;
    };
    *count = count.saturating_sub(1);
    if *count == 0 {
        state.principal_counts.remove(principal_key);
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

/// Aggregate operations one authenticated principal may hold on this replica.
///
/// The per-lease limit alone is not a principal limit: a caller with many
/// leases could multiply it until every target connection and API worker was
/// occupied. This bound is intentionally larger than the per-lease allowance
/// so a normal caller can work across several Sandboxes without being able to
/// grow without limit.
pub const MAX_STREAMS_PER_PRINCIPAL: usize = 32;

/// Register one operation for this lease, or refuse because it is at its limit.
///
/// Replaces a separate "may I?" check: asking and then registering is a race
/// that lets every concurrent request pass a limit none of them has taken yet.
pub async fn register_bounded(
    registry: &Arc<StreamRegistry>,
    lease_uid: &str,
    identity: &StreamIdentity,
) -> Option<StreamGuard> {
    registry
        .try_register(
            lease_uid,
            identity,
            MAX_STREAMS_PER_LEASE,
            MAX_STREAMS_PER_PRINCIPAL,
        )
        .await
}

/// Result of atomically claiming a local stream slot and fencing it against
/// the latest lease object.
pub enum ConfirmedStreamRegistration {
    Registered(StreamGuard),
    LimitReached,
    LeaseEnded,
}

/// Register first, then strongly re-read the exact lease before starting work.
///
/// The order closes both sides of the watch race: a deletion event observed
/// before registration is reflected by the GET, while an event after
/// registration cancels the guard already stored in this replica's registry.
/// UID, Ready phase, and deletionTimestamp are checked together so a
/// same-named replacement or direct Kubernetes DELETE cannot open a stream.
pub async fn register_confirmed(
    registry: &Arc<StreamRegistry>,
    leases: &Api<SandboxLease>,
    lease_name: &str,
    expected_uid: &str,
    expected_identity: &StreamIdentity,
) -> Result<ConfirmedStreamRegistration, kube::Error> {
    let Some(guard) = register_bounded(registry, expected_uid, expected_identity).await else {
        return Ok(ConfirmedStreamRegistration::LimitReached);
    };
    let current = match leases.get(lease_name).await {
        Ok(current) => current,
        Err(kube::Error::Api(error)) if error.code == 404 => {
            return Ok(ConfirmedStreamRegistration::LeaseEnded);
        }
        Err(error) => return Err(error),
    };
    let current_uid = current.uid();
    if current_uid.as_deref() != Some(expected_uid)
        || StreamIdentity::from_ready_lease(&current).as_ref() != Some(expected_identity)
        || current.metadata.deletion_timestamp.is_some()
        || current
            .annotations()
            .contains_key(crate::api::sandbox::SANDBOX_RELEASE_REQUESTED_AT_ANNOTATION)
        || guard.cancelled().is_cancelled()
    {
        return Ok(ConfirmedStreamRegistration::LeaseEnded);
    }
    Ok(ConfirmedStreamRegistration::Registered(guard))
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
    initial_sync: oneshot::Sender<Result<(), String>>,
    shutdown: tokio_util::sync::CancellationToken,
) {
    let leases: Api<SandboxLease> = Api::namespaced(client, namespace);
    let stream = watcher(leases, watcher::Config::default());
    futures::pin_mut!(stream);
    let mut initial_sync = Some(initial_sync);
    let mut relist_uids = None;

    info!("Starting Sandbox stream revoker");
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                fail_initial_sync(&mut initial_sync, "shutdown requested before initial lease sync");
                break;
            },
            event = stream.next() => {
                match event {
                    Some(Ok(event)) => {
                        let initial_list_complete = event_completes_initial_sync(&event);
                        handle_watch_event(&registry, event, &mut relist_uids).await;
                        if initial_list_complete {
                            complete_initial_sync(&mut initial_sync);
                        }
                    }
                    Some(Err(error)) => {
                        if initial_sync.is_some() {
                            fail_initial_sync(
                                &mut initial_sync,
                                format!("initial Sandbox lease watch failed: {error}"),
                            );
                            break;
                        }
                        // The watch restarts itself; log and keep going. Giving
                        // up here would silently stop revoking.
                        warn!(error = %error, "Sandbox lease watch error");
                    }
                    None => {
                        fail_initial_sync(
                            &mut initial_sync,
                            "Sandbox lease watch ended before initial sync",
                        );
                        break;
                    }
                }
            }
        }
    }
    info!("Sandbox stream revoker shut down");
}

/// Only the watcher's `InitDone` marker proves the initial LIST is complete.
fn event_completes_initial_sync(event: &watcher::Event<SandboxLease>) -> bool {
    matches!(event, watcher::Event::InitDone)
}

/// Open the per-replica startup barrier after the watch's initial LIST has
/// been fully consumed.
///
/// `InitApply` is not sufficient: a lease omitted later in the same LIST can
/// still determine whether a stream must be revoked. Only `InitDone` proves
/// the replica has a complete baseline before it starts serving Sandbox
/// operations.
fn complete_initial_sync(initial_sync: &mut Option<oneshot::Sender<Result<(), String>>>) {
    if let Some(initial_sync) = initial_sync.take() {
        let _ = initial_sync.send(Ok(()));
    }
}

/// Fail the unopened startup barrier. Errors after `InitDone` are ordinary
/// restartable watch errors and therefore leave the already-open barrier
/// untouched.
fn fail_initial_sync(
    initial_sync: &mut Option<oneshot::Sender<Result<(), String>>>,
    reason: impl Into<String>,
) {
    if let Some(initial_sync) = initial_sync.take() {
        let _ = initial_sync.send(Err(reason.into()));
    }
}

/// Act on one watch event.
///
/// Extracted so the EVENT MAPPING is testable, not just the action. Testing
/// `revoke_if_ended` directly proves nothing about which events reach it —
/// which is exactly where this went wrong: handling only `Apply` meant a
/// re-listed lease was silently ignored.
async fn handle_watch_event(
    registry: &Arc<StreamRegistry>,
    event: watcher::Event<SandboxLease>,
    relist_uids: &mut Option<HashSet<String>>,
) {
    match event {
        // `Apply` AND `InitApply`. A watch that reconnects — after an etcd
        // compaction, an apiserver restart, a network blip — re-lists every
        // object as `InitApply`, and a lease that transitioned to Releasing
        // during the gap arrives ONLY that way. Handling just `Apply` meant
        // revocation quietly stopped working across a reconnect, while the
        // revoker went on looking healthy — worse than not having one.
        watcher::Event::Apply(lease) => {
            revoke_if_ended(registry, &lease).await;
        }
        watcher::Event::InitApply(lease) => {
            if let (Some(seen), Some(uid)) = (relist_uids.as_mut(), lease.uid()) {
                seen.insert(uid);
            }
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
        // A complete relist also communicates absence. Without this set
        // reconciliation, a missed Delete or same-name UID replacement would
        // leave the old socket alive indefinitely.
        watcher::Event::Init => *relist_uids = Some(HashSet::new()),
        watcher::Event::InitDone => {
            if let Some(live_uids) = relist_uids.take() {
                let cancelled = registry.revoke_absent_from_relist(&live_uids).await;
                if cancelled > 0 {
                    info!(
                        cancelled,
                        "cancelled streams absent from Sandbox lease relist"
                    );
                }
            }
        }
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
    // A direct Kubernetes DELETE publishes deletionTimestamp before the
    // lifecycle controller can checkpoint Releasing. Treat it as ended now,
    // or an upgraded connection can survive into finalizer cleanup.
    let deleting = lease.metadata.deletion_timestamp.is_some();
    // The release annotation is the first cross-replica signal. Waiting for
    // the leader to persist Releasing leaves a window in which non-leader API
    // replicas keep serving already-upgraded sockets.
    let release_requested = lease
        .annotations()
        .contains_key(crate::api::sandbox::SANDBOX_RELEASE_REQUESTED_AT_ANNOTATION);
    let identity = StreamIdentity::from_ready_lease(lease);
    let authority_unchanged = match identity.as_ref() {
        Some(identity) => registry.lease_matches(&uid, identity).await,
        None => false,
    };
    if phase_permits_open_streams(phase) && !deleting && !release_requested && authority_unchanged {
        return;
    }
    let cancelled = registry.revoke(&uid).await;
    if cancelled > 0 {
        info!(
            lease = %lease.name_any(),
            phase = %phase,
            deleting,
            release_requested,
            authority_unchanged,
            cancelled,
            "cancelled streams for a Sandbox lease that stopped permitting access"
        );
    } else {
        debug!(
            lease = %lease.name_any(),
            phase = %phase,
            deleting,
            release_requested,
            authority_unchanged,
            "no streams to cancel here"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn ready_lease_for_stream() -> SandboxLease {
        let mut lease = crate::controllers::sandbox::tests::admitted_lease();
        let status = lease.status.as_mut().unwrap();
        status.phase = SandboxLeasePhase::Ready;
        status.ready_at = Some(chrono::Utc::now().to_rfc3339());
        status.expires_at = Some((chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339());
        lease
    }

    fn identity_for(lease: &SandboxLease) -> StreamIdentity {
        StreamIdentity::from_ready_lease(lease).expect("fixture is a complete future Ready lease")
    }

    fn principal_identity(identity: &str) -> StreamIdentity {
        let mut lease = ready_lease_for_stream();
        lease.spec.requester.identity = identity.to_string();
        identity_for(&lease)
    }

    async fn lease_api(server: &MockServer) -> Api<SandboxLease> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        Api::namespaced(crate::testutil::mock_k8s_client(server), "test-ns")
    }

    async fn handle_single_watch_event(
        registry: &Arc<StreamRegistry>,
        event: watcher::Event<SandboxLease>,
    ) {
        handle_watch_event(registry, event, &mut None).await;
    }

    /// The API must remain closed through Init and every InitApply; only the
    /// terminal marker establishes a complete revocation baseline.
    #[tokio::test]
    async fn initial_sync_barrier_opens_only_after_init_done() {
        assert!(!event_completes_initial_sync(&watcher::Event::Init));
        assert!(!event_completes_initial_sync(&watcher::Event::InitApply(
            ready_lease_for_stream()
        )));
        assert!(event_completes_initial_sync(&watcher::Event::InitDone));

        let (sender, receiver) = oneshot::channel();
        let mut sender = Some(sender);
        complete_initial_sync(&mut sender);

        assert_eq!(receiver.await.unwrap(), Ok(()));
        assert!(sender.is_none(), "the barrier must be one-shot");
    }

    /// An initial LIST/watch error must be observable by startup instead of
    /// leaving an API replica serving without a complete revocation baseline.
    #[tokio::test]
    async fn initial_sync_failure_is_reported_fail_closed() {
        let (sender, receiver) = oneshot::channel();
        let mut sender = Some(sender);
        fail_initial_sync(&mut sender, "initial list failed");

        assert_eq!(
            receiver.await.unwrap(),
            Err("initial list failed".to_string())
        );
        assert!(sender.is_none(), "the barrier must be one-shot");
    }

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

    /// If deletion was observed before registration, no guard existed for the
    /// watcher to cancel. The post-registration GET is therefore mandatory.
    #[tokio::test]
    async fn post_registration_get_catches_an_already_missed_delete_event() {
        let server = MockServer::start().await;
        let mut lease = ready_lease_for_stream();
        let expected_identity = identity_for(&lease);
        lease.metadata.deletion_timestamp =
            Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                k8s_openapi::jiff::Timestamp::from_millisecond(
                    chrono::Utc::now().timestamp_millis(),
                )
                .unwrap(),
            ));
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sbx-1",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(lease))
            .expect(1)
            .mount(&server)
            .await;
        let registry = StreamRegistry::new();

        assert!(matches!(
            register_confirmed(
                &registry,
                &lease_api(&server).await,
                "sbx-1",
                "lease-uid-1",
                &expected_identity,
            )
            .await
            .unwrap(),
            ConfirmedStreamRegistration::LeaseEnded
        ));
        tokio::task::yield_now().await;
        assert_eq!(registry.live_count("lease-uid-1").await, 0);
    }

    /// The confirmation GET fences more than phase and UID. An administrator
    /// patch that retargeted the same Ready object before registration must
    /// not authorize a socket against the stale Pod resolved earlier.
    #[tokio::test]
    async fn post_registration_get_catches_already_missed_provenance_drift() {
        let server = MockServer::start().await;
        let expected = ready_lease_for_stream();
        let expected_identity = identity_for(&expected);
        let mut current = expected;
        current
            .status
            .as_mut()
            .unwrap()
            .target
            .as_mut()
            .unwrap()
            .pod
            .as_mut()
            .unwrap()
            .uid = "replacement-pod".into();
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sbx-1",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(current))
            .expect(1)
            .mount(&server)
            .await;
        let registry = StreamRegistry::new();

        assert!(matches!(
            register_confirmed(
                &registry,
                &lease_api(&server).await,
                "sbx-1",
                "lease-uid-1",
                &expected_identity,
            )
            .await
            .unwrap(),
            ConfirmedStreamRegistration::LeaseEnded
        ));
        tokio::task::yield_now().await;
        assert_eq!(registry.live_count("lease-uid-1").await, 0);
    }

    /// Once the guard exists, an event racing the exact GET cancels it. Even a
    /// still-Ready GET response cannot resurrect that registration.
    #[tokio::test]
    async fn watch_event_after_registration_wins_the_confirmation_race() {
        let server = MockServer::start().await;
        let lease = ready_lease_for_stream();
        let expected_identity = identity_for(&lease);
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sbx-1",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(std::time::Duration::from_millis(100))
                    .set_body_json(lease),
            )
            .expect(1)
            .mount(&server)
            .await;
        let registry = StreamRegistry::new();
        let api = lease_api(&server).await;
        let task_registry = registry.clone();
        let task = tokio::spawn(async move {
            register_confirmed(
                &task_registry,
                &api,
                "sbx-1",
                "lease-uid-1",
                &expected_identity,
            )
            .await
        });

        for _ in 0..100 {
            if registry.live_count("lease-uid-1").await == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(registry.live_count("lease-uid-1").await, 1);
        assert_eq!(registry.revoke("lease-uid-1").await, 1);
        assert!(matches!(
            task.await.unwrap().unwrap(),
            ConfirmedStreamRegistration::LeaseEnded
        ));
        tokio::task::yield_now().await;
        assert_eq!(registry.live_count("lease-uid-1").await, 0);
    }

    #[tokio::test]
    async fn revoking_a_lease_cancels_exactly_its_own_streams() {
        let registry = StreamRegistry::new();
        let alice = principal_identity("alice");
        let bob = principal_identity("bob");
        let mine = registry.register("lease-a", &alice).await;
        let also_mine = registry.register("lease-a", &alice).await;
        let someone_else = registry.register("lease-b", &bob).await;

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
        let identity = principal_identity("alice");
        let old = registry.register("uid-old", &identity).await;
        let new = registry.register("uid-new", &identity).await;

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
        let identity = principal_identity("alice");
        let principal_key = identity.principal_key();
        {
            let _guard = registry.register("lease-a", &identity).await;
            assert_eq!(registry.live_count("lease-a").await, 1);
            assert_eq!(registry.live_principal_count(&principal_key).await, 1);
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
        assert_eq!(registry.live_principal_count(&principal_key).await, 0);
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
        let alice = principal_identity("alice");
        let bob = principal_identity("bob");
        let mut guards = Vec::new();
        for _ in 0..MAX_STREAMS_PER_LEASE {
            guards.push(
                register_bounded(&registry, "lease-a", &alice)
                    .await
                    .expect("under the limit"),
            );
        }
        assert!(
            register_bounded(&registry, "lease-a", &alice)
                .await
                .is_none(),
            "the limit must actually bind"
        );
        // Another lease is unaffected: the limit is per-lease, so one busy
        // caller cannot lock everybody else out.
        assert!(register_bounded(&registry, "lease-b", &bob).await.is_some());

        // Closing one frees a slot.
        guards.pop();
        for _ in 0..10 {
            if registry.live_count("lease-a").await < MAX_STREAMS_PER_LEASE {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(
            register_bounded(&registry, "lease-a", &alice)
                .await
                .is_some()
        );
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
        let identity = principal_identity("alice");
        let attempts: Vec<_> = (0..MAX_STREAMS_PER_LEASE * 4)
            .map(|_| {
                let registry = registry.clone();
                let identity = identity.clone();
                tokio::spawn(async move { register_bounded(&registry, "lease-a", &identity).await })
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

    /// A caller cannot multiply the per-lease allowance by acquiring many
    /// leases. Both counts are decided under the same registry lock, so this
    /// bound remains real even when every request races on a different lease.
    #[tokio::test]
    async fn concurrent_leases_cannot_overshoot_the_principal_limit() {
        let registry = StreamRegistry::new();
        let alice = principal_identity("alice");
        let attempts: Vec<_> = (0..MAX_STREAMS_PER_PRINCIPAL * 4)
            .map(|index| {
                let registry = registry.clone();
                let alice = alice.clone();
                tokio::spawn(async move {
                    register_bounded(&registry, &format!("lease-{index}"), &alice).await
                })
            })
            .collect();

        let mut admitted = Vec::new();
        for attempt in attempts {
            if let Ok(Some(guard)) = attempt.await {
                admitted.push(guard);
            }
        }
        assert_eq!(admitted.len(), MAX_STREAMS_PER_PRINCIPAL);
        assert_eq!(
            registry.live_principal_count(&alice.principal_key()).await,
            MAX_STREAMS_PER_PRINCIPAL
        );

        let bob = principal_identity("bob");
        assert!(
            register_bounded(&registry, "bob-lease", &bob)
                .await
                .is_some(),
            "one saturated principal must not lock another out"
        );

        admitted.pop();
        for _ in 0..20 {
            if registry.live_principal_count(&alice.principal_key()).await
                < MAX_STREAMS_PER_PRINCIPAL
            {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(
            register_bounded(&registry, "alice-replacement", &alice)
                .await
                .is_some(),
            "dropping a guard must return its principal slot"
        );
    }

    /// Expiry is not guaranteed to produce a Kubernetes watch event at the
    /// exact deadline. The registration itself therefore owns a timer and
    /// cannot depend on the lifecycle controller being scheduled promptly.
    #[tokio::test]
    async fn expiry_cancels_a_stream_without_a_watch_event() {
        let registry = StreamRegistry::new();
        let mut lease = ready_lease_for_stream();
        lease.status.as_mut().unwrap().expires_at =
            Some((chrono::Utc::now() + chrono::Duration::milliseconds(50)).to_rfc3339());
        let identity = identity_for(&lease);
        let guard = registry.register("lease-uid-1", &identity).await;

        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            guard.cancelled().cancelled(),
        )
        .await
        .expect("the exact expiry must cancel locally");
    }

    /// The release annotation is the first signal every API replica observes;
    /// waiting for the leader's later Releasing status would leave a live
    /// socket during the start of teardown.
    #[tokio::test]
    async fn release_request_revokes_before_the_phase_checkpoint() {
        let registry = StreamRegistry::new();
        let mut lease = ready_lease_for_stream();
        let identity = identity_for(&lease);
        let guard = registry.register("lease-uid-1", &identity).await;
        lease.annotations_mut().insert(
            crate::api::sandbox::SANDBOX_RELEASE_REQUESTED_AT_ANNOTATION.into(),
            chrono::Utc::now().to_rfc3339(),
        );

        handle_single_watch_event(&registry, watcher::Event::Apply(lease)).await;
        assert!(guard.cancelled().is_cancelled());
    }

    /// A Ready phase is not authority to retarget a socket. Any mutation of
    /// the admitted principal/pool/placement/target/expiry fingerprint revokes
    /// the capability that was minted for the old value.
    #[tokio::test]
    async fn ready_provenance_drift_revokes_existing_streams() {
        let mutations: [fn(&mut SandboxLease); 4] = [
            |lease| lease.spec.requester.identity = "mallory".into(),
            |lease| lease.spec.pool_ref.uid = "replacement-pool".into(),
            |lease| {
                lease
                    .status
                    .as_mut()
                    .unwrap()
                    .target
                    .as_mut()
                    .unwrap()
                    .pod
                    .as_mut()
                    .unwrap()
                    .uid = "replacement-pod".into();
            },
            |lease| {
                lease.status.as_mut().unwrap().expires_at =
                    Some((chrono::Utc::now() + chrono::Duration::hours(2)).to_rfc3339());
            },
        ];

        for mutate in mutations {
            let registry = StreamRegistry::new();
            let mut lease = ready_lease_for_stream();
            let identity = identity_for(&lease);
            let guard = registry.register("lease-uid-1", &identity).await;
            mutate(&mut lease);

            handle_single_watch_event(&registry, watcher::Event::Apply(lease)).await;
            assert!(
                guard.cancelled().is_cancelled(),
                "every authority mutation must revoke the old stream"
            );
        }
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
            let identity = identity_for(&ready_lease_for_stream());
            let guard = registry.register("lease-uid-1", &identity).await;
            handle_single_watch_event(&registry, event).await;
            assert!(
                guard.cancelled().is_cancelled(),
                "every event carrying an ended lease must cancel its streams"
            );
        }

        // And a LIVE lease is left alone, however it arrives — otherwise the fix
        // would make every resync tear down healthy sessions, which is a worse
        // bug than the one it repairs.
        let ready = ready_lease_for_stream;
        for event in [
            watcher::Event::InitApply(ready()),
            watcher::Event::Apply(ready()),
        ] {
            let registry = StreamRegistry::new();
            let event_lease = match &event {
                watcher::Event::InitApply(lease) | watcher::Event::Apply(lease) => lease,
                _ => unreachable!(),
            };
            let identity = identity_for(event_lease);
            let guard = registry.register("lease-uid-1", &identity).await;
            handle_single_watch_event(&registry, event).await;
            assert!(!guard.cancelled().is_cancelled());
        }
    }

    /// A full relist communicates that the old UID disappeared even when the
    /// watch never delivered its `Delete`. A same-name replacement must not
    /// inherit the old socket, and the absent old UID must still be revoked.
    #[tokio::test]
    async fn a_recreated_lease_on_relist_revokes_the_absent_old_uid() {
        let registry = StreamRegistry::new();
        let old = ready_lease_for_stream();
        let identity = identity_for(&old);
        let principal_key = identity.principal_key();
        let guard = registry.register("lease-uid-1", &identity).await;

        let mut replacement = old;
        replacement.metadata.uid = Some("lease-uid-2".into());
        let mut relist_uids = None;
        handle_watch_event(&registry, watcher::Event::Init, &mut relist_uids).await;
        handle_watch_event(
            &registry,
            watcher::Event::InitApply(replacement),
            &mut relist_uids,
        )
        .await;
        assert!(!guard.cancelled().is_cancelled());

        handle_watch_event(&registry, watcher::Event::InitDone, &mut relist_uids).await;
        assert!(guard.cancelled().is_cancelled());
        assert_eq!(registry.live_count("lease-uid-1").await, 0);
        assert_eq!(registry.live_principal_count(&principal_key).await, 0);
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
        let mut lease = ready_lease_for_stream();
        let identity = identity_for(&lease);
        let guard = registry.register("lease-uid-1", &identity).await;
        revoke_if_ended(&registry, &lease).await;
        assert!(
            !guard.cancelled().is_cancelled(),
            "a healthy update must not cancel anything"
        );

        lease.status.as_mut().unwrap().phase = SandboxLeasePhase::Releasing;
        revoke_if_ended(&registry, &lease).await;
        assert!(guard.cancelled().is_cancelled());
    }

    /// A direct Kubernetes DELETE must revoke on the Apply carrying
    /// deletionTimestamp, without waiting for Releasing to be persisted.
    #[tokio::test]
    async fn deletion_timestamp_revokes_a_ready_lease_immediately() {
        let registry = StreamRegistry::new();
        let mut lease = ready_lease_for_stream();
        let identity = identity_for(&lease);
        let guard = registry.register("lease-uid-1", &identity).await;
        lease.metadata.deletion_timestamp =
            Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                k8s_openapi::jiff::Timestamp::from_millisecond(
                    chrono::Utc::now().timestamp_millis(),
                )
                .unwrap(),
            ));
        handle_single_watch_event(&registry, watcher::Event::Apply(lease)).await;

        assert!(guard.cancelled().is_cancelled());
    }

    /// A lease with no UID cannot be matched to anything, and must not be
    /// treated as matching everything.
    #[tokio::test]
    async fn a_lease_without_a_uid_revokes_nothing() {
        let registry = StreamRegistry::new();
        let identity = identity_for(&ready_lease_for_stream());
        let guard = registry.register("lease-uid-1", &identity).await;

        let mut lease = crate::controllers::sandbox::tests::admitted_lease();
        lease.metadata.uid = None;
        lease.status.as_mut().unwrap().phase = SandboxLeasePhase::Released;
        revoke_if_ended(&registry, &lease).await;

        assert!(!guard.cancelled().is_cancelled());
    }
}
