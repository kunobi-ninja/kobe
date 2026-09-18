//! Wake a child placement when the child cluster changes, instead of polling it.
//!
//! The lease controller watches the management cluster. Everything a child
//! placement waits on (the canary Claim, its Sandbox and Pod, the tenant Claim)
//! lives in a different apiserver, so the reconciler used to find out only on
//! the next timer tick, one observable step per tick.
//!
//! This registry keeps one watch per child cluster and turns every event into a
//! reconcile request for the lease that owns it. The child namespace is a fixed
//! name holding exactly one lease's work, so a watch is per cluster, not per
//! object, and the lease it belongs to is known when the watch starts.
//!
//! Failure here is never fatal: a dropped event costs the backstop timer, which
//! is the behaviour the controller had before this existed.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use futures::StreamExt;
use kube::api::ApiResource;
use kube::runtime::reflector::ObjectRef;
use kube::runtime::watcher;
use kube::{Api, Client};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::crd::SandboxLease;

/// How many child clusters may be watched at once.
///
/// Each watch is a few long-lived streams against one child apiserver. The cap
/// keeps a runaway pool from opening an unbounded number of them; leases beyond
/// it still make progress on the backstop timer.
pub(crate) const MAX_CHILD_WATCHES: usize = 64;

/// Pending reconcile requests held before the controller drains them.
///
/// A full queue drops the request rather than blocking the watch: the request
/// is a hint, and the backstop timer covers a lost one.
const TRIGGER_QUEUE: usize = 256;

/// What [`ChildWatchRegistry::decide`] concluded about a watch request.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum WatchDecision {
    /// This cluster is already watched for this lease.
    AlreadyWatching,
    /// Nothing watched this cluster yet.
    Start,
    /// A different lease held this cluster; its watch was cancelled.
    Replace,
    /// The cap is reached, so this cluster stays on the backstop timer.
    Full,
}

struct ActiveWatch {
    lease: ObjectRef<SandboxLease>,
    cancel: CancellationToken,
}

/// One watch per child cluster, keyed by the cluster's instance name.
pub(crate) struct ChildWatchRegistry {
    trigger: mpsc::Sender<ObjectRef<SandboxLease>>,
    shutdown: CancellationToken,
    active: Mutex<HashMap<String, ActiveWatch>>,
}

impl ChildWatchRegistry {
    /// The registry and the stream of reconcile requests it produces.
    pub(crate) fn new(
        shutdown: CancellationToken,
    ) -> (Arc<Self>, mpsc::Receiver<ObjectRef<SandboxLease>>) {
        let (trigger, requests) = mpsc::channel(TRIGGER_QUEUE);
        let registry = Arc::new(Self {
            trigger,
            shutdown,
            active: Mutex::new(HashMap::new()),
        });
        (registry, requests)
    }

    /// Clusters currently watched.
    #[cfg(test)]
    pub(crate) fn watched(&self) -> usize {
        self.lock().len()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, ActiveWatch>> {
        self.active
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Decide what a watch request means, cancelling a watch the request replaces.
    ///
    /// Separated from spawning so the bookkeeping is testable without a cluster.
    fn decide(&self, cluster: &str, lease: &ObjectRef<SandboxLease>) -> WatchDecision {
        let mut active = self.lock();
        match active.get(cluster) {
            Some(existing) if &existing.lease == lease => WatchDecision::AlreadyWatching,
            Some(_) => {
                // The cluster was handed to another lease. The old watch would
                // now wake a lease that no longer owns this cluster.
                if let Some(previous) = active.remove(cluster) {
                    previous.cancel.cancel();
                }
                WatchDecision::Replace
            }
            None if active.len() >= MAX_CHILD_WATCHES => WatchDecision::Full,
            None => WatchDecision::Start,
        }
    }

    /// Stop watching a cluster. Safe to call for a cluster that was never watched.
    pub(crate) fn stop(&self, cluster: &str) {
        if let Some(watch) = self.lock().remove(cluster) {
            watch.cancel.cancel();
        }
    }

    /// Watch `cluster` for `lease`, replacing any watch that cluster already had.
    ///
    /// Idempotent: a reconcile may call this on every pass.
    pub(crate) fn ensure(
        self: &Arc<Self>,
        cluster: &str,
        child: &Client,
        namespace: &str,
        lease: ObjectRef<SandboxLease>,
        resources: Vec<ApiResource>,
    ) {
        match self.decide(cluster, &lease) {
            WatchDecision::AlreadyWatching => return,
            WatchDecision::Full => {
                debug!(
                    cluster = %cluster,
                    watched = MAX_CHILD_WATCHES,
                    "child watch cap reached; this placement advances on its backstop timer"
                );
                return;
            }
            WatchDecision::Start | WatchDecision::Replace => {}
        }

        let cancel = self.shutdown.child_token();
        self.lock().insert(
            cluster.to_string(),
            ActiveWatch {
                lease: lease.clone(),
                cancel: cancel.clone(),
            },
        );

        let registry = Arc::clone(self);
        let cluster_key = cluster.to_string();
        let task = watch_child(
            child.clone(),
            namespace.to_string(),
            resources,
            lease,
            registry.trigger.clone(),
            cancel,
        );
        tokio::spawn(async move {
            task.await;
            // Whatever ended it (cancellation, or every stream giving up), the
            // entry must go: a stale entry would suppress a later watch for the
            // same cluster and leave that lease on timers forever.
            registry.stop(&cluster_key);
        });
    }
}

/// Run one child cluster's watches until cancelled.
async fn watch_child(
    child: Client,
    namespace: String,
    resources: Vec<ApiResource>,
    lease: ObjectRef<SandboxLease>,
    trigger: mpsc::Sender<ObjectRef<SandboxLease>>,
    cancel: CancellationToken,
) {
    let streams = resources.into_iter().map(|resource| {
        let api: Api<kube::api::DynamicObject> =
            Api::namespaced_with(child.clone(), &namespace, &resource);
        watcher::watcher(api, watcher::Config::default()).boxed()
    });
    let mut events = futures::stream::select_all(streams);

    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => return,
            event = events.next() => match event {
                Some(Ok(_)) => {
                    // The reconciler reads the child cluster itself; this only
                    // says "look again now".
                    if trigger.try_send(lease.clone()).is_err() {
                        debug!(lease = %lease.name, "child watch request dropped; the backstop timer covers it");
                    }
                }
                Some(Err(error)) => {
                    // `watcher` reconnects on its own, so this is noise unless
                    // it persists, which shows up as the placement falling back
                    // to timer speed.
                    debug!(lease = %lease.name, error = %error, "child watch error");
                }
                None => {
                    warn!(lease = %lease.name, "child watch ended; falling back to the backstop timer");
                    return;
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lease_ref(name: &str) -> ObjectRef<SandboxLease> {
        ObjectRef::new(name).within("kobe-system")
    }

    fn registry() -> Arc<ChildWatchRegistry> {
        ChildWatchRegistry::new(CancellationToken::new()).0
    }

    /// A reconcile calls `ensure` on every pass, so the second call for the same
    /// lease must not tear down and restart a healthy watch.
    #[test]
    fn the_same_lease_on_the_same_cluster_keeps_its_watch() {
        let registry = registry();
        let lease = lease_ref("sandbox-a");
        assert_eq!(registry.decide("cluster-1", &lease), WatchDecision::Start);
        registry.lock().insert(
            "cluster-1".into(),
            ActiveWatch {
                lease: lease.clone(),
                cancel: CancellationToken::new(),
            },
        );
        assert_eq!(
            registry.decide("cluster-1", &lease),
            WatchDecision::AlreadyWatching
        );
    }

    /// A released cluster goes back to the pool and is leased again. The watch
    /// must follow the new lease, or events would wake a lease that no longer
    /// owns the cluster.
    #[test]
    fn a_relet_cluster_moves_its_watch_to_the_new_lease() {
        let registry = registry();
        let previous = CancellationToken::new();
        registry.lock().insert(
            "cluster-1".into(),
            ActiveWatch {
                lease: lease_ref("sandbox-a"),
                cancel: previous.clone(),
            },
        );

        assert_eq!(
            registry.decide("cluster-1", &lease_ref("sandbox-b")),
            WatchDecision::Replace
        );
        assert!(previous.is_cancelled(), "the old watch must be cancelled");
        assert_eq!(registry.watched(), 0, "the replaced entry is removed");
    }

    #[test]
    fn the_cap_leaves_further_clusters_on_the_backstop_timer() {
        let registry = registry();
        for index in 0..MAX_CHILD_WATCHES {
            registry.lock().insert(
                format!("cluster-{index}"),
                ActiveWatch {
                    lease: lease_ref(&format!("sandbox-{index}")),
                    cancel: CancellationToken::new(),
                },
            );
        }
        assert_eq!(
            registry.decide("one-too-many", &lease_ref("sandbox-x")),
            WatchDecision::Full
        );

        // An existing cluster is still served at the cap: only new ones are refused.
        assert_eq!(
            registry.decide("cluster-0", &lease_ref("sandbox-0")),
            WatchDecision::AlreadyWatching
        );
    }

    #[test]
    fn stopping_cancels_the_watch_and_frees_the_slot() {
        let registry = registry();
        let cancel = CancellationToken::new();
        registry.lock().insert(
            "cluster-1".into(),
            ActiveWatch {
                lease: lease_ref("sandbox-a"),
                cancel: cancel.clone(),
            },
        );

        registry.stop("cluster-1");
        assert!(cancel.is_cancelled());
        assert_eq!(registry.watched(), 0);
        // Stopping something unknown is a no-op, not a panic: release paths run
        // for placements that never had a watch.
        registry.stop("cluster-1");
        registry.stop("never-watched");
    }

    /// Operator shutdown must take the watches with it.
    #[test]
    fn shutdown_cancels_every_watch() {
        let shutdown = CancellationToken::new();
        let (registry, _requests) = ChildWatchRegistry::new(shutdown.clone());
        let cancel = shutdown.child_token();
        registry.lock().insert(
            "cluster-1".into(),
            ActiveWatch {
                lease: lease_ref("sandbox-a"),
                cancel: cancel.clone(),
            },
        );

        shutdown.cancel();
        assert!(cancel.is_cancelled());
    }
}
