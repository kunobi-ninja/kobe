use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// ClusterLease is the internal representation of a cluster lease.
///
/// Created when a user/CI leases a cluster via the HTTP API.
/// The lease controller binds it to a warm cluster, tracks TTL,
/// and handles release/expiry/recycling.
#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "kobe.kunobi.ninja",
    version = "v1alpha1",
    kind = "ClusterLease",
    plural = "clusterleases",
    shortname = "cl",
    status = "ClusterLeaseStatus",
    namespaced
)]
#[serde(rename_all = "camelCase")]
pub struct ClusterLeaseSpec {
    /// Which profile's pool to lease from.
    pub pool_ref: String,

    /// Requested TTL (e.g. "1h", "30m").
    pub ttl: String,

    /// Identity of the requester.
    pub requester: Requester,

    /// Lease priority for queue ordering.
    /// Higher values are served first.
    #[serde(default = "default_priority")]
    pub priority: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Requester {
    /// Type of requester: "{provider}:{role}" (e.g. "github-actions:ci", "clerk:admin").
    #[serde(rename = "type")]
    pub requester_type: String,

    /// Identity string (e.g. "repo:org/repo:ref:refs/heads/main" for GitHub,
    /// or user ID for Clerk).
    pub identity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct ClusterLeaseStatus {
    /// Current phase of the lease lifecycle.
    #[serde(default)]
    pub phase: LeasePhase,

    /// Name of the bound cluster (set when phase=Bound).
    // skip_serializing_if: never serialize None, so a controller doing
    // pass-through preservation that momentarily reads it as None cannot erase it
    // via a JSON-Merge-Patch null (RFC 7396). Only ever set, never cleared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster_name: Option<String>,

    /// When the lease was bound to a vcluster.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_at: Option<String>,

    /// When the lease expires (TTL deadline).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,

    /// Position in the priority queue (0 = not queued, 1 = next).
    #[serde(default)]
    pub queue_position: u32,

    /// URL to the diagnostic bundle captured on release.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostics_url: Option<String>,

    /// Number of TTL extensions granted for this lease.
    #[serde(default)]
    pub extensions_count: u32,

    /// Maximum number of extensions allowed (from policy).
    #[serde(default)]
    pub max_extensions: u32,

    /// Human-readable explanation of the lease's current state, set when the
    /// reason is non-obvious — primarily why a `Pending` lease has not bound
    /// (e.g. "no Ready cluster; pool p phase=Failing, consecutiveFailures=3,
    /// lastFailureReason=..."). Lets a client distinguish "warming up" from
    /// "this pool will never satisfy me" without scraping pool status itself.
    ///
    /// skip_serializing_if: omit when None so a JSON-Merge-Patch (RFC 7396)
    /// pass-through preservation can't erase a previously-set message via an
    /// explicit null.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// Standard Kubernetes-style status conditions, derived by the lease
    /// controller from `phase` / `cluster_name` / `message` (see
    /// `derive_lease_conditions`). Mirrors `ClusterInstanceStatus.conditions`.
    /// Currently emitted: `Bound` (True once a cluster is assigned) and
    /// `Satisfiable` (False on the no-Ready-cluster path, carrying the
    /// unsatisfiable reason). These give `kubectl` and ops tooling a familiar,
    /// machine-readable surface for *why* the lease is where it is, alongside
    /// the human-readable `message`.
    ///
    /// `skip_serializing_if = "Vec::is_empty"` protects the list from
    /// Merge-Patch erasure, same pattern as `message`: a writer that emits an
    /// empty `Vec` (e.g. a status patch that only touches another field) must
    /// omit the key entirely — otherwise a JSON Merge Patch carrying
    /// `"conditions": []` would replace the on-disk list with an empty one
    /// (RFC 7396 / array-replacement).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<ClusterLeaseCondition>,
}

/// One status condition on a `ClusterLease`. Mirrors the core/v1 condition
/// shape (type/status/reason/message/lastTransitionTime) — and
/// `ClusterInstanceCondition` — so kubectl and operators see a familiar
/// surface across all Kobe resources.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ClusterLeaseCondition {
    /// Condition name. Emitted values: `Bound`, `Satisfiable`.
    #[serde(rename = "type")]
    pub condition_type: String,

    /// One of: `True`, `False`, `Unknown`.
    pub status: String,

    /// Machine-readable reason. For `Bound` this is the current phase
    /// (e.g. `Bound`, `Pending`, `Expired`). For `Satisfiable` it is the
    /// unsatisfiable classification (e.g. `Warming`, `PoolExhausted`) on the
    /// no-Ready-cluster path, or the phase otherwise.
    pub reason: String,

    /// Human-readable detail, generally a copy of `status.message` for the
    /// current state (or empty when there is none).
    pub message: String,

    /// RFC3339 of the last status change. Updated only when `status`
    /// flips (True ↔ False ↔ Unknown), not on every reconcile, so tools
    /// tailing `kubectl get -w` see meaningful transitions rather than churn.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_transition_time: Option<String>,
}

/// Lease lifecycle phases.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default, PartialEq)]
pub enum LeasePhase {
    /// Waiting for a warm cluster to become available.
    #[default]
    Pending,
    /// Bound to a cluster.
    Bound,
    /// Explicitly released by the user.
    Released,
    /// TTL expired, cluster being reclaimed.
    Expired,
    /// Cluster being deleted and recreated.
    Recycling,
}

impl std::fmt::Display for LeasePhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LeasePhase::Pending => write!(f, "Pending"),
            LeasePhase::Bound => write!(f, "Bound"),
            LeasePhase::Released => write!(f, "Released"),
            LeasePhase::Expired => write!(f, "Expired"),
            LeasePhase::Recycling => write!(f, "Recycling"),
        }
    }
}

/// Default priority: normal (50).
fn default_priority() -> u32 {
    50
}

#[cfg(test)]
mod json_safety_tests {
    use super::*;

    #[test]
    fn status_omits_none_preserve_fields_so_merge_patch_cannot_erase_them() {
        // With skip_serializing_if, a None preserve-field is OMITTED from the
        // serialized status. A JSON Merge Patch (RFC 7396) then leaves the
        // on-disk value untouched, instead of deleting it via an explicit null —
        // so a controller doing pass-through preservation can't erase a field it
        // momentarily read as None.
        let none_status = ClusterLeaseStatus {
            phase: LeasePhase::Bound,
            ..Default::default()
        };
        let v = serde_json::to_value(&none_status).unwrap();
        assert!(
            v.get("clusterName").is_none(),
            "clusterName must be omitted when None"
        );
        assert!(
            v.get("boundAt").is_none(),
            "boundAt must be omitted when None"
        );
        assert!(
            v.get("expiresAt").is_none(),
            "expiresAt must be omitted when None"
        );
        assert!(
            v.get("diagnosticsUrl").is_none(),
            "diagnosticsUrl must be omitted when None"
        );

        // Set values are still serialized.
        let set_status = ClusterLeaseStatus {
            phase: LeasePhase::Bound,
            cluster_name: Some("pool-x-0".into()),
            bound_at: Some("2026-06-04T00:00:00Z".into()),
            expires_at: Some("2026-06-04T01:00:00Z".into()),
            ..Default::default()
        };
        let v = serde_json::to_value(&set_status).unwrap();
        assert_eq!(
            v.get("clusterName").and_then(|x| x.as_str()),
            Some("pool-x-0")
        );
        assert_eq!(
            v.get("boundAt").and_then(|x| x.as_str()),
            Some("2026-06-04T00:00:00Z")
        );
    }

    #[test]
    fn empty_conditions_are_omitted_from_serialized_status() {
        // An empty `conditions` Vec must NOT serialize (skip_serializing_if =
        // Vec::is_empty), so a Merge-Patch from a writer that does not set
        // conditions never carries `"conditions": []` — which would erase a
        // previously-derived list per RFC 7396 array-replacement.
        let st = ClusterLeaseStatus {
            phase: LeasePhase::Pending,
            ..Default::default()
        };
        let v = serde_json::to_value(&st).unwrap();
        assert!(
            v.get("conditions").is_none(),
            "empty conditions must be omitted, got: {v}"
        );

        // A populated list serializes with camelCase keys.
        let st = ClusterLeaseStatus {
            phase: LeasePhase::Bound,
            conditions: vec![ClusterLeaseCondition {
                condition_type: "Bound".into(),
                status: "True".into(),
                reason: "Bound".into(),
                message: "running".into(),
                last_transition_time: Some("2026-06-04T00:00:00Z".into()),
            }],
            ..Default::default()
        };
        let v = serde_json::to_value(&st).unwrap();
        let conds = v.get("conditions").and_then(|c| c.as_array()).unwrap();
        assert_eq!(conds.len(), 1);
        assert_eq!(conds[0].get("type").and_then(|x| x.as_str()), Some("Bound"));
        assert_eq!(
            conds[0].get("lastTransitionTime").and_then(|x| x.as_str()),
            Some("2026-06-04T00:00:00Z")
        );
    }

    /// The serialized form of `LeasePhase` is a WIRE CONTRACT, not an
    /// implementation detail.
    ///
    /// `kobectl` reads the phase out of the API response as a *string*
    /// and compares it against literals — `is_terminal_failure_phase`
    /// matches "expired" / "released" / "recycling" case-insensitively to
    /// decide whether to stop waiting on a lease. A `#[serde(rename)]` or
    /// a renamed variant here would not fail to compile anywhere; the CLI
    /// would just silently stop recognising terminal leases and wait out
    /// its full timeout on a lease that was never going to bind.
    #[test]
    fn lease_phase_serializes_as_the_bare_variant_name() {
        for (phase, wire) in [
            (LeasePhase::Pending, "Pending"),
            (LeasePhase::Bound, "Bound"),
            (LeasePhase::Released, "Released"),
            (LeasePhase::Expired, "Expired"),
            (LeasePhase::Recycling, "Recycling"),
        ] {
            assert_eq!(
                serde_json::to_value(&phase).unwrap(),
                serde_json::Value::String(wire.to_string()),
                "{phase:?} must serialize as the bare name {wire:?} — kobectl \
                 string-matches this"
            );
            let back: LeasePhase = serde_json::from_str(&format!("\"{wire}\"")).unwrap();
            assert_eq!(back, phase, "{wire:?} must round-trip back to {phase:?}");
        }
    }

    /// `Display` and the serde form must agree.
    ///
    /// Both reach users: the serde form goes over the API to the CLI's
    /// phase comparison, and `Display` is what the CLI prints back
    /// ("Lease {id} ended in phase {phase}"). If they diverged, an error
    /// message would name a phase that the code matching on it would not
    /// recognise — the most confusing possible failure.
    #[test]
    fn lease_phase_display_matches_the_serialized_form() {
        for phase in [
            LeasePhase::Pending,
            LeasePhase::Bound,
            LeasePhase::Released,
            LeasePhase::Expired,
            LeasePhase::Recycling,
        ] {
            let serialized = serde_json::to_value(&phase).unwrap();
            assert_eq!(
                serialized.as_str().unwrap(),
                phase.to_string(),
                "Display and serde disagree for {phase:?}"
            );
        }
    }

    /// Phase defaults to `Pending`: a status written without one describes
    /// a lease that has not bound, which is the safe reading. Defaulting
    /// to `Bound` would make an unbound lease look served.
    #[test]
    fn phase_defaults_to_pending() {
        let st: ClusterLeaseStatus = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(st.phase, LeasePhase::Pending);
        assert_eq!(LeasePhase::default(), LeasePhase::Pending);
    }

    /// The spec binds camelCase only. The API server writes these CRs, and
    /// the CRD schema declares `poolRef` — a snake_case key would be
    /// dropped as an unknown field rather than rejected, leaving a lease
    /// with no pool.
    #[test]
    fn spec_binds_camel_case_keys_only() {
        let ok: ClusterLeaseSpec = serde_json::from_value(serde_json::json!({
            "poolRef": "ci-small",
            "ttl": "1h",
            "requester": { "type": "github-actions:ci", "identity": "repo:org/repo" }
        }))
        .expect("camelCase spec must bind");
        assert_eq!(ok.pool_ref, "ci-small");

        let snake = serde_json::from_value::<ClusterLeaseSpec>(serde_json::json!({
            "pool_ref": "ci-small",
            "ttl": "1h",
            "requester": { "type": "github-actions:ci", "identity": "repo:org/repo" }
        }));
        assert!(
            snake.is_err(),
            "snake_case `pool_ref` must not bind — it would silently leave poolRef unset"
        );
    }

    /// `priority` is optional and defaults to normal. The queue sorts on
    /// it descending, so a wrong default would silently re-order every
    /// lease that omits it.
    #[test]
    fn priority_defaults_to_normal_when_absent() {
        let spec: ClusterLeaseSpec = serde_json::from_value(serde_json::json!({
            "poolRef": "p", "ttl": "1h",
            "requester": { "type": "t", "identity": "i" }
        }))
        .unwrap();
        assert_eq!(spec.priority, 50);

        let explicit: ClusterLeaseSpec = serde_json::from_value(serde_json::json!({
            "poolRef": "p", "ttl": "1h", "priority": 99,
            "requester": { "type": "t", "identity": "i" }
        }))
        .unwrap();
        assert_eq!(explicit.priority, 99);
    }

    /// `Requester.requester_type` is spelled `type` on the wire — the
    /// Rust field can't be, so this rename is the only thing keeping the
    /// stored CR readable by every writer of it.
    #[test]
    fn requester_type_is_named_type_on_the_wire() {
        let r = Requester {
            requester_type: "github-actions:ci".into(),
            identity: "repo:org/repo".into(),
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(
            v.get("type").and_then(|x| x.as_str()),
            Some("github-actions:ci")
        );
        assert!(
            v.get("requesterType").is_none() && v.get("requester_type").is_none(),
            "the Rust field name must not leak onto the wire, got: {v}"
        );
    }

    /// A condition with no recorded transition omits the key rather than
    /// writing null, so a Merge-Patch can't erase a timestamp another
    /// writer set. Same rule as `message` and `conditions` above.
    #[test]
    fn condition_omits_last_transition_time_when_unset() {
        let c = ClusterLeaseCondition {
            condition_type: "Satisfiable".into(),
            status: "False".into(),
            reason: "Warming".into(),
            message: "no Ready cluster".into(),
            last_transition_time: None,
        };
        let v = serde_json::to_value(&c).unwrap();
        assert!(
            v.get("lastTransitionTime").is_none(),
            "unset lastTransitionTime must be omitted, not null: {v}"
        );
    }

    /// A status written by a NEWER operator must still deserialize, or a
    /// rolling upgrade wedges the older replica on every lease it reads.
    #[test]
    fn status_from_a_newer_operator_still_deserializes() {
        let st: ClusterLeaseStatus = serde_json::from_value(serde_json::json!({
            "phase": "Bound",
            "clusterName": "pool-x-0",
            "someFieldFromTheFuture": { "nested": true }
        }))
        .expect("unknown fields must be ignored, not rejected");
        assert_eq!(st.phase, LeasePhase::Bound);
        assert_eq!(st.cluster_name.as_deref(), Some("pool-x-0"));
    }

    /// Serialize → deserialize → serialize is a fixed point, so a
    /// controller that reads a status and writes it back unchanged does
    /// not perturb it.
    #[test]
    fn status_round_trip_is_a_fixed_point() {
        let original = ClusterLeaseStatus {
            phase: LeasePhase::Bound,
            cluster_name: Some("pool-x-0".into()),
            bound_at: Some("2026-06-04T00:00:00Z".into()),
            expires_at: Some("2026-06-04T01:00:00Z".into()),
            queue_position: 0,
            diagnostics_url: None,
            extensions_count: 1,
            max_extensions: 3,
            message: Some("bound".into()),
            conditions: vec![ClusterLeaseCondition {
                condition_type: "Bound".into(),
                status: "True".into(),
                reason: "Bound".into(),
                message: "bound".into(),
                last_transition_time: Some("2026-06-04T00:00:00Z".into()),
            }],
        };
        let once = serde_json::to_value(&original).unwrap();
        let back: ClusterLeaseStatus = serde_json::from_value(once.clone()).unwrap();
        assert_eq!(serde_json::to_value(&back).unwrap(), once);
    }

    /// The CRD's public identity. Changing any of these is a breaking
    /// change for every `kubectl` invocation and manifest in the wild.
    #[test]
    fn crd_identity_is_stable() {
        use kube::CustomResourceExt;
        let crd = serde_json::to_value(ClusterLease::crd()).unwrap();

        assert_eq!(crd["spec"]["group"], "kobe.kunobi.ninja");
        assert_eq!(crd["spec"]["scope"], "Namespaced");
        assert_eq!(crd["spec"]["names"]["kind"], "ClusterLease");
        assert_eq!(crd["spec"]["names"]["plural"], "clusterleases");
        assert_eq!(crd["spec"]["names"]["shortNames"][0], "cl");
        assert_eq!(crd["metadata"]["name"], "clusterleases.kobe.kunobi.ninja");

        let versions = crd["spec"]["versions"].as_array().unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0]["name"], "v1alpha1");
        assert_eq!(versions[0]["served"], true);
        assert_eq!(versions[0]["storage"], true);
    }

    /// `status` must be a real subresource, or the apiserver silently
    /// discards every `patch_status` the lease controller issues and no
    /// lease ever leaves `Pending`.
    #[test]
    fn crd_declares_the_status_subresource() {
        use kube::CustomResourceExt;
        let crd = serde_json::to_value(ClusterLease::crd()).unwrap();
        let versions = crd["spec"]["versions"].as_array().unwrap();
        assert!(
            versions[0]["subresources"].get("status").is_some(),
            "status subresource missing: {}",
            versions[0]["subresources"]
        );
    }

    #[test]
    fn legacy_status_without_conditions_deserializes() {
        // Back-compat: a ClusterLease persisted before the conditions field
        // existed (no `conditions` key) must still deserialize, defaulting to
        // an empty Vec.
        let legacy = serde_json::json!({
            "phase": "Bound",
            "clusterName": "pool-x-0",
            "expiresAt": "2026-06-04T01:00:00Z",
            "queuePosition": 0,
            "extensionsCount": 0,
            "maxExtensions": 2
        });
        let status: ClusterLeaseStatus = serde_json::from_value(legacy).unwrap();
        assert_eq!(status.phase, LeasePhase::Bound);
        assert!(
            status.conditions.is_empty(),
            "missing conditions must default to an empty Vec"
        );
    }
}
