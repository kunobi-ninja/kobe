//! Authority-owned, immutable teardown evidence.
//!
//! A `ClusterLease.status.teardownReceipt` is a convenient lifecycle mirror,
//! but status-field RBAC cannot distinguish its producer from other Kobe
//! controllers. Consumers therefore authorize release only from this separate
//! CRD, whose write verbs and admission identity belong exclusively to the
//! teardown-authority ServiceAccount.

use kube::{CustomResource, KubeSchema};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crd::{KubernetesResourceIdentity, ResourceRef, TeardownReceipt};

/// Label proving which exact lease UID feeds a deterministic evidence name.
pub const TEARDOWN_EVIDENCE_LEASE_DIGEST_LABEL: &str = "kobe.kunobi.ninja/teardown-lease-digest";
/// Label proving which exact attempt nonce feeds a deterministic evidence name.
pub const TEARDOWN_EVIDENCE_ATTEMPT_DIGEST_LABEL: &str =
    "kobe.kunobi.ninja/teardown-attempt-digest";
/// Fixed producer label checked on create, restart adoption, and consumption.
pub const TEARDOWN_EVIDENCE_PRODUCER_LABEL: &str = "kobe.kunobi.ninja/teardown-evidence-producer";

/// Immutable identity labels for one deterministic evidence object.
///
/// Labels are consistency fences, not authentication on their own. The
/// fail-closed admission policy supplies producer authentication; these hashes
/// make a restart prove that an existing object still names the exact lease UID
/// and attempt it is about without putting arbitrary input into label values.
#[allow(dead_code)] // `crdgen` compiles this module without controller consumers.
pub fn verified_teardown_evidence_labels(
    lease_uid: &str,
    attempt_id: &str,
) -> std::collections::BTreeMap<String, String> {
    let digest = |domain: &str, value: &str| {
        let digest = Sha256::digest(format!("{domain}\0{value}").as_bytes());
        hex::encode(digest)[..40].to_string()
    };
    std::collections::BTreeMap::from([
        (
            TEARDOWN_EVIDENCE_LEASE_DIGEST_LABEL.into(),
            digest("lease", lease_uid),
        ),
        (
            TEARDOWN_EVIDENCE_ATTEMPT_DIGEST_LABEL.into(),
            digest("attempt", attempt_id),
        ),
        (
            TEARDOWN_EVIDENCE_PRODUCER_LABEL.into(),
            "teardown-authority".into(),
        ),
    ])
}

#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, KubeSchema, PartialEq, Eq)]
#[kube(
    group = "kobe.kunobi.ninja",
    version = "v1alpha1",
    kind = "VerifiedTeardownEvidence",
    plural = "verifiedteardownevidence",
    shortname = "vte",
    namespaced,
    validation = Rule::new("self.spec == oldSelf.spec")
        .message("verified teardown evidence is immutable"),
    validation = Rule::new("self.spec.attemptId == self.spec.receipt.attemptId && self.spec.lease == self.spec.receipt.lease")
        .message("evidence identity must match its embedded receipt"),
    validation = Rule::new("self.spec.receipt.outcome == 'verified' && self.spec.receipt.cleanupMode == 'VerifiedDestroy'")
        .message("only a VerifiedDestroy terminal receipt can be authoritative evidence"),
    printcolumn = r#"{"name":"Lease","type":"string","jsonPath":".spec.lease.name"}"#,
    printcolumn = r#"{"name":"Attempt","type":"string","jsonPath":".spec.attemptId"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedTeardownEvidenceSpec {
    /// Exact ClusterLease capability this record certifies.
    pub lease: ResourceRef,
    /// Durable attempt nonce, duplicated outside the receipt for indexing and
    /// admission validation.
    #[schemars(length(min = 1))]
    pub attempt_id: String,
    /// Full terminal receipt produced by the isolated teardown authority.
    pub receipt: TeardownReceipt,
}

/// Exact immutable evidence object checkpointed by a consumer before ACK.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TeardownEvidenceReference {
    #[schemars(length(min = 1))]
    pub name: String,
    #[schemars(length(min = 1))]
    pub uid: String,
    #[schemars(range(min = 1))]
    pub generation: i64,
    #[schemars(length(min = 1))]
    pub resource_version: String,
}

/// Authority-owned acknowledgement that a distinct consumer durably
/// checkpointed the exact teardown proof before the producer releases its
/// retention finalizer.
///
/// The ordinary lifecycle ServiceAccount cannot write this field. In the Helm
/// split deployment the receipt authority derives it from the live
/// `SandboxLease` checkpoint and the immutable evidence object; the producer
/// never accepts a caller-supplied acknowledgement.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TeardownAcknowledgement {
    #[schemars(length(min = 1))]
    pub attempt_id: String,
    pub consumer: KubernetesResourceIdentity,
    pub proof: TeardownAcknowledgedProof,
    #[schemars(extend("format" = "date-time"))]
    pub acknowledged_at: String,
}

/// Exact proof copied by the consumer before an authority may acknowledge it.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TeardownAcknowledgedProof {
    pub kind: TeardownAcknowledgedProofKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(equal = 71), pattern("^sha256:[0-9a-f]{64}$"))]
    pub receipt_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<TeardownEvidenceReference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("format" = "date-time"))]
    pub unbound_release_verified_at: Option<String>,
}

/// Discriminator for [`TeardownAcknowledgedProof`]. The optional payload
/// fields intentionally live in one structural object: Kubernetes CRD schemas
/// cannot merge internally-tagged enum variants that give `kind` different
/// enum constraints. The `ClusterLease` CEL rule enforces the exact payload
/// for each variant.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum TeardownAcknowledgedProofKind {
    Receipt,
    NeverBound,
}

// `crdgen` compiles this module without controller consumers.
#[allow(dead_code)]
impl TeardownAcknowledgedProof {
    pub fn receipt(receipt_token: String, evidence: TeardownEvidenceReference) -> Self {
        Self {
            kind: TeardownAcknowledgedProofKind::Receipt,
            receipt_token: Some(receipt_token),
            evidence: Some(evidence),
            unbound_release_verified_at: None,
        }
    }

    pub fn never_bound(unbound_release_verified_at: String) -> Self {
        Self {
            kind: TeardownAcknowledgedProofKind::NeverBound,
            receipt_token: None,
            evidence: None,
            unbound_release_verified_at: Some(unbound_release_verified_at),
        }
    }
}

/// Deterministic name for one lease teardown attempt. The human-readable lease
/// name is intentionally not authority; both exact UIDs/nonces feed the hash.
#[allow(dead_code)] // `crdgen` compiles this module without controller consumers.
pub fn verified_teardown_evidence_name(lease_uid: &str, attempt_id: &str) -> String {
    let digest = Sha256::digest(format!("{lease_uid}\0{attempt_id}").as_bytes());
    let encoded = hex::encode(digest);
    format!("vte-{}", &encoded[..40])
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::CustomResourceExt;

    #[test]
    fn name_is_bound_to_exact_lease_uid_and_attempt() {
        let first = verified_teardown_evidence_name("uid-a", "attempt-a");
        assert_eq!(first, verified_teardown_evidence_name("uid-a", "attempt-a"));
        assert_ne!(first, verified_teardown_evidence_name("uid-b", "attempt-a"));
        assert_ne!(first, verified_teardown_evidence_name("uid-a", "attempt-b"));
        assert!(first.len() <= 63);
    }

    #[test]
    fn identity_labels_are_bounded_and_bind_both_inputs() {
        let first = verified_teardown_evidence_labels("uid-a", "attempt-a");
        let other_lease = verified_teardown_evidence_labels("uid-b", "attempt-a");
        let other_attempt = verified_teardown_evidence_labels("uid-a", "attempt-b");
        assert_ne!(
            first[TEARDOWN_EVIDENCE_LEASE_DIGEST_LABEL],
            other_lease[TEARDOWN_EVIDENCE_LEASE_DIGEST_LABEL]
        );
        assert_ne!(
            first[TEARDOWN_EVIDENCE_ATTEMPT_DIGEST_LABEL],
            other_attempt[TEARDOWN_EVIDENCE_ATTEMPT_DIGEST_LABEL]
        );
        assert!(first.values().all(|value| value.len() <= 63));
        assert_eq!(
            first[TEARDOWN_EVIDENCE_PRODUCER_LABEL],
            "teardown-authority"
        );
    }

    #[test]
    fn crd_makes_evidence_immutable() {
        let crd = serde_json::to_value(VerifiedTeardownEvidence::crd()).unwrap();
        let rules =
            crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["x-kubernetes-validations"]
                .as_array()
                .unwrap();
        assert!(
            rules
                .iter()
                .any(|rule| rule["rule"] == "self.spec == oldSelf.spec")
        );
        assert!(rules.iter().any(|rule| {
            rule["rule"]
                == "self.spec.receipt.outcome == 'verified' && self.spec.receipt.cleanupMode == 'VerifiedDestroy'"
        }));
    }
}
