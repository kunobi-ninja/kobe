//! The one JSON error body every `/v1` lease and pool route answers with.
//!
//! Cluster and Sandbox routes used to carry two same-shaped structs whose
//! `reason` fields had different types, so the set of reasons a client could
//! see was only knowable by reading both trees. [`ApiError`] is the single
//! shape, and [`ApiErrorReason`] is the closed set of values `reason` can
//! take. Adding a variant is a wire-visible change: document it in
//! `docs/kobe-docs/api/reference.mdx` in the same commit.
//!
//! The connect proxy (`/connect/...`) is not covered: it answers the
//! Kubernetes client that is using the lease, and keeps plain-text errors.

use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// Bounded, machine-readable reason for a refused request, so a client can
/// branch on *why* without parsing the human `error` string.
///
/// Serialized as the snake_case variant name. Every `429` carries one, which
/// is how a client tells a hard limit ([`Self::QuotaExhausted`]) from
/// throttling it should wait out ([`Self::RateLimited`], [`Self::ServerBusy`]).
#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ApiErrorReason {
    // --- Admission and capacity -------------------------------------------
    /// Pool phase is `Failing`; it will not satisfy a lease without operator
    /// attention.
    PoolExhausted,
    /// Pool is in a backoff window with no schedulable headroom.
    CapacityBlocked,
    /// Pool is otherwise degraded.
    Degraded,
    /// Healthy-but-empty warm pool that is still coming up.
    Warming,
    /// The pool name exists as the other resource kind (Cluster vs Sandbox).
    WrongResourceKind,
    /// Another create for the same caller held the admission lock for the
    /// whole wait budget. Nothing was created; retry after `Retry-After`.
    AdmissionBusy,
    /// The caller holds as many active leases as their policy allows. Final
    /// until one of them is released; no `Retry-After`.
    QuotaExhausted,
    /// The caller is creating leases faster than the per-principal admission
    /// budget allows. Retry after `Retry-After`.
    RateLimited,
    /// The API replica is at its concurrent-request ceiling. Retry after
    /// `Retry-After`.
    ServerBusy,
    /// Another active lease of this caller already holds the alias.
    AliasTaken,
    /// The idempotency key was already used for a different request.
    IdempotencyConflict,
    /// The request body is malformed or out of range.
    InvalidRequest,

    // --- Lease lifecycle ---------------------------------------------------
    /// No lease with this id or alias is visible to the caller. Identical for
    /// "absent" and "someone else's", on purpose.
    NotFound,
    /// The lease is not in a phase that allows the operation yet.
    NotReady,
    /// The lease has expired.
    Expired,
    /// Release was refused because verified teardown remains quarantined.
    TeardownQuarantined,
    /// The lease has used every extension its policy allows.
    ExtensionBudgetExhausted,
    /// The extension would move expiry past the policy's `max_ttl` ceiling.
    MaxTtlCeiling,
    /// The extension would move expiry past `now + maxIdle` on a Sandbox pool
    /// that sets `maxIdle`.
    MaxIdleCeiling,
    /// The stored expiry does not match what the lease's own timestamps
    /// derive.
    ExpiryDerivationMismatch,
    /// The lease changed between read and write. Retry against current state.
    ConflictRetryable,
    /// No policy resolves the lease's requester type any more, so the server
    /// cannot compute a ceiling and refuses rather than extend without one.
    PolicyUnresolvable,

    // --- Sandbox access ----------------------------------------------------
    TargetUnresolved,
    ProvenanceIncomplete,
    PoolUnresolvable,
    NotDeclared,
    PortNameCoversRange,
    AmbiguousAlias,
    BackendError,

    // --- Sandbox executions and streams ------------------------------------
    ExecutionLimitExhausted,
    RunnerUnreachable,
    RunnerUnreadable,
    RunnerForgotExecution,
    RunnerIdConflict,
    RunnerRejectedRequest,
    RunnerInternalError,
    RunnerMissing,
    ConcurrencyLimit,
    LeaseEnded,
    IrohTransport,
    DirectTransport,
}

impl ApiErrorReason {
    /// Every variant, for tests that pin the wire spelling.
    #[cfg(test)]
    pub(crate) const ALL: &'static [Self] = &[
        Self::PoolExhausted,
        Self::CapacityBlocked,
        Self::Degraded,
        Self::Warming,
        Self::WrongResourceKind,
        Self::AdmissionBusy,
        Self::QuotaExhausted,
        Self::RateLimited,
        Self::ServerBusy,
        Self::AliasTaken,
        Self::IdempotencyConflict,
        Self::InvalidRequest,
        Self::NotFound,
        Self::NotReady,
        Self::Expired,
        Self::TeardownQuarantined,
        Self::ExtensionBudgetExhausted,
        Self::MaxTtlCeiling,
        Self::MaxIdleCeiling,
        Self::ExpiryDerivationMismatch,
        Self::ConflictRetryable,
        Self::PolicyUnresolvable,
        Self::TargetUnresolved,
        Self::ProvenanceIncomplete,
        Self::PoolUnresolvable,
        Self::NotDeclared,
        Self::PortNameCoversRange,
        Self::AmbiguousAlias,
        Self::BackendError,
        Self::ExecutionLimitExhausted,
        Self::RunnerUnreachable,
        Self::RunnerUnreadable,
        Self::RunnerForgotExecution,
        Self::RunnerIdConflict,
        Self::RunnerRejectedRequest,
        Self::RunnerInternalError,
        Self::RunnerMissing,
        Self::ConcurrencyLimit,
        Self::LeaseEnded,
        Self::IrohTransport,
        Self::DirectTransport,
    ];

    /// The wire spelling, for audit logs and metric labels that record the
    /// same code the caller receives.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::PoolExhausted => "pool_exhausted",
            Self::CapacityBlocked => "capacity_blocked",
            Self::Degraded => "degraded",
            Self::Warming => "warming",
            Self::WrongResourceKind => "wrong_resource_kind",
            Self::AdmissionBusy => "admission_busy",
            Self::QuotaExhausted => "quota_exhausted",
            Self::RateLimited => "rate_limited",
            Self::ServerBusy => "server_busy",
            Self::AliasTaken => "alias_taken",
            Self::IdempotencyConflict => "idempotency_conflict",
            Self::InvalidRequest => "invalid_request",
            Self::NotFound => "not_found",
            Self::NotReady => "not_ready",
            Self::Expired => "expired",
            Self::TeardownQuarantined => "teardown_quarantined",
            Self::ExtensionBudgetExhausted => "extension_budget_exhausted",
            Self::MaxTtlCeiling => "max_ttl_ceiling",
            Self::MaxIdleCeiling => "max_idle_ceiling",
            Self::ExpiryDerivationMismatch => "expiry_derivation_mismatch",
            Self::ConflictRetryable => "conflict_retryable",
            Self::PolicyUnresolvable => "policy_unresolvable",
            Self::TargetUnresolved => "target_unresolved",
            Self::ProvenanceIncomplete => "provenance_incomplete",
            Self::PoolUnresolvable => "pool_unresolvable",
            Self::NotDeclared => "not_declared",
            Self::PortNameCoversRange => "port_name_covers_range",
            Self::AmbiguousAlias => "ambiguous_alias",
            Self::BackendError => "backend_error",
            Self::ExecutionLimitExhausted => "execution_limit_exhausted",
            Self::RunnerUnreachable => "runner_unreachable",
            Self::RunnerUnreadable => "runner_unreadable",
            Self::RunnerForgotExecution => "runner_forgot_execution",
            Self::RunnerIdConflict => "runner_id_conflict",
            Self::RunnerRejectedRequest => "runner_rejected_request",
            Self::RunnerInternalError => "runner_internal_error",
            Self::RunnerMissing => "runner_missing",
            Self::ConcurrencyLimit => "concurrency_limit",
            Self::LeaseEnded => "lease_ended",
            Self::IrohTransport => "iroh_transport",
            Self::DirectTransport => "direct_transport",
        }
    }
}

impl From<crate::metrics::LeaseUnsatisfiableReason> for ApiErrorReason {
    fn from(r: crate::metrics::LeaseUnsatisfiableReason) -> Self {
        use crate::metrics::LeaseUnsatisfiableReason as R;
        match r {
            R::PoolExhausted => Self::PoolExhausted,
            R::CapacityBlocked => Self::CapacityBlocked,
            R::Degraded => Self::Degraded,
            R::Warming => Self::Warming,
            // The pre-flight queues an Exhausted pool's leases rather than
            // refusing them, so this never reaches the wire. Mapped to the
            // nearest existing code to keep the vocabulary closed.
            R::AtCapacity => Self::CapacityBlocked,
        }
    }
}

/// Error body for every `/v1` lease and pool route.
///
/// `detail` is reserved for client-actionable text; infrastructure failures
/// never put raw backend errors in it. `reason` is omitted where no bounded
/// reason exists.
#[derive(Serialize, Default, Debug)]
pub(crate) struct ApiError {
    pub(crate) error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) reason: Option<ApiErrorReason>,
}

impl ApiError {
    pub(crate) fn new(error: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            ..Self::default()
        }
    }

    pub(crate) fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub(crate) fn reason(mut self, reason: ApiErrorReason) -> Self {
        self.reason = Some(reason);
        self
    }

    pub(crate) fn into_response_with(self, status: StatusCode) -> Response {
        (status, Json(self)).into_response()
    }
}

/// Seconds to advertise in `Retry-After`: rounded up and floored at one, so a
/// client never comes back before the refusal would lift.
pub(crate) fn retry_after_secs(wait: std::time::Duration) -> u64 {
    wait.as_secs_f64().ceil().max(1.0) as u64
}

/// Attach `Retry-After: seconds` to a response.
pub(crate) fn with_retry_after(mut response: Response, seconds: u64) -> Response {
    if let Ok(value) = HeaderValue::from_str(&seconds.to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

/// 429 `rate_limited` with `Retry-After`, for the per-principal admission
/// limiter on both lease kinds.
pub(crate) fn rate_limited(error: impl Into<String>, wait: std::time::Duration) -> Response {
    let seconds = retry_after_secs(wait);
    with_retry_after(
        ApiError::new(error)
            .detail(format!("Retry in {seconds}s"))
            .reason(ApiErrorReason::RateLimited)
            .into_response_with(StatusCode::TOO_MANY_REQUESTS),
        seconds,
    )
}

/// The one 404 every lease route answers with.
///
/// The body is identical whether the lease is absent or owned by someone
/// else, so it confirms nothing an empty 404 would not.
pub(crate) fn lease_not_found() -> Response {
    ApiError::new("Lease not found")
        .reason(ApiErrorReason::NotFound)
        .into_response_with(StatusCode::NOT_FOUND)
}

/// 404 for an execution id that does not exist under an otherwise visible
/// lease.
pub(crate) fn execution_not_found() -> Response {
    ApiError::new("Execution not found")
        .reason(ApiErrorReason::NotFound)
        .into_response_with(StatusCode::NOT_FOUND)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `as_str` feeds audit logs and metrics; the body carries the serde
    /// spelling. They must be the same string or an operator and a client
    /// would be looking at different codes for one refusal.
    #[test]
    fn as_str_matches_the_serialized_reason_for_every_variant() {
        for reason in ApiErrorReason::ALL {
            assert_eq!(
                serde_json::to_value(reason).unwrap(),
                serde_json::Value::String(reason.as_str().to_string()),
            );
        }
    }

    #[test]
    fn rate_limited_carries_reason_and_retry_after() {
        let response = rate_limited("slow down", std::time::Duration::from_millis(1500));
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()[header::RETRY_AFTER], "2");
    }

    #[test]
    fn empty_fields_are_omitted() {
        let body = serde_json::to_value(ApiError::new("x")).unwrap();
        assert_eq!(body, serde_json::json!({ "error": "x" }));
    }
}
