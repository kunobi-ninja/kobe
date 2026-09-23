#![forbid(unsafe_code)]

/// Lifecycle phases relevant to recovery of an exact lease-to-instance
/// binding. The operator maps its wire-level CRD enum into this closed set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstancePhase {
    Creating,
    Ready,
    Leased,
    Recycling,
    Unhealthy,
    Failed,
    Quarantined,
}

/// What the current object says about the binding the reconcile originally
/// observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingState {
    Expected,
    Absent,
    Foreign,
}

/// Recovery intent selected from an authoritative lease observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryTransition {
    RecycleTerminalLease,
    ReleaseOrphan,
}

/// Decision for the next fenced write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryDecision {
    Apply,
    AlreadyApplied,
    Superseded,
}

/// Lease phases relevant to publishing an exact reciprocal reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeasePhase {
    Pending,
    Bound,
    Released,
    Expired,
    Recycling,
    Quarantined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalizationDecision {
    PublishBound,
    AlreadyBound,
    Superseded,
}

/// Cross-object state machine for the crash-safe `Pending -> Bound` commit.
/// Access is published only when both objects still carry the exact intent.
pub fn exact_binding_finalization(
    lease_phase: LeasePhase,
    lease_binding: BindingState,
    instance_phase: InstancePhase,
    instance_binding: BindingState,
) -> FinalizationDecision {
    match (lease_phase, lease_binding, instance_phase, instance_binding) {
        (
            LeasePhase::Pending,
            BindingState::Expected,
            InstancePhase::Leased,
            BindingState::Expected,
        ) => FinalizationDecision::PublishBound,
        (
            LeasePhase::Bound,
            BindingState::Expected,
            InstancePhase::Leased,
            BindingState::Expected,
        ) => FinalizationDecision::AlreadyBound,
        _ => FinalizationDecision::Superseded,
    }
}

/// Pure state machine for exact-binding recovery.
///
/// Only a `Leased` instance carrying the expected reciprocal binding may enter
/// a recovery transition. A retry may observe its own completed write. Every
/// foreign binding and every teardown phase is fail-closed.
pub fn exact_binding_recovery(
    phase: InstancePhase,
    binding: BindingState,
    lease_ref_absent: bool,
    transition: RecoveryTransition,
) -> RecoveryDecision {
    match (transition, phase, binding, lease_ref_absent) {
        (
            RecoveryTransition::RecycleTerminalLease,
            InstancePhase::Leased,
            BindingState::Expected,
            _,
        )
        | (RecoveryTransition::ReleaseOrphan, InstancePhase::Leased, BindingState::Expected, _) => {
            RecoveryDecision::Apply
        }
        (
            RecoveryTransition::RecycleTerminalLease,
            InstancePhase::Recycling,
            BindingState::Expected,
            _,
        )
        | (RecoveryTransition::ReleaseOrphan, InstancePhase::Ready, BindingState::Absent, true) => {
            RecoveryDecision::AlreadyApplied
        }
        _ => RecoveryDecision::Superseded,
    }
}

/// What a producer lease's teardown receipt says when a consumer reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptState {
    /// No receipt has been written yet.
    Absent,
    /// A receipt exists and no consumer has acknowledged it.
    Live,
    /// A consumer acknowledged it; the producer may now be deleted.
    Consumed,
}

/// What a consumer concludes from a producer lease it is reading a receipt off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildReceiptVerdict {
    /// The receipt is valid evidence; release the child's capacity.
    Accept,
    /// Not decidable yet. Read again rather than concluding anything.
    NotYet,
    /// This producer can never yield valid evidence for this consumer.
    Reject,
}

/// Whether a producer lease can actually be observed in this combination.
///
/// This is the half that the phase-only model could not express, and the half
/// the bug lives in. Two controllers write a producer lease on independent
/// timers: the instance controller writes `teardownReceipt` after it verifies
/// the instance is gone, touching no phase, and the lease controller moves the
/// phase to `Recycling` on its own later reconcile. So a live receipt is
/// observable while the phase is still the terminal one it was written under.
pub fn producer_state_is_reachable(phase: LeasePhase, receipt: ReceiptState) -> bool {
    match (phase, receipt) {
        // No teardown has begun, so nothing has written evidence.
        (LeasePhase::Pending | LeasePhase::Bound, ReceiptState::Absent) => true,
        (LeasePhase::Pending | LeasePhase::Bound, _) => false,

        // Terminal, and where verification runs. `Absent` is before the
        // instance controller wrote the receipt; `Live` is after it did and
        // before the lease controller moved the phase. `Consumed` is not
        // reachable here: acknowledgement happens under `Recycling`.
        (LeasePhase::Released | LeasePhase::Expired, ReceiptState::Absent) => true,
        (LeasePhase::Released | LeasePhase::Expired, ReceiptState::Live) => true,
        (LeasePhase::Released | LeasePhase::Expired, ReceiptState::Consumed) => false,

        // The producer holds here until its receipt is acknowledged.
        (LeasePhase::Recycling, ReceiptState::Absent) => false,
        (LeasePhase::Recycling, _) => true,

        // Teardown could not be proven. Evidence may be missing or present
        // and unusable, but nothing acknowledged it.
        (LeasePhase::Quarantined, ReceiptState::Consumed) => false,
        (LeasePhase::Quarantined, _) => true,
    }
}

/// What a consumer concludes from a producer's phase and receipt.
///
/// The phase is a coarse guard; the receipt's own contents (attempt id,
/// creation manifest, instance UID) are what actually prove teardown.
/// Three outcomes rather than two, and that is the whole fix. A producer
/// holding live evidence that simply has not been swept into `Recycling` yet
/// is not the same as one that can never yield valid evidence, and collapsing
/// both onto `Reject` is what turns a timing window into a quarantine.
pub fn child_receipt_acceptance(phase: LeasePhase, receipt: ReceiptState) -> ChildReceiptVerdict {
    match (phase, receipt) {
        // No evidence is never evidence.
        (_, ReceiptState::Absent) => ChildReceiptVerdict::Reject,

        // The one state acceptance happens in. Widening this to the terminal
        // phases below would mean honouring evidence before the producer's own
        // state machine finished with it — and would keep honouring it if the
        // producer got stuck and never swept.
        (LeasePhase::Recycling, _) => ChildReceiptVerdict::Accept,

        // Written, not yet swept. The producer is mid-handoff between two
        // controllers, so nothing is decidable; read again.
        (LeasePhase::Released | LeasePhase::Expired, ReceiptState::Live) => {
            ChildReceiptVerdict::NotYet
        }

        // Teardown could not be proven for this capacity. A receipt here is
        // evidence that was already judged insufficient, so this rejection is
        // the one that must stay permanent.
        (LeasePhase::Quarantined, _) => ChildReceiptVerdict::Reject,

        _ => ChildReceiptVerdict::Reject,
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    fn arbitrary_phase(selector: u8) -> InstancePhase {
        match selector % 7 {
            0 => InstancePhase::Creating,
            1 => InstancePhase::Ready,
            2 => InstancePhase::Leased,
            3 => InstancePhase::Recycling,
            4 => InstancePhase::Unhealthy,
            5 => InstancePhase::Failed,
            _ => InstancePhase::Quarantined,
        }
    }

    fn arbitrary_binding(selector: u8) -> BindingState {
        match selector % 3 {
            0 => BindingState::Expected,
            1 => BindingState::Absent,
            _ => BindingState::Foreign,
        }
    }

    fn arbitrary_lease_phase(selector: u8) -> LeasePhase {
        match selector % 6 {
            0 => LeasePhase::Pending,
            1 => LeasePhase::Bound,
            2 => LeasePhase::Released,
            3 => LeasePhase::Expired,
            4 => LeasePhase::Recycling,
            _ => LeasePhase::Quarantined,
        }
    }

    #[kani::proof]
    fn recovery_apply_requires_the_exact_leased_subject() {
        let phase = arbitrary_phase(kani::any());
        let binding = arbitrary_binding(kani::any());
        let transition = if kani::any() {
            RecoveryTransition::RecycleTerminalLease
        } else {
            RecoveryTransition::ReleaseOrphan
        };
        let decision = exact_binding_recovery(phase, binding, kani::any(), transition);

        if decision == RecoveryDecision::Apply {
            assert_eq!(phase, InstancePhase::Leased);
            assert_eq!(binding, BindingState::Expected);
        }
    }

    #[kani::proof]
    fn teardown_phases_are_never_reopened_by_recovery() {
        let phase = match kani::any::<u8>() % 4 {
            0 => InstancePhase::Recycling,
            1 => InstancePhase::Quarantined,
            2 => InstancePhase::Failed,
            _ => InstancePhase::Unhealthy,
        };
        let transition = if kani::any() {
            RecoveryTransition::RecycleTerminalLease
        } else {
            RecoveryTransition::ReleaseOrphan
        };
        let decision = exact_binding_recovery(
            phase,
            arbitrary_binding(kani::any()),
            kani::any(),
            transition,
        );

        assert_ne!(decision, RecoveryDecision::Apply);
    }

    #[kani::proof]
    fn bound_publication_requires_two_exact_reciprocal_sides() {
        let lease_phase = arbitrary_lease_phase(kani::any());
        let lease_binding = arbitrary_binding(kani::any());
        let instance_phase = arbitrary_phase(kani::any());
        let instance_binding = arbitrary_binding(kani::any());
        let decision = exact_binding_finalization(
            lease_phase,
            lease_binding,
            instance_phase,
            instance_binding,
        );

        if decision == FinalizationDecision::PublishBound {
            assert_eq!(lease_phase, LeasePhase::Pending);
            assert_eq!(lease_binding, BindingState::Expected);
            assert_eq!(instance_phase, InstancePhase::Leased);
            assert_eq!(instance_binding, BindingState::Expected);
        }
    }

    fn arbitrary_receipt(selector: u8) -> ReceiptState {
        match selector % 3 {
            0 => ReceiptState::Absent,
            1 => ReceiptState::Live,
            _ => ReceiptState::Consumed,
        }
    }

    /// The property #367 violates, and the one that says why widening
    /// acceptance is the wrong fix.
    ///
    /// `Reject` is permanent — it quarantines the consumer and withholds its
    /// capacity — so live evidence may only earn it from a producer that can
    /// never yield valid evidence. `Quarantined` is exactly that producer and
    /// must keep rejecting. Every other reachable live state is a producer
    /// mid-handoff, which is not a verdict.
    ///
    /// Enumerating this is what found the third state. Reading the code found
    /// `Released` and `Expired`; `Quarantined` + live is also reachable, and
    /// it is the one where the existing rejection was right all along.
    #[kani::proof]
    fn live_evidence_is_rejected_only_when_teardown_was_disproven() {
        let phase = arbitrary_lease_phase(kani::any());
        let receipt = arbitrary_receipt(kani::any());
        kani::assume(producer_state_is_reachable(phase, receipt));
        kani::assume(receipt == ReceiptState::Live);

        if child_receipt_acceptance(phase, receipt) == ChildReceiptVerdict::Reject {
            assert_eq!(phase, LeasePhase::Quarantined);
        }
    }

    /// Acceptance happens in exactly one phase.
    ///
    /// The alternative fix — letting `Released`/`Expired` accept too — would
    /// also close #367, and this is the property that rules it out: a producer
    /// whose lease controller is stuck and never sweeps would have its evidence
    /// honoured anyway, so acceptance would no longer mean the producer's own
    /// state machine agreed.
    #[kani::proof]
    fn acceptance_happens_only_under_recycling() {
        let phase = arbitrary_lease_phase(kani::any());
        let receipt = arbitrary_receipt(kani::any());
        kani::assume(producer_state_is_reachable(phase, receipt));

        if child_receipt_acceptance(phase, receipt) == ChildReceiptVerdict::Accept {
            assert_eq!(phase, LeasePhase::Recycling);
        }
    }

    /// The other half: nothing without evidence is ever accepted.
    #[kani::proof]
    fn acceptance_requires_a_receipt() {
        let phase = arbitrary_lease_phase(kani::any());
        let receipt = arbitrary_receipt(kani::any());
        kani::assume(producer_state_is_reachable(phase, receipt));

        if child_receipt_acceptance(phase, receipt) == ChildReceiptVerdict::Accept {
            assert_ne!(receipt, ReceiptState::Absent);
        }
    }

    #[kani::proof]
    fn terminal_leases_never_publish_bound() {
        let lease_phase = match kani::any::<u8>() % 4 {
            0 => LeasePhase::Released,
            1 => LeasePhase::Expired,
            2 => LeasePhase::Recycling,
            _ => LeasePhase::Quarantined,
        };
        let decision = exact_binding_finalization(
            lease_phase,
            arbitrary_binding(kani::any()),
            arbitrary_phase(kani::any()),
            arbitrary_binding(kani::any()),
        );
        assert_ne!(decision, FinalizationDecision::PublishBound);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_matrix_is_exhaustive_and_fail_closed() {
        let phases = [
            InstancePhase::Creating,
            InstancePhase::Ready,
            InstancePhase::Leased,
            InstancePhase::Recycling,
            InstancePhase::Unhealthy,
            InstancePhase::Failed,
            InstancePhase::Quarantined,
        ];
        let bindings = [
            BindingState::Expected,
            BindingState::Absent,
            BindingState::Foreign,
        ];
        let transitions = [
            RecoveryTransition::RecycleTerminalLease,
            RecoveryTransition::ReleaseOrphan,
        ];

        for phase in phases {
            for binding in bindings {
                for lease_ref_absent in [false, true] {
                    for transition in transitions {
                        let actual =
                            exact_binding_recovery(phase, binding, lease_ref_absent, transition);
                        let expected = match (transition, phase, binding, lease_ref_absent) {
                            (_, InstancePhase::Leased, BindingState::Expected, _) => {
                                RecoveryDecision::Apply
                            }
                            (
                                RecoveryTransition::RecycleTerminalLease,
                                InstancePhase::Recycling,
                                BindingState::Expected,
                                _,
                            )
                            | (
                                RecoveryTransition::ReleaseOrphan,
                                InstancePhase::Ready,
                                BindingState::Absent,
                                true,
                            ) => RecoveryDecision::AlreadyApplied,
                            _ => RecoveryDecision::Superseded,
                        };
                        assert_eq!(
                            actual, expected,
                            "phase={phase:?} binding={binding:?} lease_ref_absent={lease_ref_absent} transition={transition:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn finalization_matrix_is_exhaustive_and_fail_closed() {
        let lease_phases = [
            LeasePhase::Pending,
            LeasePhase::Bound,
            LeasePhase::Released,
            LeasePhase::Expired,
            LeasePhase::Recycling,
            LeasePhase::Quarantined,
        ];
        let instance_phases = [
            InstancePhase::Creating,
            InstancePhase::Ready,
            InstancePhase::Leased,
            InstancePhase::Recycling,
            InstancePhase::Unhealthy,
            InstancePhase::Failed,
            InstancePhase::Quarantined,
        ];
        let bindings = [
            BindingState::Expected,
            BindingState::Absent,
            BindingState::Foreign,
        ];

        for lease_phase in lease_phases {
            for lease_binding in bindings {
                for instance_phase in instance_phases {
                    for instance_binding in bindings {
                        let actual = exact_binding_finalization(
                            lease_phase,
                            lease_binding,
                            instance_phase,
                            instance_binding,
                        );
                        let expected =
                            match (lease_phase, lease_binding, instance_phase, instance_binding) {
                                (
                                    LeasePhase::Pending,
                                    BindingState::Expected,
                                    InstancePhase::Leased,
                                    BindingState::Expected,
                                ) => FinalizationDecision::PublishBound,
                                (
                                    LeasePhase::Bound,
                                    BindingState::Expected,
                                    InstancePhase::Leased,
                                    BindingState::Expected,
                                ) => FinalizationDecision::AlreadyBound,
                                _ => FinalizationDecision::Superseded,
                            };
                        assert_eq!(actual, expected);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod child_receipt_tests {
    use super::*;

    const PHASES: [LeasePhase; 6] = [
        LeasePhase::Pending,
        LeasePhase::Bound,
        LeasePhase::Released,
        LeasePhase::Expired,
        LeasePhase::Recycling,
        LeasePhase::Quarantined,
    ];
    const RECEIPTS: [ReceiptState; 3] = [
        ReceiptState::Absent,
        ReceiptState::Live,
        ReceiptState::Consumed,
    ];

    /// Which phases can be observed holding live evidence, and which of those
    /// the old two-outcome code rejected.
    ///
    /// Reading the code found `Released` and `Expired`. Enumerating the model
    /// found `Quarantined` too — and that is the one whose rejection was right
    /// all along, which is why the fix needed a third outcome rather than a
    /// wider acceptance.
    #[test]
    fn enumerating_live_evidence_finds_the_state_reading_the_code_missed() {
        let live: Vec<LeasePhase> = PHASES
            .into_iter()
            .filter(|phase| producer_state_is_reachable(*phase, ReceiptState::Live))
            .collect();
        assert_eq!(
            live,
            vec![
                LeasePhase::Released,
                LeasePhase::Expired,
                LeasePhase::Recycling,
                LeasePhase::Quarantined,
            ],
        );

        let not_accepted: Vec<LeasePhase> = live
            .into_iter()
            .filter(|phase| {
                child_receipt_acceptance(*phase, ReceiptState::Live) != ChildReceiptVerdict::Accept
            })
            .collect();
        assert_eq!(
            not_accepted,
            vec![
                LeasePhase::Released,
                LeasePhase::Expired,
                LeasePhase::Quarantined,
            ],
            "the three states the old code collapsed onto one permanent verdict",
        );
    }

    /// The handoff window answers "read again", never a verdict.
    #[test]
    fn the_handoff_window_is_not_a_verdict() {
        for phase in [LeasePhase::Released, LeasePhase::Expired] {
            assert_eq!(
                child_receipt_acceptance(phase, ReceiptState::Live),
                ChildReceiptVerdict::NotYet,
                "{phase:?} carries live evidence mid-handoff",
            );
        }
    }

    /// A producer whose teardown was disproven keeps rejecting, receipt or not.
    #[test]
    fn a_quarantined_producer_still_rejects() {
        for receipt in RECEIPTS {
            assert_eq!(
                child_receipt_acceptance(LeasePhase::Quarantined, receipt),
                ChildReceiptVerdict::Reject,
                "{receipt:?}",
            );
        }
    }

    /// Nothing unreachable is ever consulted, and every reachable state has a
    /// verdict. Guards the model against a combination nobody considered.
    #[test]
    fn every_reachable_state_has_a_verdict() {
        let mut reachable = 0;
        for phase in PHASES {
            for receipt in RECEIPTS {
                if producer_state_is_reachable(phase, receipt) {
                    reachable += 1;
                    let _ = child_receipt_acceptance(phase, receipt);
                }
            }
        }
        assert_eq!(reachable, 10, "reachable (phase, receipt) combinations");
    }
}
