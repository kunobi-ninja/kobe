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
