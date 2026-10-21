//! Admission accounts for Kubernetes' annotation limit before writing. History
//! reserves only half the object, leaving access and teardown usable at capacity.

use super::{
    AccessLedgerError, CLOSED, ENTRIES_ANNOTATION, EXECUTIONS_ANNOTATION, ExecutionCreationState,
    ExecutionEntry, OPEN, STATE_ANNOTATION, annotation_path, encoding, lease_rv, lease_uid,
};
use k8s_openapi::api::coordination::v1::Lease;
use kube::ResourceExt;
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;

// Kubernetes ValidateAnnotationsSize sums UTF-8 key and value bytes, with a
// 256 KiB ceiling. Keep half available for access registrations and recovery.
const ANNOTATION_BYTES: usize = 256 << 10;
const HISTORY_BYTES: usize = 128 << 10;

fn future_growth(entries: &BTreeMap<String, ExecutionEntry>) -> usize {
    entries
        .values()
        .map(|entry| {
            // API-server UIDs are UUIDs. Reserve 128 bytes for the later UID
            // and one byte for true -> false without releasing active slots.
            usize::from(
                entry.execution_uid.is_none()
                    && entry.creation_state == ExecutionCreationState::Creating,
            ) * 128
                + usize::from(entry.active)
        })
        .sum()
}

pub(super) fn history_fits(
    gate: &Lease,
    entries: &BTreeMap<String, ExecutionEntry>,
) -> Result<bool, AccessLedgerError> {
    let encoded = encoding::encode(entries)?;
    let future = future_growth(entries);
    if encoded.len() + future > HISTORY_BYTES {
        return Ok(false);
    }
    match check_size(gate, &[(EXECUTIONS_ANNOTATION, &encoded)], future) {
        Ok(()) => Ok(true),
        Err(AccessLedgerError::Capacity) => Ok(false),
        Err(error) => Err(error),
    }
}

fn check_size(
    object: &Lease,
    replacements: &[(&str, &str)],
    future: usize,
) -> Result<(), AccessLedgerError> {
    let mut annotations = object.annotations().clone();
    for (key, value) in replacements {
        annotations.insert((*key).into(), (*value).into());
    }
    let closing = annotations
        .get(STATE_ANNOTATION)
        .map_or(0, |state| CLOSED.len().saturating_sub(state.len()));
    let used: usize = annotations
        .iter()
        .map(|(key, value)| key.len() + value.len())
        .sum();
    if used + future + closing > ANNOTATION_BYTES {
        return Err(AccessLedgerError::Capacity);
    }
    Ok(())
}

pub(super) fn check_execution_patch(gate: &Lease, next: &str) -> Result<(), AccessLedgerError> {
    // Existing reservations must be able to settle even when a legacy gate
    // predates the headroom rule. Only new admissions reserve future growth.
    // Teardown and binding still obey the API server's actual byte ceiling.
    check_size(gate, &[(EXECUTIONS_ANNOTATION, next)], 0)
}

/// Close and compact one exact gate atomically. Legacy history can already
/// fill the annotation limit, leaving no room for open -> closed's two bytes.
/// Closing must preserve existing reservations without requiring new headroom.
pub(super) fn close_patch(gate: &Lease) -> Result<Value, AccessLedgerError> {
    let mut patch = vec![
        json!({ "op": "test", "path": "/metadata/uid", "value": lease_uid(gate)? }),
        json!({ "op": "test", "path": "/metadata/resourceVersion", "value": lease_rv(gate)? }),
        json!({ "op": "test", "path": annotation_path(STATE_ANNOTATION), "value": OPEN }),
        json!({ "op": "replace", "path": annotation_path(STATE_ANNOTATION), "value": CLOSED }),
    ];
    let compact;
    let mut replacements = vec![(STATE_ANNOTATION, CLOSED)];
    if let Some(history) = gate.annotations().get(EXECUTIONS_ANNOTATION) {
        compact = encoding::encode(&encoding::decode(history)?)?;
        replacements.push((EXECUTIONS_ANNOTATION, compact.as_str()));
        if compact != *history {
            patch.push(json!({ "op": "test", "path": annotation_path(EXECUTIONS_ANNOTATION), "value": history }));
            patch.push(json!({ "op": "replace", "path": annotation_path(EXECUTIONS_ANNOTATION), "value": compact }));
        }
    }
    check_size(gate, &replacements, 0)?;
    Ok(Value::Array(patch))
}

/// Compact a legacy gate in the same UID/resourceVersion CAS that admits an
/// access operation. A full legacy history can therefore recover on its first
/// access after upgrading, retaining every execution and writer identity.
pub(super) fn access_patch<T: Serialize>(
    object: &Lease,
    previous: &str,
    entries: &BTreeMap<String, T>,
) -> Result<Value, AccessLedgerError> {
    let next = serde_json::to_string(entries)?;
    let mut patch = vec![
        json!({ "op": "test", "path": "/metadata/uid", "value": lease_uid(object)? }),
        json!({ "op": "test", "path": "/metadata/resourceVersion", "value": lease_rv(object)? }),
        json!({ "op": "test", "path": annotation_path(ENTRIES_ANNOTATION), "value": previous }),
    ];
    let compact;
    let mut replacements = vec![(ENTRIES_ANNOTATION, next.as_str())];
    let mut future = 0;
    if let Some(history) = object.annotations().get(EXECUTIONS_ANNOTATION) {
        let executions = encoding::decode(history)?;
        compact = encoding::encode(&executions)?;
        future = future_growth(&executions);
        replacements.push((EXECUTIONS_ANNOTATION, compact.as_str()));
        if compact != *history {
            patch.push(json!({ "op": "test", "path": annotation_path(EXECUTIONS_ANNOTATION), "value": history }));
            patch.push(json!({ "op": "replace", "path": annotation_path(EXECUTIONS_ANNOTATION), "value": compact }));
        }
    }
    check_size(object, &replacements, future)?;
    patch.push(
        json!({ "op": "replace", "path": annotation_path(ENTRIES_ANNOTATION), "value": next }),
    );
    Ok(Value::Array(patch))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox_access_ledger::encoding::tests::{full_legacy_history, history};

    fn object(annotations: BTreeMap<String, String>) -> Lease {
        serde_json::from_value(json!({
            "apiVersion":"coordination.k8s.io/v1", "kind":"Lease",
            "metadata":{"name":"gate","uid":"uid","resourceVersion":"7","annotations":annotations},
            "spec":{}
        }))
        .unwrap()
    }

    #[test]
    fn annotation_budget_counts_utf8_keys_values_and_closing_growth() {
        let mut object = object(BTreeMap::from([
            (STATE_ANNOTATION.into(), "open".into()),
            ("payload".into(), String::new()),
        ]));
        let overhead = STATE_ANNOTATION.len() + "closed".len() + "payload".len();
        object
            .metadata
            .annotations
            .as_mut()
            .unwrap()
            .insert("payload".into(), "x".repeat(262_144 - overhead));
        assert!(check_size(&object, &[], 0).is_ok());
        assert!(matches!(
            check_size(&object, &[], 1),
            Err(AccessLedgerError::Capacity)
        ));
        object
            .metadata
            .annotations
            .as_mut()
            .unwrap()
            .get_mut("payload")
            .unwrap()
            .push('é');
        assert!(matches!(
            check_size(&object, &[], 0),
            Err(AccessLedgerError::Capacity)
        ));
        // Replacement counts the new value instead of both old and new.
        assert!(check_size(&object, &[("payload", "short")], 0).is_ok());
    }

    #[test]
    fn new_execution_history_stops_before_access_capacity_is_consumed() {
        let gate = object(BTreeMap::new());
        assert!(history_fits(&gate, &history(10)).unwrap());
        assert!(!history_fits(&gate, &history(2000)).unwrap());
        let mut creating = history(1);
        let before = future_growth(&creating);
        let entry = creating.values_mut().next().unwrap();
        entry.execution_uid = Some(uuid::Uuid::new_v4().to_string());
        entry.creation_state = ExecutionCreationState::Bound;
        assert_eq!(before - future_growth(&creating), 128);
        assert_eq!(future_growth(&creating), 1);
        creating.values_mut().next().unwrap().active = false;
        assert_eq!(future_growth(&creating), 0);
    }

    #[test]
    fn existing_legacy_reservations_can_bind_without_new_admission_headroom() {
        let mut entries = history(500);
        for entry in entries.values_mut() {
            entry.execution_uid = None;
            entry.creation_state = ExecutionCreationState::Creating;
            entry.active = true;
            entry.writer = None;
        }
        let legacy = serde_json::to_string(&entries).unwrap();
        let mut gate = object(BTreeMap::from([
            (STATE_ANNOTATION.into(), "open".into()),
            (EXECUTIONS_ANNOTATION.into(), legacy),
            ("padding".into(), String::new()),
        ]));
        let used: usize = gate
            .annotations()
            .iter()
            .map(|(k, v)| k.len() + v.len())
            .sum();
        gate.metadata
            .annotations
            .as_mut()
            .unwrap()
            .insert("padding".into(), "x".repeat(262_144 - used - 2));
        check_size(&gate, &[], 0).unwrap();
        let compact = encoding::encode(&entries).unwrap();
        assert!(matches!(
            check_size(
                &gate,
                &[(EXECUTIONS_ANNOTATION, &compact)],
                future_growth(&entries)
            ),
            Err(AccessLedgerError::Capacity)
        ));
        assert!(!history_fits(&gate, &entries).unwrap());
        let entry = entries.values_mut().next().unwrap();
        entry.execution_uid = Some("8f1d9a91-a725-4f34-90a0-612023f6f806".into());
        entry.creation_state = ExecutionCreationState::Bound;
        let bound = encoding::encode(&entries).unwrap();
        check_execution_patch(&gate, &bound).unwrap();
        assert_eq!(encoding::decode(&bound).unwrap(), entries);
        entries.values_mut().next().unwrap().active = false;
        check_execution_patch(&gate, &encoding::encode(&entries).unwrap()).unwrap();
    }

    #[test]
    fn access_annotations_also_limit_new_execution_admission() {
        let entries = history(10);
        let encoded = encoding::encode(&entries).unwrap();
        let mut gate = object(BTreeMap::from([
            (STATE_ANNOTATION.into(), "open".into()),
            (EXECUTIONS_ANNOTATION.into(), encoded),
            (ENTRIES_ANNOTATION.into(), String::new()),
        ]));
        assert!(history_fits(&gate, &entries).unwrap());
        let used: usize = gate
            .annotations()
            .iter()
            .map(|(k, v)| k.len() + v.len())
            .sum();
        // Valid JSON whitespace consumes the remaining annotation space.
        gate.metadata.annotations.as_mut().unwrap().insert(
            ENTRIES_ANNOTATION.into(),
            format!("{{}}{}", " ".repeat(262_144 - used - 4)),
        );
        check_size(&gate, &[], 0).unwrap();
        assert!(!history_fits(&gate, &entries).unwrap());
    }

    #[test]
    fn a_physically_full_legacy_gate_can_close_without_prior_access() {
        let (entries, mut legacy) = full_legacy_history();
        let overhead = STATE_ANNOTATION.len()
            + OPEN.len()
            + ENTRIES_ANNOTATION.len()
            + 2
            + EXECUTIONS_ANNOTATION.len();
        legacy.extend(std::iter::repeat_n(' ', 262_144 - overhead - legacy.len()));
        let gate = object(BTreeMap::from([
            (STATE_ANNOTATION.into(), OPEN.into()),
            (ENTRIES_ANNOTATION.into(), "{}".into()),
            (EXECUTIONS_ANNOTATION.into(), legacy),
        ]));
        assert_eq!(
            gate.annotations()
                .iter()
                .map(|(k, v)| k.len() + v.len())
                .sum::<usize>(),
            262_144
        );
        assert!(matches!(
            check_size(&gate, &[(STATE_ANNOTATION, CLOSED)], 0),
            Err(AccessLedgerError::Capacity)
        ));
        let patch: json_patch::Patch = serde_json::from_value(close_patch(&gate).unwrap()).unwrap();
        let mut updated = serde_json::to_value(&gate).unwrap();
        json_patch::patch(&mut updated, &patch).unwrap();
        let updated: Lease = serde_json::from_value(updated).unwrap();
        assert_eq!(updated.annotations()[STATE_ANNOTATION], CLOSED);
        assert_eq!(
            encoding::decode(&updated.annotations()[EXECUTIONS_ANNOTATION]).unwrap(),
            entries
        );
        check_size(&updated, &[], 0).unwrap();
        let mut raced = serde_json::to_value(&gate).unwrap();
        raced["metadata"]["annotations"][EXECUTIONS_ANNOTATION] = json!("{}");
        assert!(json_patch::patch(&mut raced, &patch).is_err());
    }

    #[test]
    fn a_full_legacy_history_compacts_in_the_access_cas_without_losing_rows() {
        let (entries, legacy) = full_legacy_history();
        let original = object(BTreeMap::from([
            (STATE_ANNOTATION.into(), "open".into()),
            (ENTRIES_ANNOTATION.into(), "{}".into()),
            (EXECUTIONS_ANNOTATION.into(), legacy.clone()),
        ]));
        let operations = BTreeMap::from([("new-operation".to_string(), "identity".repeat(256))]);
        assert!(legacy.len() + serde_json::to_string(&operations).unwrap().len() > 262_144);
        let patch = access_patch(&original, "{}", &operations).unwrap();
        assert_eq!(
            patch[0],
            json!({"op":"test","path":"/metadata/uid","value":"uid"})
        );
        assert_eq!(
            patch[1],
            json!({"op":"test","path":"/metadata/resourceVersion","value":"7"})
        );
        let mut updated = serde_json::to_value(&original).unwrap();
        let typed: json_patch::Patch = serde_json::from_value(patch.clone()).unwrap();
        json_patch::patch(&mut updated, &typed).unwrap();
        let updated: Lease = serde_json::from_value(updated).unwrap();
        assert_eq!(
            encoding::decode(&updated.annotations()[EXECUTIONS_ANNOTATION]).unwrap(),
            entries
        );
        assert_eq!(
            updated.annotations()[ENTRIES_ANNOTATION],
            serde_json::to_string(&operations).unwrap()
        );
        check_size(&updated, &[], future_growth(&entries)).unwrap();
        // A racing writer changes history: the old CAS cannot compact over it.
        let mut raced = serde_json::to_value(&original).unwrap();
        raced["metadata"]["annotations"][EXECUTIONS_ANNOTATION] = json!("{}");
        assert!(json_patch::patch(&mut raced, &typed).is_err());
    }
}
