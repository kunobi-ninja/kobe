//! Admission accounts for Kubernetes' annotation limit before writing. History
//! reserves only half the object, leaving access and teardown usable at capacity.

use super::{
    AccessLedgerError, CLOSED, ENTRIES_ANNOTATION, EXECUTIONS_ANNOTATION, ExecutionCreationState,
    ExecutionEntry, STATE_ANNOTATION, annotation_path, encoding, lease_rv, lease_uid,
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
    entries: &BTreeMap<String, ExecutionEntry>,
) -> Result<bool, AccessLedgerError> {
    Ok(encoding::encode(entries)?.len() + future_growth(entries) <= HISTORY_BYTES)
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

pub(super) fn check_execution_patch(
    gate: &Lease,
    next: &str,
    entries: &BTreeMap<String, ExecutionEntry>,
) -> Result<(), AccessLedgerError> {
    check_size(
        gate,
        &[(EXECUTIONS_ANNOTATION, next)],
        future_growth(entries),
    )
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
    use crate::sandbox_access_ledger::encoding::tests::history;

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
        assert!(history_fits(&history(10)).unwrap());
        assert!(!history_fits(&history(2000)).unwrap());
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
    fn a_full_legacy_history_compacts_in_the_access_cas_without_losing_rows() {
        let overhead = STATE_ANNOTATION.len()
            + "closed".len()
            + ENTRIES_ANNOTATION.len()
            + 2
            + EXECUTIONS_ANNOTATION.len();
        let mut entries = BTreeMap::new();
        for (name, entry) in history(1500) {
            entries.insert(name.clone(), entry);
            if serde_json::to_string(&entries).unwrap().len() + overhead > 262_144 - 256 {
                entries.remove(&name);
                break;
            }
        }
        let legacy = serde_json::to_string(&entries).unwrap();
        let original = object(BTreeMap::from([
            (STATE_ANNOTATION.into(), "open".into()),
            (ENTRIES_ANNOTATION.into(), "{}".into()),
            (EXECUTIONS_ANNOTATION.into(), legacy.clone()),
        ]));
        let operations = BTreeMap::from([("new-operation".to_string(), "identity".repeat(256))]);
        assert!(
            legacy.len() + serde_json::to_string(&operations).unwrap().len() + overhead > 262_144
        );
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
