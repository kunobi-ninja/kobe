//! Keep complete execution identities in a bounded annotation. Repeated target
//! and writer identities are interned; no history or process evidence is lost.

use super::{AccessLedgerError, ExecutionCreationState, ExecutionEntry, ServingReplica};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const PREFIX: &str = "compact-v1:";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompactExecutions {
    pods: Vec<String>,
    writers: Vec<ServingReplica>,
    entries: BTreeMap<String, PackedExecution>,
}

#[derive(Serialize, Deserialize)]
struct PackedExecution(
    String,
    usize,
    String,
    Option<String>,
    ExecutionCreationState,
    bool,
    Option<usize>,
);

pub(super) fn decode(encoded: &str) -> Result<BTreeMap<String, ExecutionEntry>, AccessLedgerError> {
    let Some(compact) = encoded.strip_prefix(PREFIX) else {
        return Ok(serde_json::from_str(encoded)?);
    };
    let compact: CompactExecutions = serde_json::from_str(compact)?;
    compact
        .entries
        .into_iter()
        .map(|(name, row)| {
            let PackedExecution(digest, pod, at, uid, state, active, writer) = row;
            let pod_uid = compact
                .pods
                .get(pod)
                .ok_or(AccessLedgerError::Invalid("execution target index"))?
                .clone();
            let writer = writer
                .map(|index| {
                    compact
                        .writers
                        .get(index)
                        .cloned()
                        .ok_or(AccessLedgerError::Invalid("execution writer index"))
                })
                .transpose()?;
            Ok((
                name,
                ExecutionEntry {
                    request_digest: digest,
                    pod_uid,
                    reserved_at: at,
                    execution_uid: uid,
                    creation_state: state,
                    active,
                    writer,
                },
            ))
        })
        .collect()
}

pub(super) fn encode(
    entries: &BTreeMap<String, ExecutionEntry>,
) -> Result<String, AccessLedgerError> {
    let plain = serde_json::to_string(entries)?;
    // Small ledgers retain the original wire format.
    if plain.len() <= 64 << 10 {
        return Ok(plain);
    }
    let mut pods = Vec::new();
    let mut writers = Vec::new();
    let mut packed = BTreeMap::new();
    for (name, entry) in entries {
        let pod = intern(&mut pods, &entry.pod_uid);
        let writer = entry
            .writer
            .as_ref()
            .map(|writer| intern(&mut writers, writer));
        packed.insert(
            name.clone(),
            PackedExecution(
                entry.request_digest.clone(),
                pod,
                entry.reserved_at.clone(),
                entry.execution_uid.clone(),
                entry.creation_state,
                entry.active,
                writer,
            ),
        );
    }
    let compact = format!(
        "{PREFIX}{}",
        serde_json::to_string(&CompactExecutions {
            pods,
            writers,
            entries: packed,
        })?
    );
    Ok(if compact.len() < plain.len() {
        compact
    } else {
        plain
    })
}

fn intern<T: Clone + PartialEq>(values: &mut Vec<T>, value: &T) -> usize {
    if let Some(index) = values.iter().position(|existing| existing == value) {
        index
    } else {
        values.push(value.clone());
        values.len() - 1
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    pub(in crate::sandbox_access_ledger) fn history(
        count: usize,
    ) -> BTreeMap<String, ExecutionEntry> {
        (0..count)
            .map(|index| {
                (
                    format!("sbxe-{index:032x}"),
                    ExecutionEntry {
                        request_digest: format!("{index:064x}"),
                        pod_uid: format!("sandbox-pod-{}", index % 2),
                        reserved_at: "2026-10-21T12:00:00.000000+00:00".into(),
                        execution_uid: (index % 3 != 0)
                            .then(|| format!("execution-uid-{index:032x}")),
                        creation_state: match index % 3 {
                            0 => ExecutionCreationState::Creating,
                            1 => ExecutionCreationState::Bound,
                            _ => ExecutionCreationState::Rejected,
                        },
                        active: index % 3 != 2,
                        writer: (index % 4 != 0).then(|| ServingReplica {
                            namespace: "kobe-system".into(),
                            pod_name: format!("kobe-operator-{}", index % 2),
                            pod_uid: format!("replica-pod-{}", index % 2),
                            boot_id: format!("replica-boot-{}", index % 2),
                        }),
                    },
                )
            })
            .collect()
    }

    #[test]
    fn compact_history_preserves_every_identity_and_transition() {
        let entries = history(1000);
        let legacy = serde_json::to_string(&entries).unwrap();
        assert!(legacy.len() > 262_144);
        let compact = encode(&entries).unwrap();
        assert!(compact.starts_with(PREFIX));
        assert!(compact.len() < legacy.len() * 3 / 4);
        assert_eq!(decode(&compact).unwrap(), entries);
        assert_eq!(decode(&legacy).unwrap(), entries);
        // Re-encoding does not reorder dictionary references or change bytes.
        assert_eq!(encode(&decode(&compact).unwrap()).unwrap(), compact);
    }

    #[test]
    fn small_and_legacy_histories_remain_readable() {
        let entries = history(2);
        assert_eq!(
            encode(&entries).unwrap(),
            serde_json::to_string(&entries).unwrap()
        );
        let legacy = r#"{"old":{"requestDigest":"digest","podUid":"pod","reservedAt":"then","active":true}}"#;
        let decoded = decode(legacy).unwrap();
        assert_eq!(
            decoded["old"].creation_state,
            ExecutionCreationState::Creating
        );
        assert_eq!(decoded["old"].execution_uid, None);
        assert_eq!(decoded["old"].writer, None);
        assert_eq!(decode(&encode(&decoded).unwrap()).unwrap(), decoded);
    }

    #[test]
    fn corrupt_dictionary_references_and_unknown_formats_are_refused() {
        let encoded = encode(&history(500)).unwrap();
        let original: serde_json::Value =
            serde_json::from_str(encoded.strip_prefix(PREFIX).unwrap()).unwrap();
        for field in [1, 6] {
            let mut corrupt = original.clone();
            let row = corrupt["entries"]
                .as_object_mut()
                .unwrap()
                .values_mut()
                .next()
                .unwrap();
            row[field] = serde_json::json!(9999);
            assert!(decode(&format!("{PREFIX}{corrupt}")).is_err());
        }
        for encoded in [
            "compact-v2:{}",
            "compact-v1:{}",
            "compact-v1:[]",
            "compact-v1:not-json",
        ] {
            assert!(decode(encoded).is_err());
        }
    }
}
