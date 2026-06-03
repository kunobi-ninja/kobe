//! Shared lease selection.
//!
//! A requester can hold multiple concurrent leases, so every lease-scoped
//! command (`release`, `extend`, ...) needs to answer the same question:
//! *which* lease did the user mean? This module centralizes that resolution
//! so the behavior is consistent and the picker UX is shared.

use anyhow::Result;

use super::OutputFormat;
use super::config::ResolvedConfig;
use super::leases::{
    LeaseSummary, fetch_leases_path, lease_cluster_label, lease_phase_label, lease_when_label,
};
use super::picker::{PickerItem, run_picker};

/// What to do when no target is given, more than one active lease matches,
/// and the interactive picker cannot run (i.e. `--output json`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum OnAmbiguous {
    /// Pick the first active lease. Preserves the legacy `release` behavior.
    FirstActive,
    /// Refuse and list the candidate ids. Safe default for mutating commands
    /// like `extend`, where silently acting on an arbitrary lease is wrong.
    Reject,
}

/// A lease is selectable while it still refers to a live (or pending) cluster.
fn is_active(lease: &LeaseSummary) -> bool {
    !lease.phase.eq_ignore_ascii_case("released")
        && !lease.phase.eq_ignore_ascii_case("expired")
        && !lease.phase.eq_ignore_ascii_case("recycling")
}

/// Outcome of the pure selection step. Either we resolved a single lease id,
/// or the choice is ambiguous and the caller must run the interactive picker
/// over the candidates.
#[derive(Debug)]
enum Selection {
    Resolved(String),
    NeedsPicker(Vec<LeaseSummary>),
}

/// Pure selection over a pre-fetched, pre-filtered (active-only) lease set.
///
/// Kept free of I/O so the precedence rules are unit-testable; the interactive
/// picker case is deferred to the caller via [`Selection::NeedsPicker`].
fn select(
    active: Vec<LeaseSummary>,
    target: Option<&str>,
    output: OutputFormat,
    on_ambiguous: OnAmbiguous,
) -> Result<Selection> {
    if let Some(target) = target {
        if let Some(lease) = active.iter().find(|lease| lease.id == target) {
            return Ok(Selection::Resolved(lease.id.clone()));
        }
        let by_pool: Vec<&LeaseSummary> = active
            .iter()
            .filter(|lease| lease.profile == target)
            .collect();
        return match by_pool.as_slice() {
            [only] => Ok(Selection::Resolved(only.id.clone())),
            [] => anyhow::bail!("No active lease matching '{target}' (by id or pool)"),
            many => anyhow::bail!(
                "'{target}' matches {} active leases by pool: {}. Specify a lease id.",
                many.len(),
                join_ids(many.iter().copied()),
            ),
        };
    }

    match active.as_slice() {
        [] => anyhow::bail!("No active leases found"),
        [only] => Ok(Selection::Resolved(only.id.clone())),
        many => {
            if output == OutputFormat::Json {
                return match on_ambiguous {
                    OnAmbiguous::FirstActive => Ok(Selection::Resolved(many[0].id.clone())),
                    OnAmbiguous::Reject => anyhow::bail!(
                        "Multiple active leases ({}); specify a lease id or pool: {}",
                        many.len(),
                        join_ids(many.iter()),
                    ),
                };
            }
            Ok(Selection::NeedsPicker(active))
        }
    }
}

/// Resolve a user-supplied selector to a concrete lease id.
///
/// Precedence:
/// - `target` is an exact lease id of an active lease -> that lease
/// - `target` matches exactly one active lease by pool/profile -> that lease
/// - `target` is `None` and there is exactly one active lease -> that lease
/// - `target` is `None` and there are several -> interactive picker (text),
///   or the [`OnAmbiguous`] policy (json)
pub(crate) async fn resolve_lease_id(
    config: &ResolvedConfig,
    target: Option<&str>,
    output: OutputFormat,
    on_ambiguous: OnAmbiguous,
) -> Result<String> {
    let active: Vec<LeaseSummary> = fetch_leases_path(config, "/v1/leases")
        .await?
        .into_iter()
        .filter(is_active)
        .collect();

    match select(active, target, output, on_ambiguous)? {
        Selection::Resolved(id) => Ok(id),
        Selection::NeedsPicker(candidates) => {
            let items: Vec<PickerItem> = candidates
                .iter()
                .map(|lease| PickerItem {
                    primary: format!(
                        "{}  {}  {}",
                        lease.id,
                        lease.profile,
                        lease_when_label(lease)
                    ),
                    secondary: format!(
                        "phase: {}   cluster: {}",
                        lease_phase_label(lease),
                        lease_cluster_label(lease)
                    ),
                })
                .collect();
            let selected = run_picker(
                "Select a lease",
                "↑/↓ to move · Enter to select · q to cancel",
                &items,
            )?;
            Ok(candidates[selected].id.clone())
        }
    }
}

fn join_ids<'a, I>(leases: I) -> String
where
    I: IntoIterator<Item = &'a LeaseSummary>,
{
    leases
        .into_iter()
        .map(|lease| lease.id.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lease(id: &str, profile: &str, phase: &str) -> LeaseSummary {
        LeaseSummary {
            id: id.to_string(),
            phase: phase.to_string(),
            profile: profile.to_string(),
            cluster_name: None,
            expires_at: None,
            queue_position: 0,
            requester: None,
            kubeconfig_path: None,
        }
    }

    fn resolved(sel: Selection) -> String {
        match sel {
            Selection::Resolved(id) => id,
            Selection::NeedsPicker(_) => panic!("expected a resolved selection, got picker"),
        }
    }

    #[test]
    fn explicit_id_wins() {
        let active = vec![
            lease("lease-aaa", "p1", "Bound"),
            lease("lease-bbb", "p2", "Bound"),
        ];
        let sel = select(
            active,
            Some("lease-bbb"),
            OutputFormat::Text,
            OnAmbiguous::Reject,
        )
        .unwrap();
        assert_eq!(resolved(sel), "lease-bbb");
    }

    #[test]
    fn unique_pool_match_resolves() {
        let active = vec![
            lease("lease-aaa", "p1", "Bound"),
            lease("lease-bbb", "p2", "Bound"),
        ];
        let sel = select(active, Some("p2"), OutputFormat::Text, OnAmbiguous::Reject).unwrap();
        assert_eq!(resolved(sel), "lease-bbb");
    }

    #[test]
    fn ambiguous_pool_match_errors() {
        let active = vec![
            lease("lease-aaa", "p1", "Bound"),
            lease("lease-bbb", "p1", "Bound"),
        ];
        let err = select(active, Some("p1"), OutputFormat::Text, OnAmbiguous::Reject).unwrap_err();
        assert!(err.to_string().contains("matches 2 active leases"));
    }

    #[test]
    fn unknown_target_errors() {
        let active = vec![lease("lease-aaa", "p1", "Bound")];
        let err = select(
            active,
            Some("nope"),
            OutputFormat::Text,
            OnAmbiguous::Reject,
        )
        .unwrap_err();
        assert!(err.to_string().contains("No active lease matching"));
    }

    #[test]
    fn single_active_lease_used_implicitly() {
        let active = vec![lease("lease-aaa", "p1", "Bound")];
        let sel = select(active, None, OutputFormat::Json, OnAmbiguous::Reject).unwrap();
        assert_eq!(resolved(sel), "lease-aaa");
    }

    #[test]
    fn no_active_leases_errors() {
        let err = select(vec![], None, OutputFormat::Text, OnAmbiguous::Reject).unwrap_err();
        assert!(err.to_string().contains("No active leases found"));
    }

    #[test]
    fn json_reject_refuses_ambiguity() {
        let active = vec![
            lease("lease-aaa", "p1", "Bound"),
            lease("lease-bbb", "p2", "Bound"),
        ];
        let err = select(active, None, OutputFormat::Json, OnAmbiguous::Reject).unwrap_err();
        assert!(err.to_string().contains("Multiple active leases"));
    }

    #[test]
    fn json_first_active_keeps_release_behavior() {
        let active = vec![
            lease("lease-aaa", "p1", "Bound"),
            lease("lease-bbb", "p2", "Bound"),
        ];
        let sel = select(active, None, OutputFormat::Json, OnAmbiguous::FirstActive).unwrap();
        assert_eq!(resolved(sel), "lease-aaa");
    }

    #[test]
    fn multiple_active_text_defers_to_picker() {
        let active = vec![
            lease("lease-aaa", "p1", "Bound"),
            lease("lease-bbb", "p2", "Bound"),
        ];
        let sel = select(active, None, OutputFormat::Text, OnAmbiguous::Reject).unwrap();
        assert!(matches!(sel, Selection::NeedsPicker(c) if c.len() == 2));
    }
}
