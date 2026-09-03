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
    LeaseSummary, fetch_all_leases, lease_cluster_label, lease_phase_label, lease_when_label,
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
        // #107 P2: an alias names exactly one active lease (server-enforced),
        // so it resolves directly — `kobe extend pr-106 30m`.
        if let Some(lease) = active
            .iter()
            .find(|lease| lease.alias.as_deref() == Some(target))
        {
            return Ok(Selection::Resolved(lease.id.clone()));
        }
        let by_pool: Vec<&LeaseSummary> = active
            .iter()
            .filter(|lease| lease.profile == target)
            .collect();
        return match by_pool.as_slice() {
            [only] => Ok(Selection::Resolved(only.id.clone())),
            [] => anyhow::bail!("No active lease matching '{target}' (by id, alias, or pool)"),
            many => anyhow::bail!(
                "'{target}' matches {} active leases by pool: {}. Specify a lease id or alias.",
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

/// Render lease candidates for the interactive picker.
///
/// Shared so every picker describes a lease the same way: whichever command
/// opened it, the caller is choosing between the same rows.
fn picker_items(candidates: &[LeaseSummary]) -> Vec<PickerItem> {
    candidates
        .iter()
        .map(|lease| PickerItem {
            primary: format!(
                "{}  {}  {}",
                lease.id,
                lease.profile,
                lease_when_label(lease)
            ),
            secondary: format!(
                "kind: {}   phase: {}   resource: {}",
                lease.resource_kind,
                lease_phase_label(lease),
                lease_cluster_label(lease)
            ),
        })
        .collect()
}

/// Active leases that advertise `capability`.
///
/// Both halves matter. A released lease is gone, and a lease that never
/// advertised the verb cannot serve it: cluster leases carry `kubeconfig`, not
/// `attach`, so offering one in an attach picker would be offering a choice
/// that can only fail.
fn serving(leases: Vec<LeaseSummary>, capability: &str) -> Vec<LeaseSummary> {
    leases
        .into_iter()
        .filter(is_active)
        .filter(|lease| {
            lease
                .capabilities
                .iter()
                .any(|advertised| advertised == capability)
        })
        .collect()
}

/// Resolve a lease that advertises `capability`, with no target given.
///
/// `kobe attach` with no argument is the case where the caller knows they want
/// a session but not which lease. Only leases that actually serve the verb are
/// offered: a cluster lease never advertises `attach`, and listing one would
/// be offering a choice that can only fail.
pub(crate) async fn resolve_lease_for_capability(
    config: &ResolvedConfig,
    capability: &str,
    output: OutputFormat,
) -> Result<String> {
    let capable = serving(fetch_all_leases(config).await?, capability);

    if capable.is_empty() {
        anyhow::bail!(
            "No active lease supports `{capability}`. `kobe status` lists what you hold."
        );
    }

    match select(capable, None, output, OnAmbiguous::Reject)? {
        Selection::Resolved(id) => Ok(id),
        Selection::NeedsPicker(candidates) => {
            let items = picker_items(&candidates);
            let selected = run_picker(
                &format!("Select a lease to {capability}"),
                "↑/↓ to move · Enter to select · q to cancel",
                &items,
            )?;
            Ok(candidates[selected].id.clone())
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
    let active: Vec<LeaseSummary> = fetch_all_leases(config)
        .await?
        .into_iter()
        .filter(is_active)
        .collect();

    match select(active, target, output, on_ambiguous)? {
        Selection::Resolved(id) => Ok(id),
        Selection::NeedsPicker(candidates) => {
            let items = picker_items(&candidates);
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
            resource_kind: "Cluster".to_string(),
            capabilities: vec!["kubeconfig".to_string()],
            profile: profile.to_string(),
            cluster_name: None,
            expires_at: None,
            queue_position: 0,
            requester: None,
            kubeconfig_path: None,
            alias: None,
            metadata: None,
        }
    }

    /// An attach picker must only offer leases that can actually attach.
    ///
    /// Cluster leases advertise `kubeconfig` and never `attach`, so listing
    /// one would be offering a choice that fails after the user commits to
    /// it. Released leases are gone regardless of what they once advertised.
    #[test]
    fn only_active_leases_advertising_the_verb_are_offered() {
        let attachable = |id: &str, phase: &str| {
            let mut lease = lease(id, "agent-small", phase);
            lease.resource_kind = "Sandbox".to_string();
            lease.capabilities = vec!["lease".to_string(), "attach".to_string()];
            lease
        };

        let offered = serving(
            vec![
                attachable("sbx-ready", "Ready"),
                // Right verb, but the lease is over.
                attachable("sbx-released", "Released"),
                // Active, but a cluster lease cannot serve attach.
                lease("cluster-1", "e2e-k3s", "Bound"),
            ],
            "attach",
        );

        let ids: Vec<&str> = offered.iter().map(|lease| lease.id.as_str()).collect();
        assert_eq!(ids, vec!["sbx-ready"]);

        // A verb nothing advertises yields nothing rather than everything.
        assert!(serving(vec![attachable("sbx-ready", "Ready")], "port-forward").is_empty());
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
    fn alias_match_resolves() {
        // #107 P2: an alias selects its lease even though it's neither the id
        // nor the pool name — `kobe extend pr-106`.
        let mut tagged = lease("lease-aaa", "p1", "Bound");
        tagged.alias = Some("pr-106".to_string());
        let active = vec![tagged, lease("lease-bbb", "p2", "Bound")];
        let sel = select(
            active,
            Some("pr-106"),
            OutputFormat::Text,
            OnAmbiguous::Reject,
        )
        .unwrap();
        assert_eq!(resolved(sel), "lease-aaa");
    }

    #[test]
    fn id_wins_over_alias_collision() {
        // An exact id resolves even when another lease's alias equals that id —
        // id is checked before alias.
        let mut decoy = lease("lease-bbb", "p2", "Bound");
        decoy.alias = Some("lease-aaa".to_string());
        let active = vec![lease("lease-aaa", "p1", "Bound"), decoy];
        let sel = select(
            active,
            Some("lease-aaa"),
            OutputFormat::Text,
            OnAmbiguous::Reject,
        )
        .unwrap();
        assert_eq!(resolved(sel), "lease-aaa");
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
