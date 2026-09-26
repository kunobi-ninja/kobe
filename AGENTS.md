# Agent Guidance

## Documentation vs. internal notes

Written material for this project lives in two homes. Keep them separate.

### `docs/` — public documentation (in this repo)

- Feeds the documentation website consumed by kobe users.
- Scope: how to use kobe, API reference, CLI, getting started, operational guides, user-facing architecture.
- Audience: someone *using* kobe (operator, SRE, CI user).
- Rule of thumb: if an external adopter does not need to read it, it does not belong here.

Current structure:

- `docs/kobe-docs/` — the site source (MDX + `meta.json`). Operator runbooks that should appear on kunobi.com also live here under `operate/`.
- `docs/guides/` — operator how-to guides in the repo (CRD comments and code point here). Keep them as full documents, not stubs. If a guide is also on the site, update both.

### Internal notes — outside the repo

Plans, roadmap, ADRs, research, risk analysis, competitive notes, and draft specs live in the maintainer's Obsidian vault. They are **not tracked in git** and not distributed with the codebase.

### Rules when writing docs

- Do **not** create planning, roadmap, research, ADR, or draft-spec files inside `docs/`.
- `docs/` changes must be limited to public, user-facing documentation content.
- If the user asks you to write a plan, design doc, or internal spec and the target location is unclear, ask before writing — the likely destination is the Obsidian vault, not the repo.

## In-code documentation

The code is the source of truth for behavior. Doc-comments on what the code does belong on the code that does it. Standalone markdown about internals rots faster than the code it describes.

### Where each kind of doc lives

| What | Where |
|---|---|
| Module purpose, cross-cutting flow | `//!` at the top of `mod.rs` / the file |
| Struct or enum semantics | `///` on the type |
| Function contract, invariants, edge cases | `///` on the function |
| CRD field meaning / valid values | `#[schemars(description = "...")]` on the field |
| Why-this-shape decisions | inline `//` comment at the decision site |
| User-facing config / runbook / how-to | `docs/kobe-docs/` (site) and `docs/guides/*.md` (in-repo operator guides) |
| Plans, roadmap, ADRs, research | Obsidian vault (not in git) |

### Rules

- **Behavior change ⇒ doc-comment update in the same commit.** A PR review should reveal both the behavior shift and the explanation. A doc-comment that contradicts the body of the function is worse than no doc-comment.
- Prefer linking from doc-comments (`` [`OtherType`] ``, `` [`module::function`] ``) over duplicating prose. `cargo doc` resolves these automatically.
- Pin invariants with tests next to the doc-comment. The test name should mirror the invariant (`compute_pool_actions_keeps_min_ready_during_drift`).
- If a doc-comment grows beyond ~40 lines, that's a hint the code below it is too complex — split the function, don't shrink the doc.

### When `docs/` is right

`docs/` is for content an external kobe adopter needs to read. The site (`docs/kobe-docs/`) and operator runbooks (`docs/guides/`) qualify. Algorithm internals, code-level decision rationale, and one-off design notes do not — they belong inline with the code or in the Obsidian vault.

## Testing what another component has to agree with

Most defects found in this repo are not logic errors. They are the right shape
pointing at the wrong referent: code that does exactly what it says, about the
wrong thing.

Four from one week — a gate keyed on `metadata.generation`, which a delete does
not bump; a workflow input read from `HEAD` when the caller was pinned to an
older SHA; a `PATCH` sending `visibility: selected` without
`selected_repository_ids`, which empties the list rather than leaving it; and a
label selector hashing a pool's own name when members are labelled with a hash
of the upstream object's name, `kobe-<pool>`.

Unit tests do not catch these. A test written beside the code inherits the same
mental model, so it can prove internal consistency and never the agreement.
Every one of the above shipped with passing tests that are still correct.

### Assert against the other side's definition

If a function builds a name, path, selector or key that **another component
resolves**, the test must reference that component, not a literal:

```rust
// Wrong: agrees with whatever the author believed.
assert_eq!(warm_member_selector(&pool), "…=3f2a1c04");

// Right: fails when the producer's naming moves.
assert_eq!(
    warm_member_selector(&pool),
    format!("{WARM_POOL_LABEL}={}", upstream_name_hash(&management_object_name(&pool))),
);
```

Better still, put the two beside each other so they cannot drift.

### Label `ci:conformance` on cluster-facing changes

A selector, a name, a label, a path, an API shape another controller matches —
none of it is validated by `cargo test`. Applying `ci:conformance` to the PR
runs the k3s leg, which is the only thing that resolves those against a real
cluster.

It costs ~30 minutes and is opt-in precisely so it can be asked for. Ask for it
when the change constructs something someone else has to find.

### Read the whole object before writing part of it

A partial `PATCH` is not a partial write. Before mutating any API object, read
it whole and keep what you are not changing — the field you did not send may be
the one that gets cleared, and the response usually names the other lists right
beside the one you came for.
