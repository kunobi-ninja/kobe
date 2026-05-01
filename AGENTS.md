# Agent Guidance

## Documentation vs. internal notes

Written material for this project lives in two homes. Keep them separate.

### `docs/` — public documentation (in this repo)

- Feeds the documentation website consumed by kobe users.
- Scope: how to use kobe, API reference, CLI, getting started, operational guides, user-facing architecture.
- Audience: someone *using* kobe (operator, SRE, CI user).
- Rule of thumb: if an external adopter does not need to read it, it does not belong here.

Current structure:

- `docs/kobe-docs/` — the site source (MDX + `meta.json`).
- `docs/guides/` — operator how-to guides, referenced by the site.

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
| User-facing config / runbook / how-to | `docs/guides/*.md` |
| Plans, roadmap, ADRs, research | Obsidian vault (not in git) |

### Rules

- **Behavior change ⇒ doc-comment update in the same commit.** A PR review should reveal both the behavior shift and the explanation. A doc-comment that contradicts the body of the function is worse than no doc-comment.
- Prefer linking from doc-comments (`` [`OtherType`] ``, `` [`module::function`] ``) over duplicating prose. `cargo doc` resolves these automatically.
- Pin invariants with tests next to the doc-comment. The test name should mirror the invariant (`compute_pool_actions_keeps_min_ready_during_drift`).
- If a doc-comment grows beyond ~40 lines, that's a hint the code below it is too complex — split the function, don't shrink the doc.

### When `docs/` is right

`docs/` is for content an external kobe adopter needs to read. Operator runbooks (`docs/guides/`) and the site (`docs/kobe-docs/`) qualify. Algorithm internals, code-level decision rationale, and one-off design notes do not — they belong inline with the code or in the Obsidian vault.
