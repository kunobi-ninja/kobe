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
