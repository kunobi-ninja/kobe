//! Per-shell session state for kobe's active target.
//!
//! Thin wrapper around `kunobi_auth::client::session`, which provides
//! the cross-platform parent-PID-keyed file machinery used by all
//! Kunobi CLIs. This module only exists to:
//!
//! - hard-code the `"kobe"` product key in one place so call sites
//!   don't pass it everywhere,
//! - declare the kobe-specific [`SessionState`] shape (just
//!   `current_target` today; future fields would land here).
//!
//! See `kunobi_auth::client::session` for the storage layout, the
//! `KUNOBI_SESSIONS_DIR` test override, and the rationale for using
//! the parent shell PID instead of env vars or shell hooks.

use anyhow::Result;
use kunobi_auth::client::session as base;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Product key under which kobe's session files live in the shared
/// Kunobi cache (`<cache>/kunobi/sessions/kobe/<ppid>.json`).
const PRODUCT: &str = "kobe";

/// Persistent state for one interactive shell's `kobe` session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionState {
    pub current_target: String,
}

/// Read the current shell's session state, if any.
pub fn load() -> Result<Option<(SessionState, PathBuf, u32)>> {
    base::load::<SessionState>(PRODUCT)
}

/// Write the current shell's session state, replacing any previous
/// content.
pub fn save(state: &SessionState) -> Result<PathBuf> {
    base::save(PRODUCT, state)
}

/// Remove the current shell's session file. No-op if it doesn't exist.
/// Currently used only by tests; exposed as `pub` so a future
/// `kobe config logout-target` (or similar) can reuse it without
/// re-deriving the path.
#[allow(dead_code)]
pub fn clear() -> Result<()> {
    base::clear(PRODUCT)
}

/// Sweep session files whose owning shell PID has exited.
pub fn gc_dead_sessions() {
    base::gc_dead_sessions(PRODUCT);
}
