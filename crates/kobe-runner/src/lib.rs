//! The Kobe Sandbox runner: one supervised command, and the contract Kobe
//! drives it with (#82).
//!
//! # Why this is a library as well as a binary
//!
//! Kobe writes the requests and reads the replies; the runner does the reverse,
//! from a different image built on a different day. Two hand-maintained copies
//! of a wire format drift, and the drift shows up as a *misread* reply rather
//! than a broken one — a caller told their command succeeded because a field
//! moved. [`protocol`] is compiled into both halves so that cannot happen.
//!
//! The operator depends on this crate for [`protocol`] alone. Everything else
//! here runs inside the Sandbox container.

pub mod protocol;
pub mod spool;
#[cfg(unix)]
pub mod supervisor;
