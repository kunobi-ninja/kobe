//! kobe-sync virtual cluster runtime.
//!
//! This module contains the core components of the kobe-sync binary:
//! - **bootstrap**: One-shot RBAC bootstrap on the virtual apiserver
//! - **config**: Runtime configuration loading
//! - **certs**: CA and serving certificate management
//! - **proxy**: Reverse proxy with name/namespace translation
//! - **syncer**: Resource syncer framework and implementations
//! - **upgrade**: HTTP Upgrade tunnel for exec/attach/portforward

// This module is only used by the kobe-sync binary; dead-code analysis from
// the operator binary would flag everything here.
#![allow(dead_code, unused_imports)]

pub mod bootstrap;
pub mod certs;
pub mod config;
pub mod proxy;
pub mod syncer;
pub mod upgrade;
