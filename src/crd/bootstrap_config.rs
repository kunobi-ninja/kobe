use std::collections::BTreeMap;

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// BootstrapConfig stores a reusable bootstrap bundle in the host cluster.
#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "kobe.kunobi.ninja",
    version = "v1alpha1",
    kind = "BootstrapConfig",
    plural = "bootstrapconfigs",
    shortname = "bc",
    namespaced
)]
#[serde(rename_all = "camelCase")]
pub struct BootstrapConfigSpec {
    /// Bundle files keyed by file name.
    ///
    /// The initial MVP treats all `*.yaml` / `*.yml` entries as manifests and
    /// applies them in lexical order. This keeps the API ready for richer
    /// renderers later while already supporting built-in and custom bundles.
    #[serde(default)]
    pub files: BTreeMap<String, String>,
}
