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

    /// Optional bootstrap runner job configuration.
    ///
    /// When set, the operator runs a host-cluster Job that targets the leased
    /// cluster using its generated kubeconfig Secret. This is useful for
    /// tool-driven installs like `flux install`, `helm upgrade --install`, or
    /// `kustomize build | kubectl apply`.
    #[serde(default)]
    pub job: Option<BootstrapJobSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BootstrapJobSpec {
    /// Container image for the bootstrap runner.
    pub image: String,

    /// Optional image pull policy.
    #[serde(default)]
    pub image_pull_policy: Option<String>,

    /// Entrypoint command for the runner container.
    #[serde(default)]
    pub command: Vec<String>,

    /// Arguments for the runner container.
    #[serde(default)]
    pub args: Vec<String>,

    /// Extra environment variables passed to the runner.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}
