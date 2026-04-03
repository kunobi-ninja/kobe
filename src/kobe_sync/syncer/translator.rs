use std::collections::BTreeMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

/// Maximum length for Kubernetes resource names (per RFC 1123 / K8s docs).
const MAX_K8S_NAME_LEN: usize = 253;

/// Label key indicating a resource is managed by kobe-sync.
pub const LABEL_MANAGED: &str = "vkobe.kunobi.ninja/managed";
/// Label key carrying the virtual namespace of a managed resource.
pub const LABEL_VNS: &str = "vkobe.kunobi.ninja/vns";
/// Annotation key recording the translation scheme version.
pub const ANNOTATION_SCHEME_VERSION: &str = "vkobe.kunobi.ninja/scheme-version";
/// Current scheme version.
pub const SCHEME_VERSION: &str = "1";

/// Translates names and metadata between the virtual cluster view and the host
/// cluster.
///
/// Virtual resources have simple names/namespaces (e.g. `my-app` in `default`).
/// On the host cluster every virtual namespace maps to a single host namespace
/// and the resource name carries a deterministic suffix so that names from
/// different virtual namespaces never collide.
///
/// **Format:** `{name}-x-{virtual_namespace}-x-{suffix}`
pub struct NameTranslator {
    host_namespace: String,
    suffix: String,
}

impl NameTranslator {
    /// Create a new translator.
    ///
    /// `host_namespace` is the single namespace on the host cluster where all
    /// translated resources live (e.g. `pool-e2e-basic-0`).
    pub fn new(host_namespace: String) -> Self {
        Self {
            host_namespace,
            suffix: "vc".to_string(),
        }
    }

    /// Translate a virtual resource name into a host resource name.
    ///
    /// Example: `to_host_name("my-app", "default")` -> `"my-app-x-default-x-vc"`
    ///
    /// When the translated name would exceed the Kubernetes 253-character limit,
    /// it is truncated and a deterministic hash is appended to preserve uniqueness.
    pub fn to_host_name(&self, virtual_name: &str, virtual_ns: &str) -> String {
        let full = format!("{}-x-{}-x-{}", virtual_name, virtual_ns, self.suffix);
        if full.len() <= MAX_K8S_NAME_LEN {
            return full;
        }
        // Truncate and append a hash to ensure uniqueness.
        let mut hasher = DefaultHasher::new();
        virtual_name.hash(&mut hasher);
        virtual_ns.hash(&mut hasher);
        let hash = format!("{:016x}", hasher.finish());
        let prefix_len = MAX_K8S_NAME_LEN - hash.len() - 1; // -1 for the dash
        let truncated = &full[..prefix_len];
        // Ensure truncated doesn't end with a dash (invalid K8s name).
        let truncated = truncated.trim_end_matches('-');
        format!("{truncated}-{hash}")
    }

    /// Reverse-translate a host resource name back to the virtual (name, namespace) pair.
    ///
    /// Returns `None` if the host name does not match the expected suffix pattern.
    pub fn to_virtual(&self, host_name: &str) -> Option<(String, String)> {
        let suffix_with_sep = format!("-x-{}", self.suffix);
        let without_suffix = host_name.strip_suffix(&suffix_with_sep)?;
        // Find the last `-x-` separator before the suffix — that separates the
        // virtual name from the virtual namespace.
        let sep = "-x-";
        let sep_pos = without_suffix.rfind(sep)?;
        let virtual_name = &without_suffix[..sep_pos];
        let virtual_ns = &without_suffix[sep_pos + sep.len()..];
        if virtual_name.is_empty() || virtual_ns.is_empty() {
            return None;
        }
        Some((virtual_name.to_string(), virtual_ns.to_string()))
    }

    /// The single host namespace where all translated resources live.
    pub fn host_namespace(&self) -> &str {
        &self.host_namespace
    }

    /// Labels that mark a resource as managed by kobe-sync and record the
    /// virtual namespace it belongs to.
    pub fn management_labels(&self, virtual_ns: &str) -> BTreeMap<String, String> {
        let mut labels = BTreeMap::new();
        labels.insert(LABEL_MANAGED.to_string(), "true".to_string());
        labels.insert(LABEL_VNS.to_string(), virtual_ns.to_string());
        labels
    }

    /// Annotations that record the translation scheme version.
    pub fn management_annotations(&self) -> BTreeMap<String, String> {
        let mut annotations = BTreeMap::new();
        annotations.insert(
            ANNOTATION_SCHEME_VERSION.to_string(),
            SCHEME_VERSION.to_string(),
        );
        annotations
    }

    /// Check whether the given label map contains the `managed=true` marker.
    pub fn is_managed(&self, labels: &BTreeMap<String, String>) -> bool {
        labels
            .get(LABEL_MANAGED)
            .map(|v| v == "true")
            .unwrap_or(false)
    }

    /// Return a new label map that is the union of `labels` and the management
    /// labels for the given virtual namespace.
    pub fn translate_labels(
        &self,
        labels: &BTreeMap<String, String>,
        virtual_ns: &str,
    ) -> BTreeMap<String, String> {
        let mut merged = labels.clone();
        for (k, v) in self.management_labels(virtual_ns) {
            merged.insert(k, v);
        }
        merged
    }

    /// Produce a translated `ObjectMeta` suitable for creating or patching a
    /// host-side resource.
    ///
    /// * `name` is translated via [`to_host_name`].
    /// * `namespace` is set to the host namespace.
    /// * Labels and annotations are merged with management metadata.
    /// * All other fields (resourceVersion, uid, etc.) are cleared so the
    ///   result can be used in a create/apply call.
    pub fn translate_object_meta(&self, meta: &ObjectMeta, virtual_ns: &str) -> ObjectMeta {
        let virtual_name = meta.name.as_deref().unwrap_or_default();

        let host_name = self.to_host_name(virtual_name, virtual_ns);

        let existing_labels = meta.labels.clone().unwrap_or_default();
        let translated_labels = self.translate_labels(&existing_labels, virtual_ns);

        let mut existing_annotations = meta.annotations.clone().unwrap_or_default();
        for (k, v) in self.management_annotations() {
            existing_annotations.insert(k, v);
        }

        ObjectMeta {
            name: Some(host_name),
            namespace: Some(self.host_namespace.clone()),
            labels: Some(translated_labels),
            annotations: Some(existing_annotations),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn translator() -> NameTranslator {
        NameTranslator::new("pool-e2e-basic-0".to_string())
    }

    #[test]
    fn test_to_host_name_basic() {
        let t = translator();
        assert_eq!(t.to_host_name("my-app", "default"), "my-app-x-default-x-vc");
    }

    #[test]
    fn test_to_host_name_custom_ns() {
        let t = translator();
        assert_eq!(
            t.to_host_name("nginx", "kube-system"),
            "nginx-x-kube-system-x-vc"
        );
    }

    #[test]
    fn test_to_virtual_basic() {
        let t = translator();
        let result = t.to_virtual("my-app-x-default-x-vc");
        assert_eq!(result, Some(("my-app".to_string(), "default".to_string())));
    }

    #[test]
    fn test_to_virtual_with_hyphens_in_name() {
        let t = translator();
        let result = t.to_virtual("my-cool-app-x-kube-system-x-vc");
        assert_eq!(
            result,
            Some(("my-cool-app".to_string(), "kube-system".to_string()))
        );
    }

    #[test]
    fn test_to_virtual_not_translated() {
        let t = translator();
        assert_eq!(t.to_virtual("some-random-name"), None);
    }

    #[test]
    fn test_to_virtual_missing_suffix() {
        let t = translator();
        assert_eq!(t.to_virtual("app-x-default"), None);
    }

    #[test]
    fn test_to_virtual_empty_parts() {
        let t = translator();
        // "-x--x-vc" => name="" ns="" → None
        assert_eq!(t.to_virtual("-x--x-vc"), None);
    }

    #[test]
    fn test_roundtrip() {
        let t = translator();
        let host = t.to_host_name("api-server", "production");
        let (name, ns) = t.to_virtual(&host).expect("roundtrip should succeed");
        assert_eq!(name, "api-server");
        assert_eq!(ns, "production");
    }

    #[test]
    fn test_host_namespace() {
        let t = translator();
        assert_eq!(t.host_namespace(), "pool-e2e-basic-0");
    }

    #[test]
    fn test_management_labels() {
        let t = translator();
        let labels = t.management_labels("default");
        assert_eq!(labels.get(LABEL_MANAGED), Some(&"true".to_string()));
        assert_eq!(labels.get(LABEL_VNS), Some(&"default".to_string()));
        assert_eq!(labels.len(), 2);
    }

    #[test]
    fn test_management_annotations() {
        let t = translator();
        let anns = t.management_annotations();
        assert_eq!(anns.get(ANNOTATION_SCHEME_VERSION), Some(&"1".to_string()));
        assert_eq!(anns.len(), 1);
    }

    #[test]
    fn test_is_managed_true() {
        let t = translator();
        let mut labels = BTreeMap::new();
        labels.insert(LABEL_MANAGED.to_string(), "true".to_string());
        assert!(t.is_managed(&labels));
    }

    #[test]
    fn test_is_managed_false_missing() {
        let t = translator();
        let labels = BTreeMap::new();
        assert!(!t.is_managed(&labels));
    }

    #[test]
    fn test_is_managed_false_wrong_value() {
        let t = translator();
        let mut labels = BTreeMap::new();
        labels.insert(LABEL_MANAGED.to_string(), "false".to_string());
        assert!(!t.is_managed(&labels));
    }

    #[test]
    fn test_translate_labels_merges() {
        let t = translator();
        let mut original = BTreeMap::new();
        original.insert("app".to_string(), "nginx".to_string());
        original.insert("tier".to_string(), "frontend".to_string());

        let result = t.translate_labels(&original, "staging");
        assert_eq!(result.get("app"), Some(&"nginx".to_string()));
        assert_eq!(result.get("tier"), Some(&"frontend".to_string()));
        assert_eq!(result.get(LABEL_MANAGED), Some(&"true".to_string()));
        assert_eq!(result.get(LABEL_VNS), Some(&"staging".to_string()));
        assert_eq!(result.len(), 4);
    }

    #[test]
    fn test_translate_labels_overwrites_management() {
        let t = translator();
        let mut original = BTreeMap::new();
        original.insert(LABEL_MANAGED.to_string(), "false".to_string());

        let result = t.translate_labels(&original, "default");
        assert_eq!(result.get(LABEL_MANAGED), Some(&"true".to_string()));
    }

    #[test]
    fn test_translate_object_meta() {
        let t = translator();
        let meta = ObjectMeta {
            name: Some("my-config".to_string()),
            namespace: Some("default".to_string()),
            labels: Some({
                let mut m = BTreeMap::new();
                m.insert("app".to_string(), "web".to_string());
                m
            }),
            annotations: Some({
                let mut m = BTreeMap::new();
                m.insert("note".to_string(), "test".to_string());
                m
            }),
            ..Default::default()
        };

        let translated = t.translate_object_meta(&meta, "default");

        assert_eq!(
            translated.name,
            Some("my-config-x-default-x-vc".to_string())
        );
        assert_eq!(translated.namespace, Some("pool-e2e-basic-0".to_string()));

        let labels = translated.labels.as_ref().unwrap();
        assert_eq!(labels.get("app"), Some(&"web".to_string()));
        assert_eq!(labels.get(LABEL_MANAGED), Some(&"true".to_string()));
        assert_eq!(labels.get(LABEL_VNS), Some(&"default".to_string()));

        let annotations = translated.annotations.as_ref().unwrap();
        assert_eq!(annotations.get("note"), Some(&"test".to_string()));
        assert_eq!(
            annotations.get(ANNOTATION_SCHEME_VERSION),
            Some(&"1".to_string())
        );

        // Ownership metadata should be cleared
        assert!(translated.resource_version.is_none());
        assert!(translated.uid.is_none());
    }

    #[test]
    fn test_translate_object_meta_no_existing_labels() {
        let t = translator();
        let meta = ObjectMeta {
            name: Some("bare".to_string()),
            ..Default::default()
        };

        let translated = t.translate_object_meta(&meta, "myns");

        assert_eq!(translated.name, Some("bare-x-myns-x-vc".to_string()));
        let labels = translated.labels.as_ref().unwrap();
        assert_eq!(labels.get(LABEL_MANAGED), Some(&"true".to_string()));
        assert_eq!(labels.get(LABEL_VNS), Some(&"myns".to_string()));
    }

    #[test]
    fn test_to_virtual_namespace_with_hyphens() {
        let t = translator();
        // Virtual name "a" in namespace "b-c-d"
        let host = t.to_host_name("a", "b-c-d");
        assert_eq!(host, "a-x-b-c-d-x-vc");
        let (name, ns) = t.to_virtual(&host).unwrap();
        assert_eq!(name, "a");
        assert_eq!(ns, "b-c-d");
    }

    #[test]
    fn test_to_virtual_name_containing_x() {
        let t = translator();
        // Virtual name that itself contains "-x-"
        let host = t.to_host_name("my-x-app", "default");
        assert_eq!(host, "my-x-app-x-default-x-vc");
        let (name, ns) = t.to_virtual(&host).unwrap();
        assert_eq!(name, "my-x-app");
        assert_eq!(ns, "default");
    }

    #[test]
    fn test_long_name_is_truncated() {
        let t = translator();
        let long_name = "a".repeat(200);
        let long_ns = "b".repeat(100);
        let result = t.to_host_name(&long_name, &long_ns);
        assert!(result.len() <= 253);
        assert!(!result.ends_with('-'));
    }

    #[test]
    fn test_long_name_is_deterministic() {
        let t = translator();
        let long_name = "a".repeat(200);
        let long_ns = "b".repeat(100);
        let r1 = t.to_host_name(&long_name, &long_ns);
        let r2 = t.to_host_name(&long_name, &long_ns);
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_truncated_name_no_reverse() {
        let t = translator();
        let long_name = "a".repeat(200);
        let long_ns = "b".repeat(100);
        let host = t.to_host_name(&long_name, &long_ns);
        // Truncated names cannot be reverse-translated.
        assert!(t.to_virtual(&host).is_none());
    }
}
