use std::collections::BTreeMap;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

/// Maximum length for Kubernetes resource names (per RFC 1123 / K8s docs).
const MAX_K8S_NAME_LEN: usize = 253;

/// The separator token that joins `{name}`, `{virtual_namespace}`, and the
/// `{suffix}` in a host name (e.g. `my-app-x-default-x-vc`).
const SEPARATOR: &str = "-x-";

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
    /// Example: `to_host_name("my-app", "default")` -> `Ok("my-app-x-default-x-vc")`
    ///
    /// When the translated name would exceed the Kubernetes 253-character limit,
    /// it is truncated and a deterministic hash is appended to preserve uniqueness.
    ///
    /// # Errors
    ///
    /// Returns [`TranslateError::SeparatorInIdentity`] when the virtual name or
    /// namespace itself contains the `-x-` separator token. Such an input would
    /// produce an ambiguous host name: distinct `(name, ns)` pairs could collide
    /// onto the same host object (cross-tenant clobber in the host namespace),
    /// and the reverse split in [`to_virtual`](Self::to_virtual) could not
    /// recover the original pair. Both are k8s-legal names, so we reject them
    /// loudly at sync time rather than silently mistranslating.
    pub fn to_host_name(
        &self,
        virtual_name: &str,
        virtual_ns: &str,
    ) -> Result<String, TranslateError> {
        if virtual_name.contains(SEPARATOR) {
            return Err(TranslateError::SeparatorInIdentity {
                field: "name",
                value: virtual_name.to_string(),
            });
        }
        if virtual_ns.contains(SEPARATOR) {
            return Err(TranslateError::SeparatorInIdentity {
                field: "namespace",
                value: virtual_ns.to_string(),
            });
        }

        let full = format!(
            "{virtual_name}{SEPARATOR}{virtual_ns}{SEPARATOR}{}",
            self.suffix
        );
        if full.len() <= MAX_K8S_NAME_LEN {
            return Ok(full);
        }
        // Truncate and append a build-stable hash to ensure uniqueness. FNV-1a
        // is used (not `DefaultHasher`, whose algorithm is unspecified and may
        // change across Rust releases) so a toolchain bump never re-hashes an
        // already-synced object's name and orphans it. Mirrors `hash_identity`
        // in `src/api/routes.rs`.
        let hash = fnv1a_hex(virtual_name, virtual_ns);
        let prefix_len = MAX_K8S_NAME_LEN - hash.len() - 1; // -1 for the dash
        let truncated = &full[..prefix_len];
        // Ensure truncated doesn't end with a dash (invalid K8s name).
        let truncated = truncated.trim_end_matches('-');
        Ok(format!("{truncated}-{hash}"))
    }

    /// Reverse-translate a host resource name back to the virtual (name, namespace) pair.
    ///
    /// Returns `None` if the host name does not match the expected suffix pattern.
    pub fn to_virtual(&self, host_name: &str) -> Option<(String, String)> {
        let suffix_with_sep = format!("{SEPARATOR}{}", self.suffix);
        let without_suffix = host_name.strip_suffix(&suffix_with_sep)?;
        // Find the last `-x-` separator before the suffix — that separates the
        // virtual name from the virtual namespace. Forward translation rejects
        // any name/namespace containing the separator (see `to_host_name`), so
        // a single split point is unambiguous for every name we produce.
        let sep_pos = without_suffix.rfind(SEPARATOR)?;
        let virtual_name = &without_suffix[..sep_pos];
        let virtual_ns = &without_suffix[sep_pos + SEPARATOR.len()..];
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
    ///
    /// # Errors
    ///
    /// Propagates [`TranslateError`] from [`to_host_name`](Self::to_host_name)
    /// when the virtual name or namespace contains the `-x-` separator token.
    pub fn translate_object_meta(
        &self,
        meta: &ObjectMeta,
        virtual_ns: &str,
    ) -> Result<ObjectMeta, TranslateError> {
        let virtual_name = meta.name.as_deref().unwrap_or_default();

        let host_name = self.to_host_name(virtual_name, virtual_ns)?;

        let existing_labels = meta.labels.clone().unwrap_or_default();
        let translated_labels = self.translate_labels(&existing_labels, virtual_ns);

        let mut existing_annotations = meta.annotations.clone().unwrap_or_default();
        for (k, v) in self.management_annotations() {
            existing_annotations.insert(k, v);
        }

        Ok(ObjectMeta {
            name: Some(host_name),
            namespace: Some(self.host_namespace.clone()),
            labels: Some(translated_labels),
            annotations: Some(existing_annotations),
            ..Default::default()
        })
    }
}

/// Error returned by name translation when an input cannot be safely encoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TranslateError {
    /// A virtual name or namespace contained the `-x-` separator token, which
    /// would produce an ambiguous (potentially colliding) host name.
    SeparatorInIdentity {
        /// Which identity field carried the separator (`"name"` / `"namespace"`).
        field: &'static str,
        /// The offending value.
        value: String,
    },
}

impl std::fmt::Display for TranslateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TranslateError::SeparatorInIdentity { field, value } => write!(
                f,
                "virtual {field} {value:?} contains the reserved `-x-` separator token; \
                 cannot produce an unambiguous host name"
            ),
        }
    }
}

impl std::error::Error for TranslateError {}

/// FNV-1a hash of `name` + `namespace`, rendered as a fixed 16-hex-digit
/// string. Build-stable across Rust releases (unlike `DefaultHasher`), so a
/// truncated host name is reproducible after a toolchain bump. Constants match
/// `hash_identity` in `src/api/routes.rs`.
fn fnv1a_hex(name: &str, namespace: &str) -> String {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x00000100000001B3;

    let mut hash = FNV_OFFSET;
    // Hash name, then a `-x-` domain separator, then namespace, so that e.g.
    // ("ab", "c") and ("a", "bc") never collide.
    for byte in name
        .as_bytes()
        .iter()
        .chain(SEPARATOR.as_bytes())
        .chain(namespace.as_bytes())
    {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    format!("{hash:016x}")
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
        assert_eq!(
            t.to_host_name("my-app", "default").unwrap(),
            "my-app-x-default-x-vc"
        );
    }

    #[test]
    fn test_to_host_name_custom_ns() {
        let t = translator();
        assert_eq!(
            t.to_host_name("nginx", "kube-system").unwrap(),
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
        let host = t.to_host_name("api-server", "production").unwrap();
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

        let translated = t.translate_object_meta(&meta, "default").unwrap();

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

        let translated = t.translate_object_meta(&meta, "myns").unwrap();

        assert_eq!(translated.name, Some("bare-x-myns-x-vc".to_string()));
        let labels = translated.labels.as_ref().unwrap();
        assert_eq!(labels.get(LABEL_MANAGED), Some(&"true".to_string()));
        assert_eq!(labels.get(LABEL_VNS), Some(&"myns".to_string()));
    }

    #[test]
    fn test_to_virtual_namespace_with_hyphens() {
        let t = translator();
        // Virtual name "a" in namespace "b-c-d" (plain hyphens, no `-x-`).
        let host = t.to_host_name("a", "b-c-d").unwrap();
        assert_eq!(host, "a-x-b-c-d-x-vc");
        let (name, ns) = t.to_virtual(&host).unwrap();
        assert_eq!(name, "a");
        assert_eq!(ns, "b-c-d");
    }

    /// A virtual name containing the `-x-` separator token is rejected up
    /// front. Without rejection it would produce an ambiguous host name
    /// (see `test_collision_is_rejected`), so we surface the error loudly
    /// instead of silently mistranslating.
    #[test]
    fn test_to_host_name_rejects_separator_in_name() {
        let t = translator();
        let err = t.to_host_name("my-x-app", "default").unwrap_err();
        assert_eq!(
            err,
            TranslateError::SeparatorInIdentity {
                field: "name",
                value: "my-x-app".to_string(),
            }
        );
    }

    #[test]
    fn test_to_host_name_rejects_separator_in_namespace() {
        let t = translator();
        let err = t.to_host_name("app", "team-x-prod").unwrap_err();
        assert_eq!(
            err,
            TranslateError::SeparatorInIdentity {
                field: "namespace",
                value: "team-x-prod".to_string(),
            }
        );
    }

    /// Collision/ambiguity case: WITHOUT the separator guard, these two
    /// distinct `(name, ns)` pairs both format to the same host string
    /// `a-x-b-x-c-x-vc`, which is the cross-tenant clobber the guard
    /// prevents. The guard makes both inputs error out instead.
    #[test]
    fn test_collision_is_rejected() {
        let t = translator();
        // ("a-x-b", "c") and ("a", "b-x-c") would both naively render as
        // "a-x-b-x-c-x-vc" — an ambiguous, colliding host name.
        assert!(t.to_host_name("a-x-b", "c").is_err());
        assert!(t.to_host_name("a", "b-x-c").is_err());
    }

    #[test]
    fn test_translate_object_meta_rejects_separator() {
        let t = translator();
        let meta = ObjectMeta {
            name: Some("svc-x-evil".to_string()),
            ..Default::default()
        };
        assert!(t.translate_object_meta(&meta, "default").is_err());
    }

    #[test]
    fn test_long_name_is_truncated() {
        let t = translator();
        let long_name = "a".repeat(200);
        let long_ns = "b".repeat(100);
        let result = t.to_host_name(&long_name, &long_ns).unwrap();
        assert!(result.len() <= 253);
        assert!(!result.ends_with('-'));
    }

    #[test]
    fn test_long_name_is_deterministic() {
        let t = translator();
        let long_name = "a".repeat(200);
        let long_ns = "b".repeat(100);
        let r1 = t.to_host_name(&long_name, &long_ns).unwrap();
        let r2 = t.to_host_name(&long_name, &long_ns).unwrap();
        assert_eq!(r1, r2);
    }

    /// Build-stability assertion: a known input maps to a known fixed hash
    /// suffix. FNV-1a is deterministic across Rust releases, so this value
    /// must never change — if a toolchain bump altered it, every truncated
    /// host name would change and orphan the previously-synced object.
    #[test]
    fn test_truncated_hash_suffix_is_stable() {
        let t = translator();
        let long_name = "a".repeat(200);
        let long_ns = "b".repeat(100);
        let host = t.to_host_name(&long_name, &long_ns).unwrap();
        // The suffix is the last 16 hex chars after the final dash.
        let suffix = host.rsplit('-').next().unwrap();
        assert_eq!(suffix.len(), 16, "suffix must be 16 hex digits: {host}");
        // Known fixed FNV-1a value for these exact inputs.
        assert_eq!(
            suffix, "379313b7e60dafdf",
            "truncation hash suffix must be build-stable; got {host}"
        );
    }

    /// The raw FNV-1a helper is order-sensitive (domain-separated), so e.g.
    /// ("ab", "c") and ("a", "bc") produce different digests even though
    /// their naive concatenation matches.
    #[test]
    fn test_fnv1a_hex_domain_separated() {
        assert_ne!(fnv1a_hex("ab", "c"), fnv1a_hex("a", "bc"));
        // Stable known value.
        assert_eq!(fnv1a_hex("my-app", "default").len(), 16);
    }

    #[test]
    fn test_truncated_name_no_reverse() {
        let t = translator();
        let long_name = "a".repeat(200);
        let long_ns = "b".repeat(100);
        let host = t.to_host_name(&long_name, &long_ns).unwrap();
        // Truncated names cannot be reverse-translated.
        assert!(t.to_virtual(&host).is_none());
    }
}
