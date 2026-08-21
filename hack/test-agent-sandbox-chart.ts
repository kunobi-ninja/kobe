#!/usr/bin/env bun

const chart = "charts/kobe";
const releaseFixture = "hack/fixtures/agent-sandbox-v0.5.6.yaml";
const releaseSha256 =
	"1696dbb6faded503149b3994badb599df5dcf24d5985466881784f442dd9c3e5";
const taggedImage =
	"registry.k8s.io/agent-sandbox/agent-sandbox-controller:v0.5.6";
const upstreamCrds = new Set([
	"sandboxclaims.extensions.agents.x-k8s.io",
	"sandboxes.agents.x-k8s.io",
	"sandboxtemplates.extensions.agents.x-k8s.io",
	"sandboxwarmpools.extensions.agents.x-k8s.io",
]);

function invariant(condition: unknown, message: string): asserts condition {
	if (!condition) throw new Error(message);
}

function sha256(value: string | Uint8Array): string {
	return new Bun.CryptoHasher("sha256").update(value).digest("hex");
}

async function helm(
	mode: string,
	release = "kobe",
	namespace = "kobe-system",
): Promise<string> {
	const process = Bun.spawn(
		[
			"helm",
			"template",
			release,
			chart,
			"--namespace",
			namespace,
			"--set",
			`agentSandbox.mode=${mode}`,
		],
		{ stdout: "pipe", stderr: "pipe" },
	);
	const [stdout, stderr, exitCode] = await Promise.all([
		new Response(process.stdout).text(),
		new Response(process.stderr).text(),
		process.exited,
	]);
	invariant(
		exitCode === 0,
		`helm template ${release}/${namespace} ${mode} failed: ${stderr}`,
	);
	return stdout;
}

async function helmRejects(mode: string): Promise<void> {
	const process = Bun.spawn(
		["helm", "template", "kobe", chart, "--set", `agentSandbox.mode=${mode}`],
		{ stdout: "ignore", stderr: "pipe" },
	);
	const [stderr, exitCode] = await Promise.all([
		new Response(process.stderr).text(),
		process.exited,
	]);
	invariant(exitCode !== 0, `${mode} mode unexpectedly rendered`);
	invariant(
		stderr.includes("agentSandbox") && stderr.includes("mode"),
		`${mode} mode error is not actionable`,
	);
}

function parseDocuments(yaml: string): Record<string, unknown>[] {
	return yaml
		.split(/^---\s*$/m)
		.map((document) => document.trim())
		.filter(Boolean)
		.map((document) => Bun.YAML.parse(document) as Record<string, unknown>)
		.filter(
			(document) =>
				document && typeof document === "object" && "kind" in document,
		);
}

function metadata(document: Record<string, unknown>): Record<string, unknown> {
	return (document.metadata ?? {}) as Record<string, unknown>;
}

function annotations(
	document: Record<string, unknown>,
): Record<string, unknown> {
	return (metadata(document).annotations ?? {}) as Record<string, unknown>;
}

function objectNamed(
	documents: Record<string, unknown>[],
	kind: string,
	name: string,
): Record<string, unknown> | undefined {
	return documents.find(
		(document) => document.kind === kind && metadata(document).name === name,
	);
}

function teardownFencePolicy(
	documents: Record<string, unknown>[],
): Record<string, unknown> | undefined {
	return documents.find((document) => {
		if (document.kind !== "ValidatingAdmissionPolicy") return false;
		const spec = (document.spec ?? {}) as Record<string, unknown>;
		const paramKind = (spec.paramKind ?? {}) as Record<string, unknown>;
		return paramKind.apiVersion === "v1" && paramKind.kind === "ConfigMap";
	});
}

// -----------------------------------------------------------------------------
// The pinned release fixture is the compatibility oracle for external mode and
// the harness's operator-role install source. It must remain the exact
// upstream v0.5.6 asset; the digest pin happens where it is applied.
// -----------------------------------------------------------------------------

const source = await Bun.file(releaseFixture).text();
invariant(
	sha256(source) === releaseSha256,
	"pinned release fixture digest drifted",
);
invariant(
	source.includes(taggedImage),
	"pinned release fixture lost the upstream controller image",
);

const fixtureDocuments = parseDocuments(source);
const fixtureCrds = fixtureDocuments.filter(
	(document) =>
		document.kind === "CustomResourceDefinition" &&
		upstreamCrds.has(String(metadata(document).name)),
);
invariant(
	fixtureCrds.length === 4,
	`fixture contains ${fixtureCrds.length} upstream CRDs, expected 4`,
);

const warmPoolCrd = fixtureCrds.find(
	(crd) => metadata(crd).name === "sandboxwarmpools.extensions.agents.x-k8s.io",
);
invariant(warmPoolCrd, "fixture WarmPool CRD is missing");
const warmPoolVersions = (warmPoolCrd.spec as Record<string, unknown>)
	.versions as Array<Record<string, unknown>>;
const warmPoolV1Beta1 = warmPoolVersions.find(
	(version) => version.name === "v1beta1" && version.served === true,
);
invariant(warmPoolV1Beta1, "fixture WarmPool v1beta1 schema is missing");
const warmPoolSchema = warmPoolV1Beta1.schema as Record<string, unknown>;
const warmPoolRoot = warmPoolSchema.openAPIV3Schema as Record<string, unknown>;
const warmPoolProperties = warmPoolRoot.properties as Record<string, unknown>;
const warmPoolStatus = warmPoolProperties.status as Record<string, unknown>;
const warmPoolStatusProperties = warmPoolStatus.properties as Record<
	string,
	unknown
>;
const observedGeneration =
	warmPoolStatusProperties.observedGeneration as Record<string, unknown>;
invariant(
	observedGeneration.type === "integer" &&
		observedGeneration.format === "int64" &&
		observedGeneration.minimum === 0,
	"fixture WarmPool CRD lacks v0.5.6 status.observedGeneration",
);

invariant(
	!fixtureDocuments.some((document) =>
		`${String(document.kind)} ${String(metadata(document).name)}`
			.toLowerCase()
			.includes("router"),
	),
	"fixture contains an Agent Sandbox Router resource",
);

// -----------------------------------------------------------------------------
// The chart owns no part of the runtime. Neither mode may render upstream
// objects, and the retired managed mode must fail values validation instead of
// silently rendering nothing.
// -----------------------------------------------------------------------------

const [disabledYaml, externalYaml] = await Promise.all([
	helm("disabled"),
	helm("external"),
]);
const disabled = parseDocuments(disabledYaml);
const external = parseDocuments(externalYaml);

// The proof process is structurally separate even when Agent Sandbox itself is
// disabled. Admission/RBAC complete this boundary; these checks pin the pod,
// namespace and identity contract that those controls refer to.
const authority = objectNamed(
	external,
	"Deployment",
	"kobe-teardown-authority",
);
invariant(authority, "chart omitted the teardown-authority Deployment");
const authorityNamespace = String(metadata(authority).namespace ?? "");
invariant(
	authorityNamespace !== "" && authorityNamespace !== "kobe-system",
	"teardown authority shares the general operator namespace",
);
invariant(
	objectNamed(external, "Namespace", authorityNamespace),
	"chart omitted the dedicated teardown-authority Namespace",
);
const authorityServiceAccount = objectNamed(
	external,
	"ServiceAccount",
	"kobe-teardown-authority",
);
invariant(
	authorityServiceAccount &&
		metadata(authorityServiceAccount).namespace === authorityNamespace,
	"teardown authority ServiceAccount is not in its dedicated namespace",
);
const authorityPod = ((authority.spec as Record<string, unknown>).template as Record<
	string,
	unknown
>).spec as Record<string, unknown>;
invariant(
	authorityPod.serviceAccountName === "kobe-teardown-authority",
	"teardown authority pod does not use the dedicated ServiceAccount",
);
const authorityContainer = (authorityPod.containers as Record<string, unknown>[])[0];
const authorityEnv = new Map(
	(authorityContainer.env as Record<string, unknown>[]).map((entry) => [
		String(entry.name),
		entry.value,
	]),
);
invariant(
	authorityEnv.get("KOBE_PROCESS_ROLE") === "teardown-authority" &&
		authorityEnv.get("AGENT_SANDBOX_MODE") === "disabled",
	"teardown authority can run general lifecycle or Sandbox placement",
);
const authorityUsername = String(
	authorityEnv.get("KOBE_TEARDOWN_AUTHORITY_USERNAME") ?? "",
);
const controlPlaneUsername = String(
	authorityEnv.get("KOBE_CONTROL_PLANE_USERNAME") ?? "",
);
const authorityPolicyName = String(
	authorityEnv.get("KOBE_TEARDOWN_AUTHORITY_POLICY_NAME") ?? "",
);
const firewallPolicyName = String(
	authorityEnv.get("KOBE_TEARDOWN_AUTHORITY_FIREWALL_POLICY_NAME") ?? "",
);
invariant(
	authorityUsername ===
		`system:serviceaccount:${authorityNamespace}:kobe-teardown-authority`,
	"teardown authority username does not bind its dedicated namespace and ServiceAccount",
);
invariant(
	controlPlaneUsername === "system:serviceaccount:kobe-system:kobe" &&
		controlPlaneUsername !== authorityUsername,
	"startup contract does not name the distinct general control-plane identity",
);
for (const [name, value] of [
	["authority policy", authorityPolicyName],
	["identity firewall", firewallPolicyName],
] as const) {
	invariant(
		value.length > 0 && value.length <= 63 && /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/.test(value),
		`${name} has an invalid cluster-scoped name`,
	);
}
invariant(
	authorityPolicyName !== firewallPolicyName,
	"field authority policy and identity firewall share one name",
);

for (const [mode, documents] of [
	["disabled", disabled],
	["external", external],
] as const) {
	const deployment = objectNamed(documents, "Deployment", "kobe-teardown-authority");
	invariant(deployment, `${mode} omitted the teardown-authority Deployment`);
	const pod = ((deployment.spec as Record<string, unknown>).template as Record<
		string,
		unknown
	>).spec as Record<string, unknown>;
	const container = (pod.containers as Record<string, unknown>[])[0];
	const env = new Map(
		(container.env as Record<string, unknown>[]).map((entry) => [
			String(entry.name),
			entry.value,
		]),
	);
	invariant(
		env.get("KOBE_TEARDOWN_AUTHORITY_POLICY_NAME") === authorityPolicyName &&
			env.get("KOBE_TEARDOWN_AUTHORITY_FIREWALL_POLICY_NAME") === firewallPolicyName,
		`${mode} changed the mandatory startup policy pair`,
	);
}

const otherNamespace = parseDocuments(await helm("external", "kobe", "other-system"));
const otherAuthority = objectNamed(
	otherNamespace,
	"Deployment",
	"kobe-teardown-authority",
);
invariant(otherAuthority, "second namespace omitted teardown authority");
const otherPod = ((otherAuthority.spec as Record<string, unknown>)
	.template as Record<string, unknown>).spec as Record<string, unknown>;
const otherEnv = new Map(
	((otherPod.containers as Record<string, unknown>[])[0].env as Record<
		string,
		unknown
	>[]).map((entry) => [String(entry.name), entry.value]),
);
invariant(
	otherEnv.get("KOBE_TEARDOWN_AUTHORITY_POLICY_NAME") !== authorityPolicyName &&
		otherEnv.get("KOBE_TEARDOWN_AUTHORITY_FIREWALL_POLICY_NAME") !== firewallPolicyName,
	"equal release names in different namespaces collide on cluster-scoped policy names",
);

const controlPlane = objectNamed(external, "Deployment", "kobe");
invariant(controlPlane, "chart omitted the control-plane Deployment");
const controlPlanePod = (((controlPlane.spec as Record<string, unknown>)
	.template as Record<string, unknown>).spec ?? {}) as Record<string, unknown>;
const controlPlaneContainer = (
	controlPlanePod.containers as Record<string, unknown>[]
)[0];
const controlPlaneEnv = new Map(
	(controlPlaneContainer.env as Record<string, unknown>[]).map((entry) => [
		String(entry.name),
		entry.value,
	]),
);
invariant(
	controlPlaneEnv.get("KOBE_PROCESS_ROLE") === "control-plane",
	"general Deployment did not select the lifecycle-only process role",
);

const generalRole = objectNamed(external, "ClusterRole", "kobe");
invariant(generalRole, "chart omitted the general control-plane ClusterRole");
const generalRules = (generalRole.rules ?? []) as Record<string, unknown>[];
invariant(
	generalRules.every(
		(rule) =>
			!Array.isArray(rule.verbs) || !rule.verbs.includes("impersonate"),
	),
	"general control-plane identity can impersonate another Kubernetes identity",
);
const evidenceRule = generalRules.find(
	(rule) =>
		Array.isArray(rule.resources) &&
		rule.resources.includes("verifiedteardownevidence"),
);
invariant(evidenceRule, "general control plane cannot authenticate teardown evidence");
invariant(
	Array.isArray(evidenceRule.verbs) &&
		["get", "list", "watch"].every((verb) => evidenceRule.verbs.includes(verb)) &&
		["create", "update", "patch", "delete"].every(
			(verb) => !evidenceRule.verbs.includes(verb),
		),
	"general control plane can mutate teardown evidence",
);


for (const [mode, documents] of [
	["disabled", disabled],
	["external", external],
] as const) {
	invariant(
		!objectNamed(documents, "Deployment", "agent-sandbox-controller"),
		`${mode} rendered the upstream controller`,
	);
	invariant(
		!objectNamed(documents, "BootstrapConfig", "agent-sandbox-v0-5-6"),
		`${mode} rendered a child runtime bootstrap`,
	);
	invariant(
		!documents.some(
			(document) =>
				document.kind === "CustomResourceDefinition" &&
				upstreamCrds.has(String(metadata(document).name)),
		),
		`${mode} rendered upstream CRDs`,
	);
}

await helmRejects("managed");
await helmRejects("invalid");

// -----------------------------------------------------------------------------
// The teardown admission fence is Kobe's own policy and must ship with the
// enabled mode only.
// -----------------------------------------------------------------------------

invariant(
	!teardownFencePolicy(disabled),
	"disabled rendered the Sandbox teardown admission fence",
);

const policy = teardownFencePolicy(external);
invariant(policy, "external omitted the Sandbox teardown admission fence");
invariant(
	annotations(policy)["helm.sh/resource-policy"] === "keep",
	"external teardown fence policy is not retained across uninstall",
);
const policyName = String(metadata(policy).name);
const spec = policy.spec as Record<string, unknown>;
const constraints = spec.matchConstraints as Record<string, unknown>;
const rules = constraints.resourceRules as Record<string, unknown>[];
invariant(
	rules.some(
		(rule) =>
			Array.isArray(rule.apiGroups) &&
			rule.apiGroups.includes("agents.x-k8s.io") &&
			Array.isArray(rule.resources) &&
			rule.resources.includes("sandboxes"),
	),
	"external fence does not cover Sandbox CREATE",
);
invariant(
	rules.some(
		(rule) =>
			Array.isArray(rule.apiGroups) &&
			rule.apiGroups.includes("") &&
			Array.isArray(rule.resources) &&
			["pods", "services", "persistentvolumeclaims"].every((resource) =>
				rule.resources.includes(resource),
			),
	),
	"external fence does not cover every Sandbox descendant",
);
const validations = spec.validations as Record<string, unknown>[];
invariant(
	validations.some((validation) =>
		String(validation.expression).includes("string(owner.uid) in params.data"),
	),
	"external fence is not keyed by exact controller-owner UID",
);
const binding = objectNamed(
	external,
	"ValidatingAdmissionPolicyBinding",
	policyName,
);
invariant(binding, "external omitted the teardown-fence binding");
invariant(
	annotations(binding)["helm.sh/resource-policy"] === "keep",
	"external teardown fence binding is not retained across uninstall",
);
const bindingSpec = binding.spec as Record<string, unknown>;
const paramRef = bindingSpec.paramRef as Record<string, unknown>;
invariant(
	paramRef.namespace === undefined,
	"external fence is not scoped to each admitted object's namespace",
);
invariant(
	paramRef.parameterNotFoundAction === "Allow",
	"external fence would block steady-state creation without a parameter",
);
const selector = paramRef.selector as Record<string, unknown>;
const matchLabels = selector.matchLabels as Record<string, unknown>;
invariant(
	matchLabels["kobe.kunobi.ninja/sandbox-teardown-fence"] === "true",
	"external binding does not select exact teardown fences",
);

console.log("Agent Sandbox Helm modes and the pinned release fixture are valid");
