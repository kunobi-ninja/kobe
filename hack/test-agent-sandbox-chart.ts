#!/usr/bin/env bun

const chart = "charts/kobe";
const releaseFixture = "hack/fixtures/agent-sandbox-v1.0.0.yaml";
const releaseSha256 =
	"3a22f89ca1d1d6084e0a351797224842ee413641d6945f9e5b2cb5e1f6cf026c";
const taggedImage =
	"registry.k8s.io/agent-sandbox/agent-sandbox-controller:v1.0.0";
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
	extra: string[] = [],
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
			...extra,
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

function normalizeExpression(expression: string): string {
	return expression.split(/\s+/).filter(Boolean).join(" ");
}

function unchangedStatusFieldExpression(
	resource: string,
	field: string,
	username: string,
): string {
	return `request.resource.resource != '${resource}' || request.userInfo.username == ${JSON.stringify(username)} || request.operation == 'DELETE' || (oldObject == null ? (!has(object.status) || !has(object.status.${field})) : (((!has(oldObject.status) || !has(oldObject.status.${field})) && (!has(object.status) || !has(object.status.${field}))) || (has(oldObject.status) && has(oldObject.status.${field}) && has(object.status) && has(object.status.${field}) && object.status.${field} == oldObject.status.${field})))`;
}

function authorityCannotChangeStatusFieldExpression(
	resource: string,
	field: string,
	username: string,
): string {
	return `request.resource.resource != '${resource}' || request.userInfo.username != ${JSON.stringify(username)} || request.operation == 'DELETE' || (oldObject == null ? (!has(object.status) || !has(object.status.${field})) : (((!has(oldObject.status) || !has(oldObject.status.${field})) && (!has(object.status) || !has(object.status.${field}))) || (has(oldObject.status) && has(oldObject.status.${field}) && has(object.status) && has(object.status.${field}) && object.status.${field} == oldObject.status.${field})))`;
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
// upstream v1.0.0 asset; the digest pin happens where it is applied.
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
	"fixture WarmPool CRD lacks v1.0.0 status.observedGeneration",
);

for (const crd of fixtureCrds) {
	const spec = crd.spec as Record<string, unknown>;
	const versions = spec.versions as Array<Record<string, unknown>>;
	invariant(
		!versions.some(
			(version) => version.name === "v1alpha1" && version.served === true,
		),
		`${String(metadata(crd).name)} still serves v1alpha1`,
	);
	invariant(
		spec.conversion == null,
		`${String(metadata(crd).name)} still declares a conversion webhook`,
	);
}
invariant(
	!fixtureDocuments.some(
		(document) =>
			(document.kind === "Service" &&
				metadata(document).name === "agent-sandbox-webhook-service") ||
			(document.kind === "Secret" &&
				metadata(document).name === "agent-sandbox-webhook-certs"),
	),
	"fixture still ships conversion-webhook infrastructure",
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
// The split teardown authority is OPT-IN. Its required admission policies and
// RBAC are not shipped yet, so rendering it by default CrashLoops the pod and,
// because the operator would then declare KOBE_PROCESS_ROLE, also disables the
// in-process authority that works today.
const SPLIT = ["--set", "teardownAuthority.separate=true"];
const externalSplit = parseDocuments(
	await helm("external", "kobe", "kobe-system", SPLIT),
);
for (const [name, documents] of [
	["disabled", disabled],
	["external", external],
] as const) {
	invariant(
		!objectNamed(documents, "Deployment", "kobe-teardown-authority"),
		`${name} rendered the opt-in split authority by default`,
	);
	invariant(
		!objectNamed(documents, "ServiceAccount", "kobe-teardown-authority"),
		`${name} rendered the authority ServiceAccount without its namespace`,
	);
}

// The proof process is structurally separate even when Agent Sandbox itself is
// disabled. Admission/RBAC complete this boundary; these checks pin the pod,
// namespace and identity contract that those controls refer to.
const authority = objectNamed(
	externalSplit,
	"Deployment",
	"kobe-teardown-authority",
);
invariant(authority, "the split authority did not render when enabled");
const authorityNamespace = String(metadata(authority).namespace ?? "");
invariant(
	authorityNamespace !== "" && authorityNamespace !== "kobe-system",
	"teardown authority shares the general operator namespace",
);
invariant(
	objectNamed(externalSplit, "Namespace", authorityNamespace),
	"chart omitted the dedicated teardown-authority Namespace",
);
const authorityServiceAccount = objectNamed(
	externalSplit,
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

const authorityPolicy = objectNamed(
	externalSplit,
	"ValidatingAdmissionPolicy",
	authorityPolicyName,
);
invariant(authorityPolicy, "split authority omitted its field-protection policy");
const authorityPolicySpec = authorityPolicy.spec as Record<string, unknown>;
invariant(
	authorityPolicySpec.failurePolicy === "Fail",
	"authority field-protection policy is not fail-closed",
);
const authorityPolicyRules = (
	authorityPolicySpec.matchConstraints as Record<string, unknown>
).resourceRules as Record<string, unknown>[];
invariant(
	authorityPolicyRules.some(
		(rule) =>
			Array.isArray(rule.apiGroups) &&
			rule.apiGroups.length === 1 &&
			rule.apiGroups[0] === "kobe.kunobi.ninja" &&
			Array.isArray(rule.apiVersions) &&
			rule.apiVersions.length === 1 &&
			rule.apiVersions[0] === "v1alpha1" &&
			Array.isArray(rule.operations) &&
			["CREATE", "UPDATE", "DELETE"].every((operation) =>
				rule.operations.includes(operation),
			) &&
			Array.isArray(rule.resources) &&
			[
				"verifiedteardownevidence",
				"clusterleases",
				"clusterleases/status",
				"clusterinstances",
				"clusterinstances/status",
			].every((resource) => rule.resources.includes(resource)),
	),
	"authority policy does not cover every proof-bearing resource and operation",
);
const authorityExpressions = (
	authorityPolicySpec.validations as Record<string, unknown>[]
).map((validation) => normalizeExpression(String(validation.expression)));
const quotedAuthority = JSON.stringify(authorityUsername);
const expectedAuthorityExpressions = [
	`request.resource.resource != 'verifiedteardownevidence' || request.userInfo.username == ${quotedAuthority}`,
	`request.userInfo.username != ${quotedAuthority} || !(request.resource.resource in ['clusterleases', 'clusterinstances']) || request.subResource == 'status'`,
	...["teardownReceipt", "teardownEvidence", "teardownAttemptId", "unboundReleaseVerifiedAt", "teardownAcknowledgement"].map(
		(field) => unchangedStatusFieldExpression("clusterleases", field, authorityUsername),
	),
	...["creationManifest", "teardownIdentities"].map((field) =>
		unchangedStatusFieldExpression("clusterinstances", field, authorityUsername),
	),
	...["binding", "clusterName", "phase", "connectTokenCreation"].map((field) =>
		authorityCannotChangeStatusFieldExpression("clusterleases", field, authorityUsername),
	),
	...["binding", "leaseRef", "phase"].map((field) =>
		authorityCannotChangeStatusFieldExpression("clusterinstances", field, authorityUsername),
	),
	"request.resource.resource != 'clusterleases' || request.operation == 'DELETE' || !has(object.status) || !has(object.status.connectTokenCreation) || object.status.connectTokenCreation.phase == 'closed' || (has(object.status.binding) && (has(object.status.connectTokenCreation.identity) == has(object.status.binding.connectToken)) && (!has(object.status.connectTokenCreation.identity) || object.status.connectTokenCreation.identity.apiVersion == object.status.binding.connectToken.apiVersion && object.status.connectTokenCreation.identity.kind == object.status.binding.connectToken.kind && object.status.connectTokenCreation.identity.name == object.status.binding.connectToken.name && object.status.connectTokenCreation.identity.uid == object.status.binding.connectToken.uid && (has(object.status.connectTokenCreation.identity.namespace) == has(object.status.binding.connectToken.namespace)) && (!has(object.status.connectTokenCreation.identity.namespace) || object.status.connectTokenCreation.identity.namespace == object.status.binding.connectToken.namespace)))",
	`request.resource.resource != 'clusterleases' || request.userInfo.username == ${quotedAuthority} || request.operation == 'DELETE' || ((oldObject == null || !has(oldObject.status) || !has(oldObject.status.conditions) ? [] : oldObject.status.conditions.filter(c, c.type == 'AllocationAbsent')) == (!has(object.status) || !has(object.status.conditions) ? [] : object.status.conditions.filter(c, c.type == 'AllocationAbsent')))`,
	"request.resource.resource != 'clusterleases' || request.operation != 'UPDATE' || !has(oldObject.metadata.finalizers) || !oldObject.metadata.finalizers.exists(f, f == 'kobe.kunobi.ninja/teardown-receipt-retention') || (has(object.metadata.finalizers) && object.metadata.finalizers.exists(f, f == 'kobe.kunobi.ninja/teardown-receipt-retention')) || (has(oldObject.status) && has(oldObject.status.teardownAcknowledgement) && has(object.status) && has(object.status.teardownAcknowledgement) && object.status.teardownAcknowledgement == oldObject.status.teardownAcknowledgement)",
].map(normalizeExpression);
for (const expected of expectedAuthorityExpressions) {
	invariant(
		authorityExpressions.includes(expected),
		`authority policy is missing the exact expression: ${expected}`,
	);
}
invariant(
	authorityExpressions.length === expectedAuthorityExpressions.length,
	"authority policy contains unvalidated extra expressions",
);
const authorityPolicyBinding = objectNamed(
	externalSplit,
	"ValidatingAdmissionPolicyBinding",
	authorityPolicyName,
);
invariant(
	authorityPolicyBinding &&
		(authorityPolicyBinding.spec as Record<string, unknown>).policyName ===
			authorityPolicyName &&
		JSON.stringify(
			(authorityPolicyBinding.spec as Record<string, unknown>).validationActions,
		) === JSON.stringify(["Deny"]),
	"authority policy binding is missing or not Deny-only",
);

const firewallPolicy = objectNamed(
	externalSplit,
	"ValidatingAdmissionPolicy",
	firewallPolicyName,
);
invariant(firewallPolicy, "split authority omitted its identity firewall");
const firewallSpec = firewallPolicy.spec as Record<string, unknown>;
invariant(
	firewallSpec.failurePolicy === "Fail",
	"authority identity firewall is not fail-closed",
);
const firewallExpressions = (
	firewallSpec.validations as Record<string, unknown>[]
).map((validation) => normalizeExpression(String(validation.expression)));
const quotedControlPlane = JSON.stringify(controlPlaneUsername);
const quotedAuthorityNamespace = JSON.stringify(authorityNamespace);
const expectedFirewallExpressions = [
	`request.userInfo.username != ${quotedControlPlane} || request.resource.resource in ['namespaces', 'clusterroles', 'clusterrolebindings'] || request.namespace != ${quotedAuthorityNamespace}`,
	`request.userInfo.username != ${quotedControlPlane} || request.resource.resource != 'namespaces' || request.name != ${quotedAuthorityNamespace}`,
	`request.userInfo.username != ${quotedControlPlane} || request.resource.group != 'rbac.authorization.k8s.io' || !(request.resource.resource in ['clusterroles', 'clusterrolebindings'])`,
].map(normalizeExpression);
invariant(
	JSON.stringify(firewallExpressions) ===
		JSON.stringify(expectedFirewallExpressions),
	"identity firewall expressions drifted from the startup contract",
);
const firewallBinding = objectNamed(
	externalSplit,
	"ValidatingAdmissionPolicyBinding",
	firewallPolicyName,
);
invariant(
	firewallBinding &&
		(firewallBinding.spec as Record<string, unknown>).policyName ===
			firewallPolicyName &&
		JSON.stringify(
			(firewallBinding.spec as Record<string, unknown>).validationActions,
		) === JSON.stringify(["Deny"]),
	"identity firewall binding is missing or not Deny-only",
);

const authorityRole = objectNamed(
	externalSplit,
	"ClusterRole",
	"kobe-teardown-authority",
);
invariant(authorityRole, "split authority omitted its dedicated ClusterRole");
const authorityRules = authorityRole.rules as Record<string, unknown>[];
const authorityRuleAllows = (resource: string, verbs: string[]): boolean =>
	authorityRules.some(
		(rule) =>
			Array.isArray(rule.resources) &&
			rule.resources.includes(resource) &&
			Array.isArray(rule.verbs) &&
			verbs.every((verb) => rule.verbs.includes(verb)),
	);
for (const [resource, verbs] of [
	["clusterinstances", ["get", "list", "watch"]],
	["clusterinstances/status", ["get", "patch", "update"]],
	["clusterleases", ["get", "list", "watch"]],
	["clusterleases/status", ["get", "patch", "update"]],
	["sandboxleases", ["get", "list", "watch"]],
	["verifiedteardownevidence", ["get", "list", "watch", "create"]],
	["validatingadmissionpolicies", ["get"]],
	["validatingadmissionpolicybindings", ["get"]],
	["selfsubjectreviews", ["create"]],
] as const) {
	invariant(
		authorityRuleAllows(resource, [...verbs]),
		`teardown authority lacks ${verbs.join("/")} on ${resource}`,
	);
}
const authorityRoleBinding = objectNamed(
	externalSplit,
	"ClusterRoleBinding",
	"kobe-teardown-authority",
);
invariant(
	authorityRoleBinding &&
		(authorityRoleBinding.roleRef as Record<string, unknown>).name ===
			"kobe-teardown-authority" &&
		(authorityRoleBinding.subjects as Record<string, unknown>[]).some(
			(subject) =>
				subject.name === "kobe-teardown-authority" &&
				subject.namespace === authorityNamespace,
		),
	"authority ClusterRole is not bound only to its dedicated identity",
);
const authorityLeaderRole = objectNamed(
	externalSplit,
	"Role",
	"kobe-teardown-authority-leader-election",
);
const authorityLeaderBinding = objectNamed(
	externalSplit,
	"RoleBinding",
	"kobe-teardown-authority-leader-election",
);
invariant(
	authorityLeaderRole &&
		metadata(authorityLeaderRole).namespace === authorityNamespace &&
	authorityLeaderBinding &&
		metadata(authorityLeaderBinding).namespace === authorityNamespace,
	"authority leader election is not isolated in its dedicated namespace",
);

for (const [mode, documents] of [["external", externalSplit]] as const) {
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

const otherNamespace = parseDocuments(
	await helm("external", "kobe", "other-system", SPLIT),
);
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
// Declaring the role is what DISABLES the in-process authority, so by default
// it must be absent - otherwise the chart turns off a working teardown path in
// favour of one it does not deploy - and it must appear only alongside the
// split authority that takes over.
invariant(
	controlPlaneEnv.get("KOBE_PROCESS_ROLE") === undefined,
	"default render declared the control-plane role without a split authority",
);
const splitOperator = objectNamed(externalSplit, "Deployment", "kobe");
invariant(splitOperator, "split render omitted the control-plane Deployment");
const splitEnv = new Map(
	(
		(
			(
				(
					(splitOperator.spec as Record<string, unknown>).template as Record<
						string,
						unknown
					>
				).spec as Record<string, unknown>
			).containers as Record<string, unknown>[]
		)[0].env as Record<string, unknown>[]
	).map((entry) => [String(entry.name), entry.value]),
);
invariant(
	splitEnv.get("KOBE_PROCESS_ROLE") === "control-plane",
	"split render did not hand the operator the lifecycle-only role",
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
		!objectNamed(documents, "BootstrapConfig", "agent-sandbox-v1-0-0"),
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
