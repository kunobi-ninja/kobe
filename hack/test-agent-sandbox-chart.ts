#!/usr/bin/env bun

const chart = "charts/kobe";
const releaseAsset = `${chart}/files/agent-sandbox-v0.5.4.yaml`;
const releaseSha256 =
	"7ada631db5d5a2cc043f48ca05cec94db54bc0afa4756b3b610c920b188fe2c4";
const bootstrapSha256 =
	"f5f6cd88a52ad76e2f18eac0a7a4ee620a77c3e02186abe48e8aa6f29155d8fa";
const pinnedImage =
	"registry.k8s.io/agent-sandbox/agent-sandbox-controller@sha256:be477ba317d84a13a38d7605e925e7b4aa82de5b313a4274358920310a931b7f";
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

async function helm(mode: string): Promise<string> {
	const process = Bun.spawn(
		[
			"helm",
			"template",
			"kobe",
			chart,
			"--namespace",
			"kobe-system",
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
	invariant(exitCode === 0, `helm template ${mode} failed: ${stderr}`);
	return stdout;
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

function collectImages(value: unknown, images: string[] = []): string[] {
	if (Array.isArray(value)) {
		for (const item of value) collectImages(item, images);
	} else if (value && typeof value === "object") {
		for (const [key, item] of Object.entries(value)) {
			if (key === "image" && typeof item === "string") images.push(item);
			collectImages(item, images);
		}
	}
	return images;
}

const source = await Bun.file(releaseAsset).bytes();
invariant(
	sha256(source) === releaseSha256,
	"vendored release asset digest drifted",
);

const [disabledYaml, managedYaml, externalYaml] = await Promise.all([
	helm("disabled"),
	helm("managed"),
	helm("external"),
]);
const disabled = parseDocuments(disabledYaml);
const managed = parseDocuments(managedYaml);
const external = parseDocuments(externalYaml);

invariant(
	!teardownFencePolicy(disabled),
	"disabled rendered the Sandbox teardown admission fence",
);
for (const [mode, documents] of [
	["managed", managed],
	["external", external],
] as const) {
	const policy = teardownFencePolicy(documents);
	invariant(policy, `${mode} omitted the Sandbox teardown admission fence`);
	invariant(
		annotations(policy)["helm.sh/resource-policy"] === "keep",
		`${mode} teardown fence policy is not retained across uninstall`,
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
		`${mode} fence does not cover Sandbox CREATE`,
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
		`${mode} fence does not cover every Sandbox descendant`,
	);
	const validations = spec.validations as Record<string, unknown>[];
	invariant(
		validations.some((validation) =>
			String(validation.expression).includes(
				"string(owner.uid) in params.data",
			),
		),
		`${mode} fence is not keyed by exact controller-owner UID`,
	);
	const binding = objectNamed(
		documents,
		"ValidatingAdmissionPolicyBinding",
		policyName,
	);
	invariant(binding, `${mode} omitted the teardown-fence binding`);
	invariant(
		annotations(binding)["helm.sh/resource-policy"] === "keep",
		`${mode} teardown fence binding is not retained across uninstall`,
	);
	const bindingSpec = binding.spec as Record<string, unknown>;
	const paramRef = bindingSpec.paramRef as Record<string, unknown>;
	invariant(
		paramRef.namespace === undefined,
		`${mode} fence is not scoped to each admitted object's namespace`,
	);
	invariant(
		paramRef.parameterNotFoundAction === "Allow",
		`${mode} fence would block steady-state creation without a parameter`,
	);
	const selector = paramRef.selector as Record<string, unknown>;
	const matchLabels = selector.matchLabels as Record<string, unknown>;
	invariant(
		matchLabels["kobe.kunobi.ninja/sandbox-teardown-fence"] === "true",
		`${mode} binding does not select exact teardown fences`,
	);
}

for (const [mode, documents] of [
	["disabled", disabled],
	["external", external],
] as const) {
	invariant(
		!objectNamed(documents, "Deployment", "agent-sandbox-controller"),
		`${mode} rendered the upstream controller`,
	);
	invariant(
		!objectNamed(documents, "BootstrapConfig", "agent-sandbox-v0-5-4"),
		`${mode} rendered the managed child bootstrap`,
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

const managedCrds = managed.filter(
	(document) =>
		document.kind === "CustomResourceDefinition" &&
		upstreamCrds.has(String(metadata(document).name)),
);
invariant(
	managedCrds.length === 4,
	`managed rendered ${managedCrds.length} upstream CRDs`,
);
for (const crd of managedCrds) {
	const annotations = (metadata(crd).annotations ?? {}) as Record<
		string,
		unknown
	>;
	invariant(
		annotations["helm.sh/resource-policy"] === "keep",
		"managed CRD is not retained",
	);
	invariant(
		annotations["kobe.kunobi.ninja/source-sha256"] === releaseSha256,
		"managed CRD lost release provenance",
	);
}

const controller = objectNamed(
	managed,
	"Deployment",
	"agent-sandbox-controller",
);
invariant(controller, "managed did not render the controller Deployment");
const images = collectImages(controller);
invariant(
	images.length === 1 && images[0] === pinnedImage,
	"controller image is not immutable",
);

const bootstrap = objectNamed(
	managed,
	"BootstrapConfig",
	"agent-sandbox-v0-5-4",
);
invariant(bootstrap, "managed did not render the child BootstrapConfig");
const bootstrapSpec = bootstrap.spec as Record<string, unknown>;
const files = bootstrapSpec.files as Record<string, unknown>;
const bootstrapManifest = files["agent-sandbox-v0.5.4.yaml"];
invariant(
	typeof bootstrapManifest === "string",
	"child bootstrap manifest is missing",
);
invariant(
	sha256(bootstrapManifest) === bootstrapSha256,
	"child bootstrap digest drifted",
);
invariant(
	bootstrapManifest.includes(pinnedImage),
	"child bootstrap does not use the pinned image",
);
invariant(
	!bootstrapManifest.includes(":v0.5.4"),
	"child bootstrap kept the mutable image tag",
);

invariant(
	!managed.some((document) =>
		`${String(document.kind)} ${String(metadata(document).name)}`
			.toLowerCase()
			.includes("router"),
	),
	"managed rendered an Agent Sandbox Router resource",
);

const invalid = Bun.spawn(
	["helm", "template", "kobe", chart, "--set", "agentSandbox.mode=invalid"],
	{ stdout: "ignore", stderr: "pipe" },
);
const invalidStderr = new Response(invalid.stderr).text();
invariant((await invalid.exited) !== 0, "invalid mode unexpectedly rendered");
invariant(
	(await invalidStderr).includes("agentSandbox") &&
		(await invalidStderr).includes("mode"),
	"invalid mode error is not actionable",
);

console.log("Agent Sandbox Helm modes and pinned artifacts are valid");
