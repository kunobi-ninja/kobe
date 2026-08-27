// Real API-server gate for the optional split teardown authority.
//
// The Helm harness pins the rendered object shape and exact CEL strings. This
// test installs those rendered policies and RBAC into a disposable Kind
// cluster, waits for Kubernetes to accept/type-check them, then proves the two
// identities cannot cross the proof/lifecycle boundary.

const context = Bun.env.KOBE_SANDBOX_APISERVER_CONTEXT ?? Bun.argv[2];
if (!context) {
	throw new Error(
		"set KOBE_SANDBOX_APISERVER_CONTEXT or pass a kubectl context as argv[2]",
	);
}

const release = "authority-contract";
const namespace = `kobe-authority-contract-${Date.now().toString(36)}`;
const leaseName = "proof-boundary";

type CommandResult = { stdout: string; stderr: string; exitCode: number };
type Document = Record<string, unknown>;

function assert(condition: unknown, message: string): asserts condition {
	if (!condition) throw new Error(message);
}

function metadata(document: Document): Record<string, unknown> {
	return (document.metadata ?? {}) as Record<string, unknown>;
}

function parseDocuments(yaml: string): Document[] {
	return yaml
		.split(/^---\s*$/m)
		.map((document) => document.trim())
		.filter(Boolean)
		.map((document) => Bun.YAML.parse(document) as Document)
		.filter((document) => document && typeof document === "object" && "kind" in document);
}

async function runCommand(
	cmd: string[],
	options?: { allowFailure?: boolean; stdin?: string },
): Promise<CommandResult> {
	const proc = Bun.spawn({
		cmd,
		cwd: process.cwd(),
		stdin: options?.stdin === undefined ? "ignore" : new Blob([options.stdin]),
		stdout: "pipe",
		stderr: "pipe",
	});
	const [stdout, stderr, exitCode] = await Promise.all([
		new Response(proc.stdout).text(),
		new Response(proc.stderr).text(),
		proc.exited,
	]);
	if (exitCode !== 0 && !options?.allowFailure) {
		throw new Error([stdout.trim(), stderr.trim()].filter(Boolean).join("\n"));
	}
	return { stdout, stderr, exitCode };
}

async function kubectl(
	args: string[],
	options?: { allowFailure?: boolean; stdin?: string },
): Promise<CommandResult> {
	return runCommand(["kubectl", "--context", context, ...args], options);
}

async function kubectlAs(
	username: string,
	args: string[],
	allowFailure = false,
): Promise<CommandResult> {
	return kubectl([`--as=${username}`, ...args], { allowFailure });
}

function policyRuleResources(policy: Document): string[] {
	const spec = policy.spec as Record<string, unknown>;
	const constraints = spec.matchConstraints as Record<string, unknown>;
	return (constraints.resourceRules as Record<string, unknown>[]).flatMap((rule) =>
		Array.isArray(rule.resources) ? rule.resources.map(String) : [],
	);
}

function policyExpressions(policy: Document): string[] {
	return ((policy.spec as Record<string, unknown>).validations as Record<string, unknown>[])
		.map((validation) => String(validation.expression));
}

async function waitForAcceptedPolicy(name: string): Promise<void> {
	const deadline = Date.now() + 60_000;
	while (Date.now() < deadline) {
		const result = await kubectl(
			["get", "validatingadmissionpolicy", name, "-o", "json"],
			{ allowFailure: true },
		);
		if (result.exitCode === 0) {
			const policy = JSON.parse(result.stdout);
			const warnings = policy.status?.typeChecking?.expressionWarnings;
			if (Array.isArray(warnings) && warnings.length > 0) {
				throw new Error(`${name} type-check warnings: ${JSON.stringify(warnings)}`);
			}
			const accepted = policy.status?.conditions?.some(
				(condition: Record<string, unknown>) =>
					condition.type === "Accepted" && condition.status === "True",
			);
			if (
				policy.status?.observedGeneration === policy.metadata?.generation &&
				accepted &&
				policy.status?.typeChecking !== undefined
			) {
				return;
			}
		}
		await Bun.sleep(500);
	}
	throw new Error(`${name} did not become accepted and type-checked`);
}

async function patchLeaseStatus(
	username: string,
	status: Record<string, unknown>,
	allowFailure = false,
): Promise<CommandResult> {
	return kubectlAs(
		username,
		[
			"patch",
			"clusterlease",
			leaseName,
			"-n",
			namespace,
			"--subresource=status",
			"--type=merge",
			"-p",
			JSON.stringify({ status }),
		],
		allowFailure,
	);
}

const rendered = await runCommand([
	"helm",
	"template",
	release,
	"charts/kobe",
	"--namespace",
	namespace,
	"--set",
	"teardownAuthority.separate=true",
	"--set",
	`operatorNamespace=${namespace}`,
	"--show-only",
	"templates/rbac.yaml",
	"--show-only",
	"templates/teardown-authority-policy.yaml",
]);
const documents = parseDocuments(rendered.stdout);
const policies = documents.filter(
	(document) => document.kind === "ValidatingAdmissionPolicy",
);
assert(policies.length === 2, `rendered ${policies.length} authority policies, expected 2`);
const authorityPolicy = policies.find((policy) =>
	policyRuleResources(policy).includes("verifiedteardownevidence"),
);
const firewallPolicy = policies.find((policy) => policy !== authorityPolicy);
assert(authorityPolicy && firewallPolicy, "could not identify the rendered policy pair");
const authorityPolicyName = String(metadata(authorityPolicy).name);
const firewallPolicyName = String(metadata(firewallPolicy).name);
const authorityUsername = policyExpressions(authorityPolicy)
	.join(" ")
	.match(/system:serviceaccount:[a-z0-9-]+:[a-z0-9-]+/)?.[0];
const controlPlaneUsername = policyExpressions(firewallPolicy)
	.join(" ")
	.match(/system:serviceaccount:[a-z0-9-]+:[a-z0-9-]+/)?.[0];
assert(authorityUsername, "rendered policy does not contain the authority identity");
assert(controlPlaneUsername, "rendered firewall does not contain the control-plane identity");
const authorityNamespace = authorityUsername.split(":")[2];

await kubectl(["create", "namespace", namespace]);
await kubectl(["create", "namespace", authorityNamespace]);
try {
	await kubectl(["apply", "-f", "-"], { stdin: rendered.stdout });
	await Promise.all([
		waitForAcceptedPolicy(authorityPolicyName),
		waitForAcceptedPolicy(firewallPolicyName),
	]);

	const lease = JSON.stringify({
		apiVersion: "kobe.kunobi.ninja/v1alpha1",
		kind: "ClusterLease",
		metadata: { name: leaseName, namespace },
		spec: {
			poolRef: "test-pool",
			ttl: "1h",
			requester: { type: "contract:test", identity: "authority-boundary" },
			cleanupMode: "VerifiedDestroy",
		},
	});
	await kubectl(["create", "-f", "-"], { stdin: lease });

	await patchLeaseStatus(controlPlaneUsername, { phase: "Pending" });
	const forged = await patchLeaseStatus(
		controlPlaneUsername,
		{ phase: "Pending", teardownAttemptId: "forged-attempt" },
		true,
	);
	assert(
		forged.exitCode !== 0 &&
			forged.stderr.includes("only the teardown authority may change status.teardownAttemptId"),
		`control plane forged teardown proof or failed unexpectedly: ${forged.stderr}`,
	);

	await patchLeaseStatus(authorityUsername, {
		phase: "Pending",
		teardownAttemptId: "authority-attempt",
	});
	const lifecycle = await patchLeaseStatus(
		authorityUsername,
		{ phase: "Released", teardownAttemptId: "authority-attempt" },
		true,
	);
	assert(
		lifecycle.exitCode !== 0 &&
			lifecycle.stderr.includes("teardown authority may not change lifecycle phase"),
		`authority changed lifecycle state or failed unexpectedly: ${lifecycle.stderr}`,
	);

	const erased = await patchLeaseStatus(
		controlPlaneUsername,
		{ phase: "Pending", teardownAttemptId: null },
		true,
	);
	assert(erased.exitCode !== 0, "control plane erased authority-owned evidence");
	const live = JSON.parse(
		(
			await kubectl([
				"get",
				"clusterlease",
				leaseName,
				"-n",
				namespace,
				"-o",
				"json",
			])
		).stdout,
	);
	assert(
		live.status?.teardownAttemptId === "authority-attempt" &&
			live.status?.phase === "Pending",
		"a rejected cross-boundary write changed live status",
	);

	const namespaceMutation = await kubectlAs(
		controlPlaneUsername,
		["create", "configmap", "forged-authority", "-n", authorityNamespace],
		true,
	);
	assert(
		namespaceMutation.exitCode !== 0 &&
			namespaceMutation.stderr.includes(
				"control plane may not mutate the teardown-authority namespace",
			),
		`control plane crossed the authority namespace firewall: ${namespaceMutation.stderr}`,
	);
	const rbacMutation = await kubectlAs(
		controlPlaneUsername,
		["create", "clusterrole", "forged-authority", "--verb=get", "--resource=pods"],
		true,
	);
	assert(
		rbacMutation.exitCode !== 0 &&
			rbacMutation.stderr.includes(
				"control plane may not replace cluster-scoped authority RBAC",
			),
		`control plane crossed the cluster-RBAC firewall: ${rbacMutation.stderr}`,
	);

	console.log("Split teardown authority API-server contract passed");
} finally {
	await kubectl(["delete", "-f", "-", "--ignore-not-found"], {
		stdin: rendered.stdout,
		allowFailure: true,
	});
	for (const target of [authorityNamespace, namespace]) {
		await kubectl(
			["delete", "namespace", target, "--ignore-not-found", "--wait=true", "--timeout=60s"],
			{ allowFailure: true },
		);
	}
}
