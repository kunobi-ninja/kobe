// Real API-server gate for the optional split teardown authority.
//
// The Helm harness pins the rendered object shape and exact CEL strings. This
// test installs those rendered policies and RBAC into a disposable Kind
// cluster, waits for Kubernetes to finish type-checking them, then proves the
// two identities cannot cross the proof/lifecycle boundary.

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

/// The kind a validation is written for, read from its own resource guard.
///
/// Every expression opens by excluding the resources it does not apply to, so
/// the guard names the one type whose fields it then reads.
function guardedKind(expression: string): string | undefined {
	if (expression.includes("!= 'verifiedteardownevidence'")) return "VerifiedTeardownEvidence";
	if (expression.includes("!= 'clusterleases'")) return "ClusterLease";
	if (expression.includes("!= 'clusterinstances'")) return "ClusterInstance";
	return undefined;
}

/// Fail on type errors against the kind an expression targets, and only that
/// kind.
///
/// The API server checks every expression against every type the policy
/// matches, so one policy spanning ClusterLease, ClusterInstance and
/// VerifiedTeardownEvidence always reports a field guard as an error on the
/// two types that do not carry that field. Those reports are noise: the
/// expression's own `request.resource.resource` guard already excluded them at
/// admission time.
///
/// An error against the targeted kind is the opposite — a misspelled or
/// removed field that would make the guard silently vacuous — so it still
/// fails the gate.
function offTargetWarnings(warnings: unknown, expressions: string[]): string[] {
	if (!Array.isArray(warnings)) return [];
	const fatal: string[] = [];
	for (const warning of warnings as Record<string, unknown>[]) {
		const index = Number(/\[(\d+)\]/.exec(String(warning.fieldRef))?.[1] ?? -1);
		const kind = guardedKind(expressions[index] ?? "");
		if (kind === undefined) {
			fatal.push(`${warning.fieldRef}: no resource guard to check against`);
			continue;
		}
		// Warnings arrive as one text block per kind, each headed by the type.
		const blocks = String(warning.warning).split(/(?=kobe\.kunobi\.ninja\/v1alpha1, Kind=)/);
		const targeted = blocks.find((block) => block.includes(`Kind=${kind}:`));
		if (targeted && /ERROR:/.test(targeted)) {
			fatal.push(`${warning.fieldRef} does not type-check against ${kind}: ${targeted}`);
		}
	}
	return fatal;
}

/// Wait until the RBAC authorizer itself grants the identity.
///
/// The single `kubectl apply` below installs the admission policies AND
/// `rbac.yaml` — the bindings both usernames patch status through. Only the
/// policies were waited for, and policy type-checking is done by a different
/// controller than the authorizer's cache refresh: the two are independent and
/// unordered.
///
/// That matters because authorization runs BEFORE validating admission. Inside
/// the propagation window the first status patch fails with `is forbidden`
/// rather than succeeding, and the forged-write assertion sees an RBAC 403
/// instead of the policy's message — so a binding that had not propagated
/// reads as the policy being wrong.
///
/// `auth can-i` is a SubjectAccessReview evaluated by the same authorizer the
/// real request will meet, so this is the condition itself rather than a proxy.
async function waitForAuthorizedIdentity(username: string): Promise<void> {
	const deadline = Date.now() + 60_000;
	let lastObservation = "authorizer never answered";
	while (Date.now() < deadline) {
		const result = await kubectl(
			[
				"auth",
				"can-i",
				"patch",
				"clusterleases.kobe.kunobi.ninja",
				"--subresource=status",
				`--as=${username}`,
				"-n",
				namespace,
			],
			{ allowFailure: true },
		);
		if (result.stdout.trim() === "yes") {
			return;
		}
		// Never leave this empty: an empty diagnostic is what made the original
		// failure take an hour to read.
		lastObservation =
			result.stdout.trim() ||
			result.stderr.trim() ||
			"no output, exit " + String(result.exitCode);
		await Bun.sleep(500);
	}
	throw new Error(
		`RBAC did not grant ${username} status patch within 60s: ${lastObservation}`,
	);
}

/// Wait until the policy actually rejects a write, not merely until it parses.
///
/// `waitForTypeCheckedPolicy` proves the API server has type-checked the
/// policy, which its own comment notes is not the same as the binding being
/// live on the admission path. Between those two moments a forged write still
/// succeeds, and every assertion below reads that as the control plane having
/// forged a teardown proof.
///
/// That window is not theoretical: this job passed at 15:30 UTC and failed at
/// 03:12 UTC on the identical commit, reporting an empty message because the
/// forged patch had returned success and therefore written nothing to stderr.
///
/// Probing with a write the policy must reject is the only signal the API
/// server offers, and it is the same evidence the assertions themselves rely
/// on.
async function waitForEnforcingPolicy(
	username: string,
	probe: () => Promise<CommandResult>,
	expected: string,
): Promise<void> {
	const deadline = Date.now() + 60_000;
	let lastObservation = "policy never rejected the probe write";
	while (Date.now() < deadline) {
		const result = await probe();
		if (result.exitCode !== 0 && result.stderr.includes(expected)) {
			return;
		}
		lastObservation =
			result.exitCode === 0
				? "probe write was ADMITTED (policy not yet enforcing)"
				: `probe rejected for another reason: ${result.stderr.trim()}`;
		await Bun.sleep(500);
	}
	throw new Error(
		`admission policy did not become enforcing for ${username}: ${lastObservation}`,
	);
}

/// Wait for the API server's documented type-check completion signals.
///
/// ValidatingAdmissionPolicy does not promise an `Accepted=True` condition.
/// The admission mutations below are the authoritative proof that the policy
/// is active after its current generation has been type-checked.
async function waitForTypeCheckedPolicy(name: string): Promise<void> {
	const deadline = Date.now() + 60_000;
	let lastObservation = "policy was not returned by the API server";
	while (Date.now() < deadline) {
		const result = await kubectl(
			["get", "validatingadmissionpolicy", name, "-o", "json"],
			{ allowFailure: true },
		);
		if (result.exitCode === 0) {
			const policy = JSON.parse(result.stdout);
			lastObservation = JSON.stringify({
				generation: policy.metadata?.generation,
				status: policy.status,
			});
			if (
				policy.status?.observedGeneration === policy.metadata?.generation &&
				policy.status?.typeChecking !== undefined
			) {
				const warnings = policy.status.typeChecking.expressionWarnings;
				const fatal = offTargetWarnings(warnings, policyExpressions(policy));
				if (fatal.length > 0) {
					throw new Error(`${name} type-check warnings: ${JSON.stringify(fatal)}`);
				}
				return;
			}
		} else {
			lastObservation = result.stderr.trim() || result.stdout.trim();
		}
		await Bun.sleep(500);
	}
	throw new Error(
		`${name} did not report completed type checking: ${lastObservation}`,
	);
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
		waitForTypeCheckedPolicy(authorityPolicyName),
		waitForTypeCheckedPolicy(firewallPolicyName),
		// The same apply installed rbac.yaml. Authorization runs before
		// validating admission, so an unpropagated binding fails the first
		// patch outright and makes the forged-write assertion read an RBAC 403
		// as the policy misbehaving.
		waitForAuthorizedIdentity(controlPlaneUsername),
		waitForAuthorizedIdentity(authorityUsername),
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

	// Type-checked is not enforcing. Prove the binding is live on the admission
	// path before reading a successful write as a forged proof.
	await waitForEnforcingPolicy(
		controlPlaneUsername,
		() =>
			patchLeaseStatus(
				controlPlaneUsername,
				{ phase: "Pending", teardownAttemptId: "enforcement-probe" },
				true,
			),
		"only the teardown authority may change status.teardownAttemptId",
	);

	const forged = await patchLeaseStatus(
		controlPlaneUsername,
		{ phase: "Pending", teardownAttemptId: "forged-attempt" },
		true,
	);
	assert(
		forged.exitCode !== 0 &&
			forged.stderr.includes("only the teardown authority may change status.teardownAttemptId"),
		forged.exitCode === 0
			? "control plane FORGED a teardown proof: the patch was admitted"
			: "control plane patch was rejected for the wrong reason: " +
				(forged.stderr.trim() || "<no stderr>"),
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
