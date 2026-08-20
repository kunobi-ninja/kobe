// Real Kubernetes API-server regression gate for SandboxLease status and the
// admission-ledger abuse boundary.
//
// Unit tests prove that Kobe builds UID/resourceVersion-fenced JSON Patches
// and emits the intended CEL. This test proves that a real API server enforces
// both contracts. It needs only the SandboxLease CRD and native admission/RBAC
// APIs, not Kobe or the external Agent Sandbox runtime.

const context = Bun.env.KOBE_SANDBOX_APISERVER_CONTEXT ?? Bun.argv[2];
if (!context) {
	throw new Error(
		"set KOBE_SANDBOX_APISERVER_CONTEXT or pass a kubectl context as argv[2]",
	);
}

const resource = "sandboxleases.kobe.kunobi.ninja";
const namespace = `kobe-sandbox-contract-${Date.now().toString(36)}`;
const ledgerNamespace = `${namespace}-ledger`;
const ledgerPolicy = `${namespace}-ledger`;
const operatorUsername = `system:serviceaccount:${namespace}:operator`;
const tenantUsername = `system:serviceaccount:${namespace}:tenant`;
const policyCanaryName = "kobe-ledger-policy-enforcement-canary";
const policyCanaryMessage =
	"Sandbox ledger admission-policy enforcement canary";
const quotaCanaryName = "kobe-ledger-quota-enforcement-canary";

type CommandResult = {
	stdout: string;
	stderr: string;
	exitCode: number;
};

type Lease = {
	metadata: {
		uid: string;
		resourceVersion: string;
	};
	status?: {
		phase?: string;
		releaseCause?: string;
	} | null;
};

type JsonPatchOperation = {
	op: "add" | "remove" | "replace" | "test";
	path: string;
	value?: unknown;
};

function assert(condition: unknown, message: string): asserts condition {
	if (!condition) throw new Error(message);
}

function info(message: string): void {
	console.log(`  - ${message}`);
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
		const detail = [stdout.trim(), stderr.trim()].filter(Boolean).join("\n");
		throw new Error(detail || `${cmd.join(" ")} exited ${exitCode}`);
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

function coordinationLease(name: string): string {
	return JSON.stringify({
		apiVersion: "coordination.k8s.io/v1",
		kind: "Lease",
		metadata: { name, namespace: ledgerNamespace },
		spec: {},
	});
}

function configMap(name: string): string {
	return JSON.stringify({
		apiVersion: "v1",
		kind: "ConfigMap",
		metadata: { name, namespace: ledgerNamespace },
	});
}

async function waitForAdmissionLedgerControls(): Promise<void> {
	const deadline = Date.now() + 60_000;
	while (Date.now() < deadline) {
		const policy = JSON.parse(
			(
				await kubectl([
					"get",
					"validatingadmissionpolicy",
					ledgerPolicy,
					"-o",
					"json",
				])
			).stdout,
		);
		const warnings = policy.status?.typeChecking?.expressionWarnings;
		if (Array.isArray(warnings) && warnings.length > 0) {
			throw new Error(
				`ledger policy type-check warnings: ${JSON.stringify(warnings)}`,
			);
		}
		const policyReady =
			policy.status?.observedGeneration === policy.metadata?.generation &&
			policy.status?.typeChecking !== undefined;

		const quota = JSON.parse(
			(
				await kubectl([
					"get",
					"resourcequota",
					ledgerPolicy,
					"-n",
					ledgerNamespace,
					"-o",
					"json",
				])
			).stdout,
		);
		const key = "count/leases.coordination.k8s.io";
		const canaryKey = "count/configmaps";
		const quotaReady =
			quota.status?.hard?.[key] === "2" &&
			quota.status?.hard?.[canaryKey] === "0" &&
			key in (quota.status?.used ?? {}) &&
			canaryKey in (quota.status?.used ?? {});
		if (policyReady && quotaReady) {
			const policyProbe = await runCommand(
				[
					"kubectl",
					"--context",
					context,
					`--as=${operatorUsername}`,
					"create",
					"-f",
					"-",
					"--validate=false",
					"--dry-run=server",
				],
				{ stdin: coordinationLease(policyCanaryName), allowFailure: true },
			);
			const quotaProbe = await runCommand(
				[
					"kubectl",
					"--context",
					context,
					`--as=${operatorUsername}`,
					"create",
					"-f",
					"-",
					"--validate=false",
					"--dry-run=server",
				],
				{ stdin: configMap(quotaCanaryName), allowFailure: true },
			);
			if (
				policyProbe.stderr.includes(policyCanaryMessage) &&
				quotaProbe.stderr.toLowerCase().includes("exceeded quota")
			) {
				return;
			}
		}
		await Bun.sleep(500);
	}
	throw new Error(
		"Sandbox admission policy and ResourceQuota did not become active",
	);
}

async function testAdmissionLedgerBoundary(): Promise<void> {
	const controls = `
apiVersion: v1
kind: Namespace
metadata:
  name: ${ledgerNamespace}
  labels:
    kobe.kunobi.ninja/sandbox-ledger: "true"
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: operator
  namespace: ${namespace}
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: tenant
  namespace: ${namespace}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ledger-test
  namespace: ${ledgerNamespace}
rules:
  - apiGroups: ["coordination.k8s.io"]
    resources: ["leases"]
    verbs: ["get", "list", "create", "update", "patch", "delete"]
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ledger-test
  namespace: ${ledgerNamespace}
subjects:
  - kind: ServiceAccount
    name: operator
    namespace: ${namespace}
  - kind: ServiceAccount
    name: tenant
    namespace: ${namespace}
roleRef:
  kind: Role
  name: ledger-test
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ${ledgerPolicy}
rules:
  - apiGroups: ["authentication.k8s.io"]
    resources: ["selfsubjectreviews"]
    verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ${ledgerPolicy}
subjects:
  - kind: ServiceAccount
    name: operator
    namespace: ${namespace}
roleRef:
  kind: ClusterRole
  name: ${ledgerPolicy}
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: ${ledgerPolicy}
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: ["coordination.k8s.io"]
        apiVersions: ["v1"]
        resources: ["leases"]
        operations: ["CREATE", "UPDATE", "DELETE"]
  matchConditions:
    - name: only-sandbox-ledger-namespace
      expression: 'request.namespace == "${ledgerNamespace}"'
  validations:
    - expression: 'request.userInfo.username == "${operatorUsername}"'
      message: only the operator may mutate the Sandbox ledger
      reason: Forbidden
    - expression: 'request.operation != "CREATE" || object.metadata.name != "${policyCanaryName}"'
      message: ${policyCanaryMessage}
      reason: Forbidden
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: ${ledgerPolicy}
spec:
  policyName: ${ledgerPolicy}
  validationActions: [Deny]
---
apiVersion: v1
kind: ResourceQuota
metadata:
  name: ${ledgerPolicy}
  namespace: ${ledgerNamespace}
spec:
  hard:
    count/leases.coordination.k8s.io: "2"
    count/configmaps: "0"
`;
	await kubectl(["apply", "-f", "-"], { stdin: controls });
	await waitForAdmissionLedgerControls();

	let result = await runCommand(
		[
			"kubectl",
			"--context",
			context,
			`--as=${operatorUsername}`,
			"create",
			"-f",
			"-",
			"--validate=false",
			"-o",
			"json",
		],
		{
			stdin: JSON.stringify({
				apiVersion: "authentication.k8s.io/v1",
				kind: "SelfSubjectReview",
				metadata: {},
			}),
		},
	);
	const review = JSON.parse(result.stdout);
	assert(
		review.status?.userInfo?.username === operatorUsername,
		`SelfSubjectReview returned ${review.status?.userInfo?.username ?? "<missing>"}`,
	);
	info("operator identity confirmed by SelfSubjectReview");

	// `kubectlAs` cannot carry stdin; use the generic runner for the mutating
	// requests so the impersonated identity and exact object body stay visible.
	const createAs = (username: string, name: string, allowFailure = false) =>
		runCommand(
			[
				"kubectl",
				"--context",
				context,
				`--as=${username}`,
				"create",
				"-f",
				"-",
				"--validate=false",
			],
			{ stdin: coordinationLease(name), allowFailure },
		);

	result = await createAs(tenantUsername, "tenant-injected", true);
	assert(result.exitCode !== 0, "tenant created a Sandbox ledger Lease");
	assert(
		result.stderr.includes("only the operator may mutate the Sandbox ledger"),
		`tenant CREATE failed for an unexpected reason: ${result.stderr}`,
	);
	info("tenant reservation CREATE denied by admission policy");

	await createAs(operatorUsername, "operator-slot-0");
	await createAs(operatorUsername, "operator-slot-1");
	info("operator reservation CREATE accepted");

	result = await runCommand(
		[
			"kubectl",
			"--context",
			context,
			`--as=${operatorUsername}`,
			"create",
			"-f",
			"-",
			"--validate=false",
			"--dry-run=server",
		],
		{ stdin: coordinationLease(policyCanaryName), allowFailure: true },
	);
	assert(result.exitCode !== 0, "admission-policy canary was accepted");
	assert(
		result.stderr.includes(policyCanaryMessage),
		`admission-policy canary failed for an unexpected reason: ${result.stderr}`,
	);
	info("ValidatingAdmissionPolicy enforcement proved by dry-run denial");

	result = await runCommand(
		[
			"kubectl",
			"--context",
			context,
			`--as=${operatorUsername}`,
			"create",
			"-f",
			"-",
			"--validate=false",
			"--dry-run=server",
		],
		{ stdin: configMap(quotaCanaryName), allowFailure: true },
	);
	assert(result.exitCode !== 0, "ResourceQuota canary was accepted");
	assert(
		result.stderr.toLowerCase().includes("exceeded quota"),
		`ResourceQuota canary failed for an unexpected reason: ${result.stderr}`,
	);
	info("ResourceQuota enforcement proved by dry-run denial");

	result = await kubectlAs(
		tenantUsername,
		[
			"annotate",
			"lease.coordination.k8s.io",
			"operator-slot-0",
			"attacker.example/mutated=true",
			"-n",
			ledgerNamespace,
			"--overwrite",
		],
		true,
	);
	assert(result.exitCode !== 0, "tenant mutated an operator reservation");
	assert(
		result.stderr.includes("only the operator may mutate the Sandbox ledger"),
		`tenant UPDATE failed for an unexpected reason: ${result.stderr}`,
	);
	info("tenant reservation UPDATE denied by admission policy");

	result = await createAs(operatorUsername, "operator-slot-2", true);
	assert(
		result.exitCode !== 0,
		"namespace Lease object quota accepted object 3",
	);
	assert(
		result.stderr.toLowerCase().includes("exceeded quota"),
		`third operator CREATE failed for an unexpected reason: ${result.stderr}`,
	);
	info("namespace-wide reservation object limit enforced");

	result = await kubectlAs(
		tenantUsername,
		[
			"delete",
			"lease.coordination.k8s.io",
			"operator-slot-0",
			"-n",
			ledgerNamespace,
		],
		true,
	);
	assert(result.exitCode !== 0, "tenant deleted an operator reservation");
	assert(
		result.stderr.includes("only the operator may mutate the Sandbox ledger"),
		`tenant DELETE failed for an unexpected reason: ${result.stderr}`,
	);
	await kubectl([
		"get",
		"lease.coordination.k8s.io",
		"operator-slot-0",
		"-n",
		ledgerNamespace,
	]);
	info("tenant reservation DELETE denied and object preserved");
}

function leaseManifest(name: string): string {
	return JSON.stringify({
		apiVersion: "kobe.kunobi.ninja/v1alpha1",
		kind: "SandboxLease",
		metadata: { name, namespace },
		spec: {
			poolRef: { name: "contract", uid: "pool-contract-uid", generation: 1 },
			ttl: "1m",
			requester: {
				provider: "contract",
				type: "oidc:user",
				issuer: "https://contract.invalid",
				identity: "contract",
			},
		},
	});
}

async function createLease(name: string): Promise<Lease> {
	await kubectl(["apply", "-f", "-"], { stdin: leaseManifest(name) });
	return getLease(name);
}

async function getLease(name: string): Promise<Lease> {
	const { stdout } = await kubectl([
		"get",
		resource,
		name,
		"-n",
		namespace,
		"-o",
		"json",
	]);
	return JSON.parse(stdout) as Lease;
}

async function patchStatus(
	name: string,
	uid: string,
	resourceVersion: string,
	operations: JsonPatchOperation[],
	allowFailure = false,
): Promise<CommandResult> {
	const patch: JsonPatchOperation[] = [
		{ op: "test", path: "/metadata/uid", value: uid },
		{ op: "test", path: "/metadata/resourceVersion", value: resourceVersion },
		...operations,
	];
	return kubectl(
		[
			"patch",
			resource,
			name,
			"-n",
			namespace,
			"--subresource=status",
			"--type=json",
			"-p",
			JSON.stringify(patch),
		],
		{ allowFailure },
	);
}

async function expectRejected(
	label: string,
	name: string,
	operations: JsonPatchOperation[],
): Promise<void> {
	const before = await getLease(name);
	const result = await patchStatus(
		name,
		before.metadata.uid,
		before.metadata.resourceVersion,
		operations,
		true,
	);
	assert(
		result.exitCode !== 0,
		`${label}: API server accepted the forbidden patch`,
	);
	const after = await getLease(name);
	assert(
		after.status?.releaseCause === "Requested",
		`${label}: rejected patch changed releaseCause to ${after.status?.releaseCause ?? "<absent>"}`,
	);
	assert(
		after.status?.phase === "Releasing",
		`${label}: rejected patch changed phase`,
	);
	info(`${label} rejected`);
}

async function testReleaseCauseCel(): Promise<void> {
	const name = "release-cause";
	let lease = await createLease(name);
	assert(
		lease.status?.releaseCause === undefined,
		"new lease unexpectedly has releaseCause",
	);

	await patchStatus(name, lease.metadata.uid, lease.metadata.resourceVersion, [
		{
			op: "add",
			path: "/status",
			value: { phase: "Releasing", releaseCause: "Requested", conditions: [] },
		},
	]);
	lease = await getLease(name);
	assert(
		lease.status?.releaseCause === "Requested",
		"absent -> Requested was not persisted",
	);
	info("releaseCause absent -> Requested accepted");

	const beforeSame = lease.metadata.resourceVersion;
	await patchStatus(name, lease.metadata.uid, beforeSame, [
		{ op: "replace", path: "/status/releaseCause", value: "Requested" },
	]);
	lease = await getLease(name);
	assert(
		lease.status?.releaseCause === "Requested",
		"same releaseCause was not preserved",
	);
	info("releaseCause Requested -> Requested accepted");

	await expectRejected("releaseCause change", name, [
		{ op: "replace", path: "/status/releaseCause", value: "RuntimeTtl" },
	]);
	await expectRejected("releaseCause field removal", name, [
		{ op: "remove", path: "/status/releaseCause" },
	]);
	await expectRejected("status null", name, [
		{ op: "replace", path: "/status", value: null },
	]);
	await expectRejected("whole status removal", name, [
		{ op: "remove", path: "/status" },
	]);
}

async function expectFenceRejected(
	label: string,
	name: string,
	uid: string,
	resourceVersion: string,
): Promise<void> {
	const result = await patchStatus(
		name,
		uid,
		resourceVersion,
		[{ op: "add", path: "/status", value: { phase: "Ready", conditions: [] } }],
		true,
	);
	assert(
		result.exitCode !== 0,
		`${label}: API server accepted a stale fenced patch`,
	);
	info(`${label} rejected`);
}

async function testJsonPatchFences(): Promise<void> {
	const name = "identity-fence";
	let lease = await createLease(name);

	await patchStatus(name, lease.metadata.uid, lease.metadata.resourceVersion, [
		{
			op: "add",
			path: "/status",
			value: { phase: "Provisioning", conditions: [] },
		},
	]);
	lease = await getLease(name);
	assert(
		lease.status?.phase === "Provisioning",
		"current UID/resourceVersion patch did not land",
	);
	info("current UID/resourceVersion accepted");

	const staleResourceVersion = lease.metadata.resourceVersion;
	await kubectl([
		"annotate",
		resource,
		name,
		"-n",
		namespace,
		"contract.kobe.kunobi.ninja/bump=1",
		"--overwrite",
	]);
	const bumped = await getLease(name);
	assert(
		bumped.metadata.uid === lease.metadata.uid,
		"metadata bump replaced the lease UID",
	);
	assert(
		bumped.metadata.resourceVersion !== staleResourceVersion,
		"metadata bump did not advance resourceVersion",
	);
	await expectFenceRejected(
		"stale resourceVersion",
		name,
		bumped.metadata.uid,
		staleResourceVersion,
	);
	let after = await getLease(name);
	assert(
		after.status?.phase === "Provisioning",
		"stale resourceVersion patch changed status",
	);

	const deletedUid = bumped.metadata.uid;
	await kubectl([
		"delete",
		resource,
		name,
		"-n",
		namespace,
		"--wait=true",
		"--timeout=30s",
	]);
	const replacement = await createLease(name);
	assert(
		replacement.metadata.uid !== deletedUid,
		"same-name recreation reused the deleted UID",
	);
	await expectFenceRejected(
		"recreated UID",
		name,
		deletedUid,
		replacement.metadata.resourceVersion,
	);
	after = await getLease(name);
	assert(
		after.metadata.uid === replacement.metadata.uid,
		"UID fence replaced the new object",
	);
	assert(
		after.status?.phase === undefined || after.status?.phase === "Pending",
		`UID fence changed replacement phase to ${after.status?.phase}`,
	);
	assert(
		after.status?.releaseCause === undefined,
		"UID fence changed replacement releaseCause",
	);
}

await kubectl(["create", "namespace", namespace]);
try {
	console.log(
		`SandboxLease API-server contract (${context}, namespace ${namespace})`,
	);
	await testReleaseCauseCel();
	await testJsonPatchFences();
	await testAdmissionLedgerBoundary();
	console.log("SandboxLease API-server contract passed");
} finally {
	await kubectl(
		[
			"delete",
			"validatingadmissionpolicybinding",
			ledgerPolicy,
			"--ignore-not-found",
		],
		{ allowFailure: true },
	);
	await kubectl(
		["delete", "validatingadmissionpolicy", ledgerPolicy, "--ignore-not-found"],
		{ allowFailure: true },
	);
	await kubectl(
		["delete", "clusterrolebinding", ledgerPolicy, "--ignore-not-found"],
		{ allowFailure: true },
	);
	await kubectl(["delete", "clusterrole", ledgerPolicy, "--ignore-not-found"], {
		allowFailure: true,
	});
	await kubectl(
		[
			"delete",
			"namespace",
			ledgerNamespace,
			"--ignore-not-found",
			"--wait=true",
			"--timeout=60s",
		],
		{ allowFailure: true },
	);
	await kubectl(
		[
			"delete",
			"namespace",
			namespace,
			"--ignore-not-found",
			"--wait=true",
			"--timeout=60s",
		],
		{ allowFailure: true },
	);
}
