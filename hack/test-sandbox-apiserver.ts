// Real Kubernetes API-server regression gate for SandboxLease status and the
// admission-ledger abuse boundary.
//
// Unit tests prove that Kobe builds UID/resourceVersion/state-fenced JSON
// Patches and emits the intended CEL. This test proves that a real API server
// enforces both contracts, including one-winner admission cancellation. It
// needs only the SandboxLease CRD and native admission/RBAC APIs, not Kobe or
// the external Agent Sandbox runtime.

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
const teardownFencePolicy = `${namespace}-teardown-fence`;
const teardownFenceLabel = "kobe.kunobi.ninja/sandbox-teardown-fence";
const teardownFenceMessage =
	"Sandbox teardown has fenced descendant creation for this controller owner UID";
const blockedOwnerUid = "11111111-1111-4111-8111-111111111111";

type CommandResult = {
	stdout: string;
	stderr: string;
	exitCode: number;
};

type Lease = {
	metadata: {
		uid: string;
		resourceVersion: string;
		annotations?: Record<string, string>;
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

function ownedPod(name: string, ownerUid: string): string {
	return JSON.stringify({
		apiVersion: "v1",
		kind: "Pod",
		metadata: {
			name,
			namespace,
			ownerReferences: [
				{
					apiVersion: "v1",
					kind: "ConfigMap",
					name: "upstream-owner",
					uid: ownerUid,
					controller: true,
					blockOwnerDeletion: true,
				},
			],
		},
		spec: {
			restartPolicy: "Never",
			containers: [{ name: "sandbox", image: "registry.k8s.io/pause:3.10" }],
		},
	});
}

async function waitForTeardownFencePolicy(): Promise<void> {
	const deadline = Date.now() + 60_000;
	while (Date.now() < deadline) {
		const policy = JSON.parse(
			(
				await kubectl([
					"get",
					"validatingadmissionpolicy",
					teardownFencePolicy,
					"-o",
					"json",
				])
			).stdout,
		);
		const warnings = policy.status?.typeChecking?.expressionWarnings;
		if (Array.isArray(warnings) && warnings.length > 0) {
			throw new Error(
				`teardown fence policy type-check warnings: ${JSON.stringify(warnings)}`,
			);
		}
		if (
			policy.status?.observedGeneration === policy.metadata?.generation &&
			policy.status?.typeChecking !== undefined
		) {
			// Probe with the identity the assertions use, not as admin.
			// The same apply installed tenant's Role and RoleBinding, and
			// authorization runs before validating admission: an unpropagated
			// binding answers `is forbidden` instead of the fence message, so
			// the deny assertion reads the fence as wrong and — worse — the
			// allow assertion reads a plain RBAC 403 as the fence being
			// over-broad. Require BOTH outcomes in one iteration, which is
			// exactly the conjunction the assertions depend on.
			const denied = await kubectl(
				[
					"create",
					"-f",
					"-",
					"--validate=false",
					"--dry-run=server",
					`--as=${tenantUsername}`,
				],
				{
					stdin: ownedPod("blocked-descendant", blockedOwnerUid),
					allowFailure: true,
				},
			);
			const allowed = await kubectl(
				[
					"create",
					"-f",
					"-",
					"--validate=false",
					"--dry-run=server",
					`--as=${tenantUsername}`,
				],
				{
					stdin: ownedPod("unrelated-descendant", "22222222-2222-2222-2222-222222222222"),
					allowFailure: true,
				},
			);
			if (
				denied.stderr.includes(teardownFenceMessage) &&
				allowed.exitCode === 0
			) {
				return;
			}
		}
		await Bun.sleep(500);
	}
	throw new Error("Sandbox teardown fence policy did not become active");
}

async function testTeardownAdmissionFence(): Promise<void> {
	const controls = `
apiVersion: v1
kind: ServiceAccount
metadata:
  name: tenant
  namespace: ${namespace}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: teardown-fence-probe
  namespace: ${namespace}
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: teardown-fence-probe
  namespace: ${namespace}
subjects:
  - kind: ServiceAccount
    name: tenant
    namespace: ${namespace}
roleRef:
  kind: Role
  name: teardown-fence-probe
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: ${teardownFencePolicy}
spec:
  failurePolicy: Fail
  paramKind:
    apiVersion: v1
    kind: ConfigMap
  matchConstraints:
    resourceRules:
      - apiGroups: ["agents.x-k8s.io"]
        apiVersions: ["v1beta1"]
        resources: ["sandboxes"]
        operations: ["CREATE"]
      - apiGroups: [""]
        apiVersions: ["v1"]
        resources: ["pods", "services", "persistentvolumeclaims"]
        operations: ["CREATE"]
  matchConditions:
    - name: controller-owned-descendant
      expression: >-
        has(object.metadata.ownerReferences) &&
        object.metadata.ownerReferences.exists(owner,
          has(owner.controller) && owner.controller == true)
  validations:
    - expression: 'has(params.data) && size(params.data) > 0'
      message: a Sandbox teardown fence must contain at least one blocked owner UID
      reason: Invalid
    - expression: >-
        !object.metadata.ownerReferences.exists(owner,
          has(owner.controller) && owner.controller == true &&
          string(owner.uid) in params.data)
      message: ${teardownFenceMessage}
      reason: Forbidden
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: ${teardownFencePolicy}
spec:
  policyName: ${teardownFencePolicy}
  paramRef:
    selector:
      matchLabels:
        ${teardownFenceLabel}: "true"
    parameterNotFoundAction: Allow
  validationActions: [Deny]
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: blocked-owner-uids
  namespace: ${namespace}
  labels:
    ${teardownFenceLabel}: "true"
  finalizers:
    - kobe.kunobi.ninja/sandbox-teardown-fence
immutable: true
data:
  ${blockedOwnerUid}: blocked
`;
	await kubectl(["apply", "-f", "-"], { stdin: controls });
	await waitForTeardownFencePolicy();

	// Parameter authorization is checked when the binding is created. The
	// admission caller itself deliberately has Pod CREATE but no ConfigMap read.
	const hiddenParameter = await kubectlAs(
		tenantUsername,
		["get", "configmap", "blocked-owner-uids", "-n", namespace],
		true,
	);
	assert(
		hiddenParameter.exitCode !== 0 &&
			hiddenParameter.stderr.toLowerCase().includes("forbidden"),
		"teardown-fence probe identity unexpectedly reads policy parameters",
	);
	const denied = await runCommand(
		[
			"kubectl",
			"--context",
			context,
			`--as=${tenantUsername}`,
			"create",
			"-f",
			"-",
			"--validate=false",
			"--dry-run=server",
		],
		{
			stdin: ownedPod("blocked-descendant", blockedOwnerUid),
			allowFailure: true,
		},
	);
	assert(denied.exitCode !== 0, "blocked owner created a descendant");
	assert(
		denied.stderr.includes(teardownFenceMessage),
		`blocked descendant failed for an unexpected reason: ${denied.stderr}`,
	);

	const allowed = await runCommand(
		[
			"kubectl",
			"--context",
			context,
			`--as=${tenantUsername}`,
			"create",
			"-f",
			"-",
			"--validate=false",
			"--dry-run=server",
		],
		{
			stdin: ownedPod(
				"unrelated-descendant",
				"22222222-2222-4222-8222-222222222222",
			),
			allowFailure: true,
		},
	);
	assert(
		allowed.exitCode === 0,
		`unrelated controller owner was fenced: ${allowed.stderr}`,
	);
	info("exact owner UID admission fence denies stale descendants only");
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
			// Both probes above run as the operator, so they prove the
			// operator's path only. Two later assertions read the tenant's
			// RBAC and the operator's SelfSubjectAccessReview grant, both
			// applied in the same manifest — and an unpropagated binding
			// answers `is forbidden` before admission ever runs, which reads
			// as the ledger policy misbehaving. Require those too.
			const tenantProbe = await kubectl(
				[
					"create",
					"-f",
					"-",
					"--validate=false",
					"--dry-run=server",
					`--as=${tenantUsername}`,
				],
				{ stdin: coordinationLease("ledger-readiness-probe"), allowFailure: true },
			);
			const reviewGrant = await kubectl(
				[
					"auth",
					"can-i",
					"create",
					"selfsubjectaccessreviews.authorization.k8s.io",
					`--as=${operatorUsername}`,
				],
				{ allowFailure: true },
			);
			if (
				policyProbe.stderr.includes(policyCanaryMessage) &&
				quotaProbe.stderr.toLowerCase().includes("exceeded quota") &&
				tenantProbe.stderr.includes("only the operator may mutate the Sandbox ledger") &&
				reviewGrant.stdout.trim() === "yes"
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
  - apiGroups: ["authorization.k8s.io"]
    resources: ["selfsubjectaccessreviews"]
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
	for (const verb of ["get", "list", "create", "patch", "delete"]) {
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
				"-o",
				"json",
			],
			{
				stdin: JSON.stringify({
					apiVersion: "authorization.k8s.io/v1",
					kind: "SelfSubjectAccessReview",
					metadata: {},
					spec: {
						resourceAttributes: {
							group: "coordination.k8s.io",
							version: "v1",
							resource: "leases",
							namespace: ledgerNamespace,
							verb,
						},
					},
				}),
			},
		);
		const access = JSON.parse(result.stdout);
		assert(access.status?.allowed === true, `operator lacks Lease ${verb}`);
	}
	info("operator access-ledger verbs confirmed by SelfSubjectAccessReview");

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

	const slot = JSON.parse(
		(
			await kubectlAs(operatorUsername, [
				"get",
				"lease.coordination.k8s.io",
				"operator-slot-0",
				"-n",
				ledgerNamespace,
				"-o",
				"json",
			])
		).stdout,
	);
	const slotPatch = JSON.stringify([
		{ op: "test", path: "/metadata/uid", value: slot.metadata.uid },
		{
			op: "test",
			path: "/metadata/resourceVersion",
			value: slot.metadata.resourceVersion,
		},
		{
			op: "add",
			path: "/metadata/annotations",
			value: {
				"kobe.kunobi.ninja/sandbox-access-state": "open",
				"kobe.kunobi.ninja/sandbox-access-entries": "{}",
			},
		},
	]);
	result = await kubectlAs(operatorUsername, [
		"patch",
		"lease.coordination.k8s.io",
		"operator-slot-0",
		"-n",
		ledgerNamespace,
		"--type=json",
		"-p",
		slotPatch,
	]);
	assert(result.exitCode === 0, "operator UID/resourceVersion PATCH failed");
	result = await kubectlAs(
		operatorUsername,
		[
			"patch",
			"lease.coordination.k8s.io",
			"operator-slot-0",
			"-n",
			ledgerNamespace,
			"--type=json",
			"-p",
			slotPatch,
		],
		true,
	);
	assert(result.exitCode !== 0, "stale access-ledger CAS PATCH succeeded");
	info(
		"operator access-ledger PATCH accepted and stale resourceVersion rejected",
	);

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
		metadata: {
			name,
			namespace,
			annotations: {
				"kobe.kunobi.ninja/sandbox-admission": "pending",
			},
		},
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

async function patchLease(
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
			"--type=json",
			"-p",
			JSON.stringify(patch),
		],
		{ allowFailure },
	);
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

async function testAdmissionCancellationCas(): Promise<void> {
	const admissionPath =
		"/metadata/annotations/kobe.kunobi.ninja~1sandbox-admission";
	const name = "cancellation-wins-cas";
	const pending = await createLease(name);

	await patchLease(
		name,
		pending.metadata.uid,
		pending.metadata.resourceVersion,
		[
			{ op: "test", path: admissionPath, value: "pending" },
			{ op: "replace", path: admissionPath, value: "cancelled" },
		],
	);
	let current = await getLease(name);
	assert(
		current.metadata.annotations?.["kobe.kunobi.ninja/sandbox-admission"] ===
			"cancelled",
		"cancellation checkpoint did not land",
	);
	info("pending -> cancelled UID/resourceVersion/state CAS accepted");

	const staleAdmission = await patchLease(
		name,
		pending.metadata.uid,
		pending.metadata.resourceVersion,
		[
			{ op: "test", path: admissionPath, value: "pending" },
			{ op: "replace", path: admissionPath, value: "admitted" },
		],
		true,
	);
	assert(
		staleAdmission.exitCode !== 0,
		"API server accepted admission after cancellation won the CAS",
	);
	current = await getLease(name);
	assert(
		current.metadata.annotations?.["kobe.kunobi.ninja/sandbox-admission"] ===
			"cancelled",
		"stale admission changed the cancelled checkpoint",
	);
	info("stale pending -> admitted writer rejected after cancellation");

	const admissionName = "admission-wins-cas";
	const secondPending = await createLease(admissionName);
	await patchLease(
		admissionName,
		secondPending.metadata.uid,
		secondPending.metadata.resourceVersion,
		[
			{ op: "test", path: admissionPath, value: "pending" },
			{ op: "replace", path: admissionPath, value: "admitted" },
		],
	);
	const staleCancellation = await patchLease(
		admissionName,
		secondPending.metadata.uid,
		secondPending.metadata.resourceVersion,
		[
			{ op: "test", path: admissionPath, value: "pending" },
			{ op: "replace", path: admissionPath, value: "cancelled" },
		],
		true,
	);
	assert(
		staleCancellation.exitCode !== 0,
		"API server accepted cancellation after admission won the CAS",
	);
	current = await getLease(admissionName);
	assert(
		current.metadata.annotations?.["kobe.kunobi.ninja/sandbox-admission"] ===
			"admitted",
		"stale cancellation changed the admitted winner",
	);
	info("stale pending -> cancelled writer rejected after admission");
}

await kubectl(["create", "namespace", namespace]);
try {
	console.log(
		`SandboxLease API-server contract (${context}, namespace ${namespace})`,
	);
	await testReleaseCauseCel();
	await testJsonPatchFences();
	await testAdmissionCancellationCas();
	await testAdmissionLedgerBoundary();
	await testTeardownAdmissionFence();
	console.log("SandboxLease API-server contract passed");
} finally {
	await kubectl(
		[
			"delete",
			"validatingadmissionpolicybinding",
			teardownFencePolicy,
			"--ignore-not-found",
		],
		{ allowFailure: true },
	);
	await kubectl(
		[
			"delete",
			"validatingadmissionpolicy",
			teardownFencePolicy,
			"--ignore-not-found",
		],
		{ allowFailure: true },
	);
	await kubectl(
		[
			"patch",
			"configmap",
			"blocked-owner-uids",
			"-n",
			namespace,
			"--type=json",
			"-p",
			'[{"op":"remove","path":"/metadata/finalizers"}]',
		],
		{ allowFailure: true },
	);
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
