// Real Kubernetes API-server regression gate for SandboxLease status.
//
// Unit tests prove that Kobe builds UID/resourceVersion-fenced JSON Patches
// and emits the intended CEL. This test proves that a real API server enforces
// both contracts. It needs only the SandboxLease CRD, not Kobe or the external
// Agent Sandbox runtime.

const context = Bun.env.KOBE_SANDBOX_APISERVER_CONTEXT ?? Bun.argv[2];
if (!context) {
	throw new Error(
		"set KOBE_SANDBOX_APISERVER_CONTEXT or pass a kubectl context as argv[2]",
	);
}

const resource = "sandboxleases.kobe.kunobi.ninja";
const namespace = `kobe-sandbox-contract-${Date.now().toString(36)}`;

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
	console.log("SandboxLease API-server contract passed");
} finally {
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
