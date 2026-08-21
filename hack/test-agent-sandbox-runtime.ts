// Live contract for Kobe's pinned Agent Sandbox v0.5.4 managed runtime.
//
// This test deliberately owns its whole Kind cluster. It never accepts an
// arbitrary kubectl context, and it refuses an existing cluster name before
// creation, so cleanup cannot delete resources belonging to another run.

const chart = "charts/kobe";
const releaseSha256 =
	"7ada631db5d5a2cc043f48ca05cec94db54bc0afa4756b3b610c920b188fe2c4";
const bootstrapSha256 =
	"f5f6cd88a52ad76e2f18eac0a7a4ee620a77c3e02186abe48e8aa6f29155d8fa";
const pinnedImage =
	"registry.k8s.io/agent-sandbox/agent-sandbox-controller@sha256:be477ba317d84a13a38d7605e925e7b4aa82de5b313a4274358920310a931b7f";
const pinnedImageDigests = new Set([
	"sha256:be477ba317d84a13a38d7605e925e7b4aa82de5b313a4274358920310a931b7f",
	"sha256:f7192ebdb18dbcfa26f242b7108f370ecb6e8d99352b427de4697d51853309d8",
	"sha256:46e2bcca361a6394ec118982c77d4644942c57467ecf6649558724a4aa5e532c",
]);
const pauseImage =
	"registry.k8s.io/pause@sha256:278fb9dbcca9518083ad1e11276933a2e96f23de604a3a08cc3c80002767d24c";
const crds = [
	"sandboxclaims.extensions.agents.x-k8s.io",
	"sandboxes.agents.x-k8s.io",
	"sandboxtemplates.extensions.agents.x-k8s.io",
	"sandboxwarmpools.extensions.agents.x-k8s.io",
];

const cluster = Bun.env.SANDBOX_RUNTIME_CLUSTER;
if (
	!cluster ||
	!/^sandbox-runtime-[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?$/.test(cluster)
) {
	throw new Error(
		"SANDBOX_RUNTIME_CLUSTER must be a unique sandbox-runtime-* DNS label of at most 55 characters",
	);
}
const temporaryRoot = Bun.env.RUNNER_TEMP ?? "/tmp";
const kubeconfig = `${temporaryRoot}/${cluster}.kubeconfig`;
const context = `kind-${cluster}`;
const namespace = "kobe-runtime-contract";
const canary = "runtime-contract";

type CommandResult = {
	stdout: string;
	stderr: string;
	exitCode: number;
};

type KubeObject = {
	metadata?: {
		name?: string;
		namespace?: string;
		uid?: string;
		generation?: number;
		annotations?: Record<string, string>;
		ownerReferences?: Array<{
			apiVersion?: string;
			kind?: string;
			name?: string;
			uid?: string;
			controller?: boolean;
		}>;
	};
	spec?: Record<string, unknown>;
	status?: Record<string, unknown>;
	data?: Record<string, string>;
	subsets?: Array<Record<string, unknown>>;
	items?: KubeObject[];
};

function invariant(condition: unknown, message: string): asserts condition {
	if (!condition) throw new Error(message);
}

function info(message: string): void {
	console.log(`  - ${message}`);
}

function errorText(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}

function sha256(value: string): string {
	return new Bun.CryptoHasher("sha256").update(value).digest("hex");
}

async function run(
	cmd: string[],
	options?: { allowFailure?: boolean; stdin?: string; useKubeconfig?: boolean },
): Promise<CommandResult> {
	const proc = Bun.spawn({
		cmd,
		cwd: process.cwd(),
		env: options?.useKubeconfig
			? { ...process.env, KUBECONFIG: kubeconfig }
			: process.env,
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
	return run(["kubectl", "--context", context, ...args], {
		...options,
		useKubeconfig: true,
	});
}

async function getObject(
	resource: string,
	name: string,
	ns?: string,
): Promise<KubeObject | undefined> {
	const args = ["get", resource, name];
	if (ns) args.push("-n", ns);
	args.push("--ignore-not-found", "-o", "json");
	const { stdout } = await kubectl(args);
	return stdout.trim() ? (JSON.parse(stdout) as KubeObject) : undefined;
}

async function getList(resource: string, ns: string): Promise<KubeObject[]> {
	const { stdout } = await kubectl(["get", resource, "-n", ns, "-o", "json"]);
	return (JSON.parse(stdout) as KubeObject).items ?? [];
}

async function eventually<T>(
	label: string,
	timeoutMs: number,
	observe: () => Promise<T | undefined>,
): Promise<T> {
	const deadline = Date.now() + timeoutMs;
	let lastError = "not observed";
	while (Date.now() < deadline) {
		try {
			const value = await observe();
			if (value !== undefined) return value;
			lastError = "condition is not ready";
		} catch (error) {
			lastError = errorText(error);
		}
		await Bun.sleep(1000);
	}
	throw new Error(`${label} timed out: ${lastError}`);
}

function controllerOwner(
	object: KubeObject,
):
	| NonNullable<NonNullable<KubeObject["metadata"]>["ownerReferences"]>[number]
	| undefined {
	return object.metadata?.ownerReferences?.find(
		(owner) => owner.controller === true,
	);
}

function nestedRecord(value: unknown): Record<string, unknown> {
	invariant(value !== null && typeof value === "object", "expected an object");
	return value as Record<string, unknown>;
}

async function renderManagedRuntime(): Promise<string> {
	const { stdout } = await run([
		"helm",
		"template",
		"kobe",
		chart,
		"--namespace",
		"kobe-system",
		"--set",
		"agentSandbox.mode=managed",
		"--show-only",
		"templates/agent-sandbox-runtime.yaml",
	]);
	return stdout;
}

async function installRuntime(): Promise<void> {
	const rendered = await renderManagedRuntime();
	invariant(
		rendered.includes(pinnedImage),
		"rendered runtime lost the pinned image",
	);
	await kubectl(
		[
			"apply",
			"--server-side",
			"--field-manager=kobe-runtime-contract",
			"-f",
			"-",
		],
		{
			stdin: rendered,
		},
	);
	for (const crd of crds) {
		await kubectl([
			"wait",
			"--for=condition=Established",
			`crd/${crd}`,
			"--timeout=90s",
		]);
	}
	await kubectl([
		"wait",
		"--for=condition=Available",
		"deployment/agent-sandbox-controller",
		"-n",
		"agent-sandbox-system",
		"--timeout=180s",
	]);
}

async function verifyChildBootstrap(): Promise<void> {
	await kubectl(
		[
			"apply",
			"--server-side",
			"--field-manager=kobe-runtime-contract",
			"-f",
			"-",
		],
		{ stdin: await Bun.file(`${chart}/crds/bootstrapconfigs.yaml`).text() },
	);
	await kubectl([
		"wait",
		"--for=condition=Established",
		"crd/bootstrapconfigs.kobe.kunobi.ninja",
		"--timeout=60s",
	]);
	await kubectl(["create", "namespace", "kobe-system"]);
	const { stdout: rendered } = await run([
		"helm",
		"template",
		"kobe",
		chart,
		"--namespace",
		"kobe-system",
		"--set",
		"agentSandbox.mode=managed",
		"--show-only",
		"templates/bootstrap-agent-sandbox.yaml",
	]);
	for (let attempt = 0; attempt < 2; attempt += 1) {
		await kubectl(
			[
				"apply",
				"--server-side",
				"--field-manager=kobe-runtime-contract",
				"-f",
				"-",
			],
			{ stdin: rendered },
		);
	}
	const bootstrap = await getObject(
		"bootstrapconfigs.kobe.kunobi.ninja",
		"agent-sandbox-v0-5-4",
		"kobe-system",
	);
	invariant(bootstrap, "managed child BootstrapConfig is missing");
	const files = nestedRecord(nestedRecord(bootstrap.spec).files);
	const manifest = files["agent-sandbox-v0.5.4.yaml"];
	invariant(typeof manifest === "string", "managed child manifest is missing");
	invariant(
		sha256(manifest) === bootstrapSha256,
		"managed child manifest digest drifted",
	);
	invariant(
		manifest.includes(pinnedImage),
		"managed child manifest image is not pinned",
	);
	info("same pinned child BootstrapConfig survives an idempotent retry");
}

async function verifyRuntime(): Promise<void> {
	for (const name of crds) {
		const crd = await getObject("crd", name);
		invariant(crd, `CRD ${name} is missing`);
		invariant(
			crd.metadata?.annotations?.["kobe.kunobi.ninja/source-sha256"] ===
				releaseSha256,
			`CRD ${name} lost release provenance`,
		);
		const spec = nestedRecord(crd.spec);
		const versions = spec.versions as Array<Record<string, unknown>>;
		invariant(
			versions.some(
				(version) => version.name === "v1beta1" && version.served === true,
			),
			`CRD ${name} does not serve v1beta1`,
		);
		const conversion = nestedRecord(spec.conversion);
		const webhook = nestedRecord(conversion.webhook);
		const clientConfig = nestedRecord(webhook.clientConfig);
		invariant(
			typeof clientConfig.caBundle === "string" &&
				clientConfig.caBundle.length > 0,
			`CRD ${name} has no conversion webhook CA bundle`,
		);
	}

	const deployment = await getObject(
		"deployment",
		"agent-sandbox-controller",
		"agent-sandbox-system",
	);
	invariant(deployment, "controller Deployment is missing");
	const deploymentSpec = nestedRecord(deployment.spec);
	const template = nestedRecord(deploymentSpec.template);
	const podSpec = nestedRecord(nestedRecord(template.spec));
	const containers = podSpec.containers as Array<Record<string, unknown>>;
	const controller = containers.find(
		(container) => container.name === "agent-sandbox-controller",
	);
	invariant(
		controller?.image === pinnedImage,
		"controller Deployment image is not pinned",
	);
	invariant(
		(controller.args as unknown[])?.includes("--extensions"),
		"controller extensions are disabled",
	);

	await eventually("pinned Ready controller Pod", 90_000, async () => {
		const pods = await getList("pods", "agent-sandbox-system");
		for (const pod of pods) {
			const labels = pod.metadata
				? nestedRecord(
						(pod.metadata as unknown as Record<string, unknown>).labels,
					)
				: {};
			if (labels.app !== "agent-sandbox-controller") continue;
			const status = nestedRecord(pod.status);
			const conditions = (status.conditions ?? []) as Array<
				Record<string, unknown>
			>;
			const ready = conditions.some(
				(condition) =>
					condition.type === "Ready" && condition.status === "True",
			);
			const containerStatuses = (status.containerStatuses ?? []) as Array<
				Record<string, unknown>
			>;
			const observed = containerStatuses.find(
				(containerStatus) =>
					containerStatus.name === "agent-sandbox-controller",
			);
			const imageId = String(observed?.imageID ?? "");
			if (
				ready &&
				observed?.ready === true &&
				[...pinnedImageDigests].some((digest) => imageId.endsWith(digest))
			) {
				return pod;
			}
		}
		return undefined;
	});

	await eventually("webhook TLS Secret and endpoint", 90_000, async () => {
		const secret = await getObject(
			"secret",
			"agent-sandbox-webhook-certs",
			"agent-sandbox-system",
		);
		if (
			!secret?.data ||
			!["ca.crt", "tls.crt", "tls.key"].every((key) => secret.data?.[key])
		) {
			return undefined;
		}
		const endpoints = await getObject(
			"endpoints",
			"agent-sandbox-webhook-service",
			"agent-sandbox-system",
		);
		const ready = endpoints?.subsets?.some((subset) => {
			const addresses = subset.addresses as unknown[] | undefined;
			const ports = subset.ports as Array<Record<string, unknown>> | undefined;
			return (
				(addresses?.length ?? 0) > 0 &&
				ports?.some((port) => port.name === "webhook" && port.port === 9443)
			);
		});
		return ready ? secret : undefined;
	});
	info("pinned controller, CRDs and conversion webhook are healthy");
}

function canaryList(): string {
	const shutdownTime = new Date(Date.now() + 5 * 60_000).toISOString();
	return JSON.stringify({
		apiVersion: "v1",
		kind: "List",
		items: [
			{
				apiVersion: "extensions.agents.x-k8s.io/v1beta1",
				kind: "SandboxTemplate",
				metadata: { name: canary, namespace },
				spec: {
					service: false,
					networkPolicyManagement: "Managed",
					envVarsInjectionPolicy: "Disallowed",
					volumeClaimTemplatesPolicy: "Disallowed",
					podTemplate: {
						spec: {
							automountServiceAccountToken: false,
							restartPolicy: "Never",
							terminationGracePeriodSeconds: 1,
							securityContext: {
								runAsNonRoot: true,
								runAsUser: 65532,
								seccompProfile: { type: "RuntimeDefault" },
							},
							containers: [
								{
									name: "canary",
									image: pauseImage,
									imagePullPolicy: "IfNotPresent",
									securityContext: {
										allowPrivilegeEscalation: false,
										readOnlyRootFilesystem: true,
										capabilities: { drop: ["ALL"] },
									},
									resources: {
										requests: { cpu: "1m", memory: "4Mi" },
										limits: { cpu: "10m", memory: "16Mi" },
									},
								},
							],
						},
					},
				},
			},
			{
				apiVersion: "extensions.agents.x-k8s.io/v1beta1",
				kind: "SandboxWarmPool",
				metadata: { name: canary, namespace },
				spec: {
					replicas: 0,
					sandboxTemplateRef: { name: canary },
					updateStrategy: { type: "Recreate" },
				},
			},
			{
				apiVersion: "extensions.agents.x-k8s.io/v1beta1",
				kind: "SandboxClaim",
				metadata: { name: canary, namespace },
				spec: {
					warmPoolRef: { name: canary },
					lifecycle: { shutdownTime, shutdownPolicy: "DeleteForeground" },
				},
			},
		],
	});
}

async function createAndDeleteCanary(): Promise<void> {
	await kubectl(
		[
			"apply",
			"--server-side",
			"--field-manager=kobe-runtime-contract",
			"-f",
			"-",
		],
		{
			stdin: canaryList(),
		},
	);

	const claim = await eventually("SandboxClaim Ready", 180_000, async () => {
		const observed = await getObject(
			"sandboxclaims.extensions.agents.x-k8s.io",
			canary,
			namespace,
		);
		if (!observed?.status) return undefined;
		const conditions = (observed.status.conditions ?? []) as Array<
			Record<string, unknown>
		>;
		const ready = conditions.some(
			(condition) => condition.type === "Ready" && condition.status === "True",
		);
		const sandbox = nestedRecord(observed.status.sandbox);
		return ready && typeof sandbox.name === "string" && sandbox.name
			? observed
			: undefined;
	});
	const claimUid = claim.metadata?.uid;
	invariant(claimUid, "Ready SandboxClaim has no UID");
	const sandboxName = String(nestedRecord(claim.status?.sandbox).name);
	const sandbox = await getObject(
		"sandboxes.agents.x-k8s.io",
		sandboxName,
		namespace,
	);
	invariant(sandbox?.metadata?.uid, "Ready Sandbox is missing");
	const sandboxOwner = controllerOwner(sandbox);
	invariant(
		sandboxOwner?.kind === "SandboxClaim" && sandboxOwner.uid === claimUid,
		"Sandbox is not controlled by the exact Claim",
	);

	const pod = await eventually("Sandbox Pod", 60_000, async () => {
		const pods = await getList("pods", namespace);
		return pods.find((candidate) => {
			const owner = controllerOwner(candidate);
			return owner?.kind === "Sandbox" && owner.uid === sandbox.metadata?.uid;
		});
	});
	invariant(
		pod.metadata?.name && pod.metadata.uid,
		"Sandbox Pod has no identity",
	);
	info(
		"real SandboxClaim reached Ready with an exact Sandbox -> Pod owner chain",
	);

	const identities = [
		["sandboxclaims.extensions.agents.x-k8s.io", canary, claimUid],
		["sandboxes.agents.x-k8s.io", sandboxName, sandbox.metadata.uid],
		["pods", pod.metadata.name, pod.metadata.uid],
	] as const;
	await kubectl([
		"delete",
		"sandboxclaims.extensions.agents.x-k8s.io",
		canary,
		"-n",
		namespace,
		"--cascade=foreground",
		"--wait=true",
		"--timeout=120s",
	]);
	for (const [resource, name, uid] of identities) {
		await eventually(`${resource}/${name} absence`, 120_000, async () => {
			const observed = await getObject(resource, name, namespace);
			if (!observed) return true;
			invariant(
				observed.metadata?.uid === uid,
				`${resource}/${name} was replaced during cleanup`,
			);
			return undefined;
		});
	}

	for (const resource of [
		"sandboxwarmpools.extensions.agents.x-k8s.io",
		"sandboxtemplates.extensions.agents.x-k8s.io",
	]) {
		const object = await getObject(resource, canary, namespace);
		invariant(
			object?.metadata?.uid,
			`${resource}/${canary} is missing before cleanup`,
		);
		await kubectl([
			"delete",
			resource,
			canary,
			"-n",
			namespace,
			"--wait=true",
			"--timeout=60s",
		]);
		await eventually(`${resource}/${canary} absence`, 60_000, async () =>
			(await getObject(resource, canary, namespace)) ? undefined : true,
		);
	}
	info(
		"foreground cleanup removed the exact Claim, Sandbox, Pod, WarmPool and Template",
	);
}

async function contract(): Promise<void> {
	const current = (
		await run(["kubectl", "config", "current-context"], { useKubeconfig: true })
	).stdout.trim();
	invariant(
		current === context,
		`created kubeconfig selected ${current}, expected ${context}`,
	);
	// This marker is the fallback cleanup proof used by CI if the process is
	// interrupted after Kind creation but before this script reaches cleanup.
	await kubectl(["create", "namespace", namespace]);
	await kubectl([
		"label",
		"namespace",
		namespace,
		`kobe.kunobi.ninja/contract-cluster=${cluster}`,
	]);
	await installRuntime();
	await verifyRuntime();
	await verifyChildBootstrap();
	await createAndDeleteCanary();
}

const clusters = (await run(["kind", "get", "clusters"])).stdout
	.split("\n")
	.map((name) => name.trim())
	.filter(Boolean);
invariant(
	!clusters.includes(cluster),
	`refusing to reuse existing Kind cluster ${cluster}`,
);
invariant(
	!(await Bun.file(kubeconfig).exists()),
	`refusing to overwrite existing ${kubeconfig}`,
);

let creationStarted = false;
let failure: unknown;
try {
	creationStarted = true;
	await run([
		"kind",
		"create",
		"cluster",
		"--name",
		cluster,
		"--kubeconfig",
		kubeconfig,
		"--wait",
		"120s",
	]);
	await contract();
} catch (error) {
	failure = error;
}

if (creationStarted) {
	const cleanup = await run(
		[
			"kind",
			"delete",
			"cluster",
			"--name",
			cluster,
			"--kubeconfig",
			kubeconfig,
		],
		{ allowFailure: true },
	);
	if (cleanup.exitCode !== 0) {
		const cleanupError = cleanup.stderr.trim() || cleanup.stdout.trim();
		failure = failure
			? new Error(
					`${errorText(failure)}; Kind cleanup also failed: ${cleanupError}`,
				)
			: new Error(`Kind cleanup failed: ${cleanupError}`);
	}
}

if (failure) throw failure;
console.log("Agent Sandbox v0.5.4 managed runtime contract passed");
