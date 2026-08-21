// Live contract for the pinned Agent Sandbox v0.5.6 release Kobe's external
// mode consumes, including the supported operator-side v0.5.4 -> v0.5.6
// rolling upgrade with a live warm Claim. Kobe does not install this runtime;
// the harness plays the operator and installs the pinned fixture itself.
//
// This test deliberately owns its whole Kind cluster. It never accepts an
// arbitrary kubectl context, and it refuses an existing cluster name before
// creation, so cleanup cannot delete resources belonging to another run.

const releaseFixture = "hack/fixtures/agent-sandbox-v0.5.6.yaml";
const releaseSha256 =
	"1696dbb6faded503149b3994badb599df5dcf24d5985466881784f442dd9c3e5";
const taggedImage =
	"registry.k8s.io/agent-sandbox/agent-sandbox-controller:v0.5.6";
const pinnedImage =
	"registry.k8s.io/agent-sandbox/agent-sandbox-controller@sha256:dc23fb0d5624c306ca2f8ef0d41848dba670ebaf62beb500f870175aec529ffd";
const pinnedImageDigests = new Set([
	"sha256:dc23fb0d5624c306ca2f8ef0d41848dba670ebaf62beb500f870175aec529ffd",
	"sha256:a502cfdbcf550e77509cc56097978458a1ac3d5b59972f21b7ce0e0a84a5c12e",
	"sha256:db3d5a89473701ff0859eb81c98a0f8fcbce70915f2af052f599eba094284061",
]);
const previousReleaseUrl =
	"https://github.com/kubernetes-sigs/agent-sandbox/releases/download/v0.5.4/sandbox-with-extensions.yaml";
const previousReleaseSha256 =
	"7ada631db5d5a2cc043f48ca05cec94db54bc0afa4756b3b610c920b188fe2c4";
const previousTaggedImage =
	"registry.k8s.io/agent-sandbox/agent-sandbox-controller:v0.5.4";
const previousPinnedImage =
	"registry.k8s.io/agent-sandbox/agent-sandbox-controller@sha256:be477ba317d84a13a38d7605e925e7b4aa82de5b313a4274358920310a931b7f";
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
const upgradeCanary = "runtime-upgrade";

type CommandResult = {
	stdout: string;
	stderr: string;
	exitCode: number;
};

type KubeObject = {
	apiVersion?: string;
	kind?: string;
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

async function exactControllerChildren(
	resource: string,
	ownerKind: string,
	ownerUid: string,
): Promise<KubeObject[]> {
	return (await getList(resource, namespace)).filter((candidate) => {
		const owner = controllerOwner(candidate);
		return owner?.kind === ownerKind && owner.uid === ownerUid;
	});
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

async function pinnedRuntime(): Promise<string> {
	const source = await Bun.file(releaseFixture).text();
	invariant(
		sha256(source) === releaseSha256,
		"pinned release fixture digest drifted",
	);
	const pinned = source.replaceAll(taggedImage, pinnedImage);
	invariant(
		pinned.includes(pinnedImage) && !pinned.includes(taggedImage),
		"v0.5.6 runtime image was not pinned",
	);
	return pinned;
}

async function applyRuntime(rendered: string): Promise<void> {
	invariant(
		rendered.includes("agent-sandbox-controller"),
		"runtime manifest has no controller",
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

async function installPreviousRuntime(): Promise<void> {
	const response = await fetch(previousReleaseUrl, {
		signal: AbortSignal.timeout(60_000),
	});
	invariant(
		response.ok,
		`failed to download v0.5.4 runtime: HTTP ${response.status}`,
	);
	const source = await response.text();
	invariant(
		sha256(source) === previousReleaseSha256,
		"downloaded v0.5.4 runtime digest drifted",
	);
	const pinned = source.replace(previousTaggedImage, previousPinnedImage);
	invariant(
		pinned.includes(previousPinnedImage) &&
			!pinned.includes(previousTaggedImage),
		"v0.5.4 runtime image was not pinned",
	);
	await applyRuntime(pinned);
	info("installed the exact former v0.5.4 runtime");
}

async function installRuntime(): Promise<void> {
	await applyRuntime(await pinnedRuntime());
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
		const servedVersion = versions.find(
			(version) => version.name === "v1beta1" && version.served === true,
		);
		invariant(servedVersion, `CRD ${name} does not serve v1beta1`);
		if (name === "sandboxwarmpools.extensions.agents.x-k8s.io") {
			const schema = nestedRecord(servedVersion.schema);
			const root = nestedRecord(schema.openAPIV3Schema);
			const properties = nestedRecord(root.properties);
			const status = nestedRecord(properties.status);
			const statusProperties = nestedRecord(status.properties);
			const observedGeneration = nestedRecord(
				statusProperties.observedGeneration,
			);
			invariant(
				observedGeneration.type === "integer" &&
					observedGeneration.format === "int64" &&
					observedGeneration.minimum === 0,
				"SandboxWarmPool CRD lacks the v0.5.6 observedGeneration contract",
			);
		}
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

function canaryObjects(
	name: string,
	replicas: number,
	lifetimeMs = 5 * 60_000,
): KubeObject[] {
	const shutdownTime = new Date(Date.now() + lifetimeMs).toISOString();
	return [
		{
			apiVersion: "extensions.agents.x-k8s.io/v1beta1",
			kind: "SandboxTemplate",
			metadata: { name, namespace },
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
			metadata: { name, namespace },
			spec: {
				replicas,
				sandboxTemplateRef: { name },
				updateStrategy: { type: "Recreate" },
			},
		},
		{
			apiVersion: "extensions.agents.x-k8s.io/v1beta1",
			kind: "SandboxClaim",
			metadata: { name, namespace },
			spec: {
				warmPoolRef: { name },
				lifecycle: { shutdownTime, shutdownPolicy: "DeleteForeground" },
			},
		},
	];
}

function objectList(items: KubeObject[]): string {
	return JSON.stringify({
		apiVersion: "v1",
		kind: "List",
		items,
	});
}

function canaryList(): string {
	return objectList(canaryObjects(canary, 0));
}

type RuntimeFootprint = {
	claimUid: string;
	sandboxName: string;
	sandboxUid: string;
	podName: string;
	podUid: string;
};

async function readyFootprint(name: string): Promise<RuntimeFootprint> {
	return eventually(`${name} exact Ready footprint`, 180_000, async () => {
		const claim = await getObject(
			"sandboxclaims.extensions.agents.x-k8s.io",
			name,
			namespace,
		);
		const claimUid = claim?.metadata?.uid;
		if (!claimUid || !claim.status) return undefined;
		const conditions = (claim.status.conditions ?? []) as Array<
			Record<string, unknown>
		>;
		if (
			!conditions.some(
				(condition) =>
					condition.type === "Ready" && condition.status === "True",
			)
		) {
			return undefined;
		}
		const sandboxName = nestedRecord(claim.status.sandbox).name;
		if (typeof sandboxName !== "string" || !sandboxName) return undefined;
		const sandboxes = await exactControllerChildren(
			"sandboxes.agents.x-k8s.io",
			"SandboxClaim",
			claimUid,
		);
		if (sandboxes.length === 0) return undefined;
		invariant(sandboxes.length === 1, `${name} Claim owns multiple Sandboxes`);
		const [sandbox] = sandboxes;
		const sandboxUid = sandbox.metadata?.uid;
		if (!sandboxUid) return undefined;
		invariant(
			sandbox.metadata?.name === sandboxName,
			`${name} Claim status does not name its exact owned Sandbox`,
		);
		const sandboxOwner = controllerOwner(sandbox);
		invariant(
			sandboxOwner?.kind === "SandboxClaim" && sandboxOwner.uid === claimUid,
			`${name} Sandbox is not controlled by the exact Claim`,
		);
		const pods = await exactControllerChildren("pods", "Sandbox", sandboxUid);
		if (pods.length === 0) return undefined;
		invariant(pods.length === 1, `${name} Sandbox owns multiple Pods`);
		const [pod] = pods;
		const podName = pod?.metadata?.name;
		const podUid = pod?.metadata?.uid;
		if (!podName || !podUid) return undefined;
		for (const resource of ["services", "persistentvolumeclaims"]) {
			invariant(
				(await exactControllerChildren(resource, "Sandbox", sandboxUid))
					.length === 0,
				`${name} restricted Sandbox unexpectedly owns ${resource}`,
			);
		}
		return { claimUid, sandboxName, sandboxUid, podName, podUid };
	});
}

async function createWarmUpgradeClaim(): Promise<RuntimeFootprint> {
	// The 20-minute CI envelope must remain the thing that bounds this Claim;
	// a five-minute emergency expiry could fire while the two controller
	// rollouts and exact-footprint checks are still progressing.
	const objects = canaryObjects(upgradeCanary, 1, 30 * 60_000);
	await kubectl(
		[
			"apply",
			"--server-side",
			"--field-manager=kobe-runtime-contract",
			"-f",
			"-",
		],
		{ stdin: objectList(objects.slice(0, 2)) },
	);
	await eventually("v0.5.4 warm capacity", 180_000, async () => {
		const warmPool = await getObject(
			"sandboxwarmpools.extensions.agents.x-k8s.io",
			upgradeCanary,
			namespace,
		);
		return warmPool?.status?.readyReplicas === 1 ? warmPool : undefined;
	});
	await kubectl(
		[
			"apply",
			"--server-side",
			"--field-manager=kobe-runtime-contract",
			"-f",
			"-",
		],
		{ stdin: JSON.stringify(objects[2]) },
	);
	const footprint = await readyFootprint(upgradeCanary);
	info("v0.5.4 warm Claim is Ready before the controller upgrade");
	return footprint;
}

async function verifyUpgradePreserved(
	expected: RuntimeFootprint,
): Promise<void> {
	const observed = await readyFootprint(upgradeCanary);
	invariant(
		JSON.stringify(observed) === JSON.stringify(expected),
		"v0.5.4 -> v0.5.6 changed the live warm Claim footprint",
	);
	await eventually(
		"upgraded WarmPool current-generation status",
		90_000,
		async () => {
			const warmPool = await getObject(
				"sandboxwarmpools.extensions.agents.x-k8s.io",
				upgradeCanary,
				namespace,
			);
			if (!warmPool?.status) return undefined;
			return warmPool.status.observedGeneration ===
				warmPool.metadata?.generation
				? warmPool
				: undefined;
		},
	);
	info("v0.5.6 preserved the exact live warm Claim and observed its pool");
}

async function cleanupUpgradeCanary(
	footprint: RuntimeFootprint,
): Promise<void> {
	const exact = await readyFootprint(upgradeCanary);
	invariant(
		JSON.stringify(exact) === JSON.stringify(footprint),
		"upgrade footprint changed before cleanup",
	);
	await kubectl([
		"delete",
		"sandboxclaims.extensions.agents.x-k8s.io",
		upgradeCanary,
		"-n",
		namespace,
		"--cascade=foreground",
		"--wait=true",
		"--timeout=120s",
	]);
	for (const [resource, name, uid] of [
		[
			"sandboxclaims.extensions.agents.x-k8s.io",
			upgradeCanary,
			footprint.claimUid,
		],
		["sandboxes.agents.x-k8s.io", footprint.sandboxName, footprint.sandboxUid],
		["pods", footprint.podName, footprint.podUid],
	] as const) {
		await eventually(`${resource}/${name} absence`, 120_000, async () => {
			const object = await getObject(resource, name, namespace);
			if (!object) return true;
			invariant(
				object.metadata?.uid === uid,
				`${resource}/${name} was replaced during upgrade cleanup`,
			);
			return undefined;
		});
	}
	for (const [resource, ownerKind, ownerUid] of [
		["sandboxes.agents.x-k8s.io", "SandboxClaim", footprint.claimUid],
		["pods", "Sandbox", footprint.sandboxUid],
		["services", "Sandbox", footprint.sandboxUid],
		["persistentvolumeclaims", "Sandbox", footprint.sandboxUid],
	] as const) {
		await eventually(`${resource} exact-owner absence`, 120_000, async () =>
			(await exactControllerChildren(resource, ownerKind, ownerUid)).length ===
			0
				? true
				: undefined,
		);
	}
	for (const resource of [
		"sandboxwarmpools.extensions.agents.x-k8s.io",
		"sandboxtemplates.extensions.agents.x-k8s.io",
	]) {
		await kubectl([
			"delete",
			resource,
			upgradeCanary,
			"-n",
			namespace,
			"--cascade=foreground",
			"--wait=true",
			"--timeout=120s",
		]);
	}
	info("upgrade fixture was removed after exact Claim/Sandbox/Pod absence");
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

	await eventually(
		"SandboxWarmPool current-generation status",
		90_000,
		async () => {
			const warmPool = await getObject(
				"sandboxwarmpools.extensions.agents.x-k8s.io",
				canary,
				namespace,
			);
			if (!warmPool?.status) return undefined;
			return warmPool.status.observedGeneration ===
				warmPool.metadata?.generation
				? warmPool
				: undefined;
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
	await installPreviousRuntime();
	const upgradeFootprint = await createWarmUpgradeClaim();
	await installRuntime();
	await verifyRuntime();
	await verifyUpgradePreserved(upgradeFootprint);
	await cleanupUpgradeCanary(upgradeFootprint);
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
console.log("Agent Sandbox v0.5.6 pinned runtime contract passed");
