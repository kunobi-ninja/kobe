type KobeStatus = {
  cliVersion: string;
  target?: string | null;
  endpoint?: string | null;
  endpointVersion?: string | null;
  pools: PoolStatus[];
  leases?: LeaseStatus[];
};

type PoolStatus = {
  name: string;
  ready: number;
  leased: number;
  creating: number;
  recycling?: number;
  queueDepth: number;
};

type LeaseResponse = {
  id: string;
  phase?: string;
  profile?: string;
  kubeconfigPath?: string | null;
  clusterName?: string | null;
};

type LeaseStatus = {
  id: string;
  phase?: string;
  profile?: string;
  clusterName?: string | null;
};

type KubeconfigView = {
  clusters: Array<{ name: string; cluster: { server: string } }>;
  contexts: Array<{ name: string }>;
  users: Array<{ name: string; user: { token?: string } }>;
};

const [pool = "ci-small", ttl = "2m", ...kobeArgs] = Bun.argv.slice(2);

const leaseWaitTimeout = Bun.env.LEASE_WAIT_TIMEOUT ?? "15s";
const warmupTimeoutSeconds = parsePositiveInt(
  Bun.env.POOL_WARMUP_TIMEOUT_SECONDS ?? "30",
  "POOL_WARMUP_TIMEOUT_SECONDS",
);
const warmupRetrySeconds = parsePositiveInt(
  Bun.env.POOL_WARMUP_RETRY_SECONDS ?? "2",
  "POOL_WARMUP_RETRY_SECONDS",
);
const connectTimeoutSeconds = parsePositiveInt(
  Bun.env.CONNECT_TIMEOUT_SECONDS ?? "5",
  "CONNECT_TIMEOUT_SECONDS",
);
const connectRetrySeconds = parsePositiveInt(
  Bun.env.CONNECT_RETRY_SECONDS ?? "1",
  "CONNECT_RETRY_SECONDS",
);
const minEndpointVersion = Bun.env.MIN_ENDPOINT_VERSION ?? "v0.8.11";

let leaseId = "";
let released = false;
let clusterName = "";
let kubeconfigPath = "";
let serverUrl = "";
let targetName = "default";
let endpointUrl = "";
let endpointVersion = "";
let cliVersion = "";
let poolBefore: PoolStatus | null = null;

function parsePositiveInt(value: string, name: string): number {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive integer, got '${value}'`);
  }
  return parsed;
}

function normalizeVersion(version: string): string {
  return version.replace(/^v/, "").split("-")[0] ?? version;
}

function isDevelopmentVersion(version: string): boolean {
  const normalized = version.trim().toLowerCase();
  return normalized === "dev" || normalized === "local";
}

function versionGte(left: string, right: string): boolean {
  if (isDevelopmentVersion(left)) {
    return true;
  }
  const leftParts = normalizeVersion(left).split(".").map(Number);
  const rightParts = normalizeVersion(right).split(".").map(Number);
  const length = Math.max(leftParts.length, rightParts.length);
  for (let i = 0; i < length; i += 1) {
    const l = leftParts[i] ?? 0;
    const r = rightParts[i] ?? 0;
    if (l > r) return true;
    if (l < r) return false;
  }
  return true;
}

function shortLeaseId(leaseId: string): string {
  return leaseId.replace(/^lease-/, "").slice(0, 8);
}

function shouldSkipKubectlVerification(serverUrl: string): boolean {
  return serverUrl.startsWith("http://127.0.0.1:") || serverUrl.startsWith("http://localhost:");
}

function truncate(text: string, max = 180): string {
  const singleLine = text.replace(/\s+/g, " ").trim();
  if (singleLine.length <= max) return singleLine;
  return `${singleLine.slice(0, max - 3)}...`;
}

function info(message = ""): void {
  console.log(message);
}

function errorLine(message = ""): void {
  console.error(message);
}

async function runCommand(
  cmd: string[],
  options?: { stdin?: string; allowFailure?: boolean },
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  const proc = Bun.spawn({
    cmd,
    stdin: options?.stdin ? "pipe" : "ignore",
    stdout: "pipe",
    stderr: "pipe",
    cwd: process.cwd(),
  });

  if (options?.stdin) {
    const writer = proc.stdin.writer();
    await writer.write(new TextEncoder().encode(options.stdin));
    await writer.end();
  }

  const [stdoutBuf, stderrBuf, exitCode] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ]);

  if (exitCode !== 0 && !options?.allowFailure) {
    const rendered = [stdoutBuf.trim(), stderrBuf.trim()].filter(Boolean).join("\n");
    throw new Error(rendered || `Command failed (${cmd.join(" ")}) with exit code ${exitCode}`);
  }

  return { stdout: stdoutBuf, stderr: stderrBuf, exitCode };
}

async function kobeJson<T>(args: string[]): Promise<T> {
  const { stdout } = await runCommand(["cargo", "run", "--quiet", "-p", "kobectl", "--bin", "kobe", "--", ...kobeArgs, ...args]);
  return JSON.parse(stdout) as T;
}

async function kubectlJson<T>(kubeconfig: string, args: string[]): Promise<T> {
  const { stdout } = await runCommand([
    "kubectl",
    "--kubeconfig",
    kubeconfig,
    ...args,
  ]);
  return JSON.parse(stdout) as T;
}

async function kubectlText(kubeconfig: string, args: string[], allowFailure = false) {
  return runCommand(["kubectl", "--kubeconfig", kubeconfig, ...args], { allowFailure });
}

async function fetchStatus(): Promise<KobeStatus> {
  return kobeJson<KobeStatus>(["status", "-o", "json"]);
}

function selectPool(status: KobeStatus, name: string): PoolStatus {
  const match = status.pools.find((poolStatus) => poolStatus.name === name);
  if (!match) {
    throw new Error(`Pool '${name}' was not found in kobe status output`);
  }
  return match;
}

function renderPool(poolStatus: PoolStatus): string {
  return `ready=${poolStatus.ready} leased=${poolStatus.leased} creating=${poolStatus.creating} recycling=${poolStatus.recycling ?? 0} queue=${poolStatus.queueDepth}`;
}

async function waitForWarmPool(name: string): Promise<PoolStatus> {
  const initialStatus = await fetchStatus();
  let current = selectPool(initialStatus, name);
  if (current.ready > 0) {
    return current;
  }

  info(
    `Pool '${name}' is not warm yet (${renderPool(current)}). Waiting up to ${warmupTimeoutSeconds}s for warm capacity...`,
  );

  const deadline = Date.now() + warmupTimeoutSeconds * 1000;
  let attempt = 0;
  while (Date.now() < deadline) {
    attempt += 1;
    await Bun.sleep(warmupRetrySeconds * 1000);
    current = selectPool(await fetchStatus(), name);
    if (current.ready > 0) {
      info(`Pool '${name}' became warm after ${attempt * warmupRetrySeconds}s.`);
      return current;
    }
    info(`  [${attempt}] waiting for warm pool - ${renderPool(current)}`);
  }

  throw new Error(
    `🚫 Pool '${name}' did not become warm within ${warmupTimeoutSeconds}s.\n   Expected at least one ready cluster.\n   Last state: ${renderPool(current)}`,
  );
}

function describeLeaseControllerAnomaly(
  lease: LeaseStatus | undefined,
  before: PoolStatus | null,
  after: PoolStatus,
): string | null {
  if (lease?.phase === "Pending" && lease.clusterName) {
    return "lease is still pending even though a cluster name was assigned";
  }

  if (lease?.phase === "Pending" && after.leased > (before?.leased ?? 0)) {
    return "lease remained pending while pool leased capacity increased";
  }

  if (
    lease?.phase === "Pending" &&
    after.queueDepth > (before?.queueDepth ?? 0) &&
    after.creating > (before?.creating ?? 0)
  ) {
    return "lease was re-queued while the pool started creating replacement capacity";
  }

  return null;
}

function summarizeProbePayload(path: string, payload: unknown): string {
  if (!payload || typeof payload !== "object") {
    return truncate(String(payload));
  }

  const record = payload as Record<string, unknown>;
  if (path === "version") {
    return `gitVersion=${record.gitVersion ?? "-"} platform=${record.platform ?? "-"}`;
  }
  if (path === "api") {
    const versions = Array.isArray(record.versions) ? record.versions.join(",") : "";
    return `versions=[${versions}]`;
  }
  if (path === "apis") {
    const groups = Array.isArray(record.groups) ? record.groups : [];
    const names = groups
      .slice(0, 5)
      .map((group) => (group && typeof group === "object" ? (group as { name?: string }).name : undefined))
      .filter((name): name is string => Boolean(name))
      .join(",");
    return `groups=${groups.length} sample=[${names}]`;
  }
  return truncate(JSON.stringify(payload));
}

type ProbeResult = {
  ok: boolean;
  status?: number;
  summary: string;
};

async function probeLeasePath(path: string, token: string): Promise<ProbeResult> {
  const response = await fetch(`${serverUrl}/${path}`, {
    headers: { Authorization: `Bearer ${token}` },
  }).catch((error) => ({ ok: false, statusText: String(error), text: async () => "" } as Response));

  if (!("ok" in response)) {
    return { ok: false, summary: truncate(String(response)) };
  }

  const bodyText = await response.text();
  if (!response.ok) {
    return {
      ok: false,
      status: response.status,
      summary: `HTTP ${response.status} ${truncate(bodyText || response.statusText)}`,
    };
  }

  let summary = truncate(bodyText);
  try {
    summary = summarizeProbePayload(path, JSON.parse(bodyText));
  } catch {
    // keep text summary
  }

  return { ok: true, status: response.status, summary };
}

async function printFailureDiagnostics(reason: string): Promise<void> {
  const status = await fetchStatus();
  const poolAfter = selectPool(status, pool);

  errorLine("");
  errorLine("Smoke diagnostics");
  errorLine(`  reason     ${reason}`);
  errorLine(`  endpoint   ${endpointUrl || "-"} (${endpointVersion || "-"})`);
  errorLine(`  target     ${targetName || "-"}`);
  errorLine(`  lease      ${leaseId || "-"}`);
  errorLine(`  cluster    ${clusterName || "-"}`);
  errorLine(`  server     ${serverUrl || "-"}`);
  errorLine(`  kubeconfig ${kubeconfigPath || "-"}`);
  errorLine("");
  errorLine("  pool");
  if (poolBefore) {
    errorLine(`    before  ${renderPool(poolBefore)}`);
  }
  errorLine(`    after   ${renderPool(poolAfter)}`);

  if (!serverUrl || !kubeconfigPath) {
    return;
  }

  const kubeconfig = await kubectlJson<KubeconfigView>(kubeconfigPath, ["config", "view", "--raw", "-o", "json"]);
  const token = kubeconfig.users[0]?.user?.token ?? "";
  if (!token) {
    errorLine("");
    errorLine("  probes");
    errorLine("    token missing from kubeconfig");
    return;
  }

  errorLine("");
  errorLine("  probes");
  for (const path of ["version", "api", "apis"]) {
    const probe = await probeLeasePath(path, token);
    if (!probe.ok) {
      errorLine(`    /${path}  err  ${probe.summary}`);
      continue;
    }
    errorLine(`    /${path}  ok`);
    errorLine(`      ${probe.summary}`);
  }
}

async function printLeaseWaitDiagnostics(reason: string): Promise<void> {
  const status = await fetchStatus();
  const poolAfter = selectPool(status, pool);
  const matchingLease = leaseId ? (status.leases ?? []).find((lease) => lease.id === leaseId) : undefined;
  const anomaly = describeLeaseControllerAnomaly(matchingLease, poolBefore, poolAfter);

  errorLine("");
  errorLine("Smoke diagnostics");
  errorLine(`  reason     ${reason}`);
  errorLine(`  endpoint   ${endpointUrl || "-"} (${endpointVersion || "-"})`);
  errorLine(`  target     ${targetName || "-"}`);
  errorLine(`  lease      ${leaseId || "-"}`);
  errorLine(`  cluster    ${matchingLease?.clusterName ?? clusterName ?? "-"}`);
  errorLine("");
  errorLine("  pool");
  if (poolBefore) {
    errorLine(`    before  ${renderPool(poolBefore)}`);
  }
  errorLine(`    after   ${renderPool(poolAfter)}`);
  errorLine("");
  errorLine("  lease status");
  if (matchingLease) {
    errorLine(
      `    ${matchingLease.id} phase=${matchingLease.phase ?? "-"} cluster=${matchingLease.clusterName ?? "-"} profile=${matchingLease.profile ?? "-"}`,
    );
  } else if (leaseId) {
    errorLine(`    ${leaseId} not present in status output`);
  } else {
    errorLine("    no lease id captured");
  }

  const poolLeases = (status.leases ?? []).filter((lease) => lease.profile === pool);
  if (poolLeases.length > 0) {
    errorLine("");
    errorLine(`  active leases in pool '${pool}'`);
    for (const lease of poolLeases.slice(0, 5)) {
      errorLine(
        `    ${lease.id} phase=${lease.phase ?? "-"} cluster=${lease.clusterName ?? "-"}`
      );
    }
  }

  if (anomaly) {
    errorLine("");
    errorLine("  controller anomaly");
    errorLine(`    ${anomaly}`);
  }
}

function tryCaptureLeaseId(message: string): string {
  const match = message.match(/lease-[a-z0-9]+/i);
  return match?.[0] ?? "";
}

async function releaseLease(): Promise<void> {
  if (!leaseId || released) return;
  info(`Releasing lease ${leaseId}...`);
  await kobeJson(["release", leaseId, "-o", "json"]);
  released = true;
}

async function main(): Promise<void> {
  info("Checking pool state...");
  const status = await fetchStatus();
  cliVersion = status.cliVersion;
  endpointVersion = status.endpointVersion ?? "";
  endpointUrl = status.endpoint ?? "";
  targetName = status.target ?? "default";
  poolBefore = selectPool(status, pool);

  info(
    `Kobe target='${targetName}' endpoint='${endpointUrl}' cli=${cliVersion} endpointVersion=${endpointVersion}`,
  );

  if (!endpointVersion) {
    throw new Error("🚫 Endpoint version is missing.\n   Refusing to run smoke test without a compatibility check.");
  }
  if (!versionGte(endpointVersion, minEndpointVersion)) {
    throw new Error(
      `🚫 Endpoint ${endpointVersion} is too old for this smoke test.\n   Expected at least ${minEndpointVersion}.\n   Reason: this smoke test assumes the warm-cluster readiness fix.\n   Bail out: no lease requested.`,
    );
  }
  poolBefore = await waitForWarmPool(pool);

  info(`Pool '${pool}': ${renderPool(poolBefore)}`);
  info(`Requesting lease from pool '${pool}' (ttl=${ttl}, lease wait timeout=${leaseWaitTimeout})...`);

  let lease: LeaseResponse;
  try {
    lease = await kobeJson<LeaseResponse>([
      "lease",
      pool,
      "--ttl",
      ttl,
      "--wait-timeout",
      leaseWaitTimeout,
      "-o",
      "json",
    ]);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    leaseId = tryCaptureLeaseId(message);
    if (message.includes("Timed out waiting for lease")) {
      errorLine(message);
      await printLeaseWaitDiagnostics("lease did not become ready within the acquisition timeout");
      process.exitCode = 1;
      return;
    }
    throw error;
  }

  leaseId = lease.id;
  clusterName = lease.clusterName ?? "";
  kubeconfigPath = lease.kubeconfigPath ?? "";

  if (!leaseId) {
    throw new Error("Lease response did not include an id");
  }
  if (!kubeconfigPath) {
    throw new Error(`Lease ${leaseId} did not return a kubeconfig path`);
  }
  if (!(await Bun.file(kubeconfigPath).exists())) {
    throw new Error(`Lease kubeconfig was not written: ${kubeconfigPath}`);
  }

  info(`Lease acquired: ${leaseId}`);
  info("Validating kubeconfig shape...");

  const kubeconfig = await kubectlJson<KubeconfigView>(kubeconfigPath, ["config", "view", "--raw", "-o", "json"]);
  serverUrl = kubeconfig.clusters[0]?.cluster.server ?? "";
  const contextName = kubeconfig.contexts[0]?.name ?? "";
  const token = kubeconfig.users[0]?.user?.token ?? "";
  const expectedSuffix = `/connect/${leaseId}`;
  const expectedContextName = `kobe-${pool}-${shortLeaseId(leaseId)}`;

  if (!serverUrl.endsWith(expectedSuffix)) {
    throw new Error(`Expected kubeconfig server to end with ${expectedSuffix}, got: ${serverUrl}`);
  }
  if (contextName !== expectedContextName) {
    throw new Error(`Expected kubeconfig context name '${expectedContextName}', got: ${contextName}`);
  }
  if (!token) {
    throw new Error(`Expected kubeconfig user '${expectedContextName}' to include a bearer token`);
  }

  info("Waiting for cluster API discovery...");
  const deadline = Date.now() + connectTimeoutSeconds * 1000;
  let attempt = 0;
  let lastError = "";

  while (Date.now() < deadline) {
    attempt += 1;
    const elapsed = Math.floor((Date.now() - (deadline - connectTimeoutSeconds * 1000)) / 1000);
    const remaining = Math.max(0, Math.ceil((deadline - Date.now()) / 1000));
    const apiProbe = await probeLeasePath("api", token);
    const apisProbe = await probeLeasePath("apis", token);

    if (apiProbe.ok && apisProbe.ok) {
      if (shouldSkipKubectlVerification(serverUrl)) {
        info(
          "Discovery ready. Skipping kubectl verification because local e2e uses an HTTP proxy endpoint and client-go does not send bearer tokens there.",
        );
        released = false;
        return;
      }

      info(`Discovery ready after ${elapsed}s. Verifying kubectl...`);
      const result = await kubectlText(
        kubeconfigPath,
        ["--request-timeout=5s", "get", "namespace", "kube-system", "-o", "name"],
        true,
      );

      if (result.exitCode === 0) {
        info(`Cluster API ready after ${elapsed}s.`);
        console.log(
          JSON.stringify({
            leaseId,
            clusterName,
            kubeconfigPath,
            server: serverUrl,
            ttl,
            endpoint: endpointUrl,
            endpointVersion,
          }),
        );
        return;
      }

      lastError = `kubectl namespace query failed: ${truncate([result.stdout, result.stderr].filter(Boolean).join(" "))}`;
    } else {
      lastError = [
        apiProbe.ok ? "" : `/api ${apiProbe.summary}`,
        apisProbe.ok ? "" : `/apis ${apisProbe.summary}`,
      ]
        .filter(Boolean)
        .join("; ");
    }

    info(`  [${attempt}] ${elapsed}s elapsed, ${remaining}s left - ${lastError || "waiting"}`);
    await Bun.sleep(connectRetrySeconds * 1000);
  }

  errorLine(`Timed out waiting for leased cluster API readiness after ${connectTimeoutSeconds}s`);
  if (lastError) {
    errorLine(`Last readiness error: ${lastError}`);
  }
  await printFailureDiagnostics("proxy discovery did not become ready within the warm-path budget");
  process.exitCode = 1;
}

try {
  await main();
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  errorLine(message);
  process.exitCode = 1;
} finally {
  try {
    await releaseLease();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    errorLine(`Failed to release lease ${leaseId}: ${message}`);
    process.exitCode = 1;
  }
}
