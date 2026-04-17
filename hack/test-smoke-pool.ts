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

const [pool = "ci-small", ttl = "2m", ...kobeArgs] = Bun.argv.slice(2);

const leaseWaitTimeout = Bun.env.LEASE_WAIT_TIMEOUT ?? "15s";
const warmTarget = parsePositiveInt(Bun.env.WARM_TARGET ?? "2", "WARM_TARGET");
const refillTimeoutSeconds = parsePositiveInt(
  Bun.env.POOL_RECOVERY_TIMEOUT_SECONDS ?? "60",
  "POOL_RECOVERY_TIMEOUT_SECONDS",
);
const refillRetrySeconds = parsePositiveInt(
  Bun.env.POOL_RECOVERY_RETRY_SECONDS ?? "2",
  "POOL_RECOVERY_RETRY_SECONDS",
);
const minEndpointVersion = Bun.env.MIN_ENDPOINT_VERSION ?? "v0.8.11";

let leaseId = "";
let released = false;
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

function versionGte(left: string, right: string): boolean {
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

function renderPool(poolStatus: PoolStatus): string {
  return `ready=${poolStatus.ready} leased=${poolStatus.leased} creating=${poolStatus.creating} recycling=${poolStatus.recycling ?? 0} queue=${poolStatus.queueDepth}`;
}

function info(message = ""): void {
  console.log(message);
}

function errorLine(message = ""): void {
  console.error(message);
}

async function runCommand(
  cmd: string[],
  options?: { allowFailure?: boolean },
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  const proc = Bun.spawn({
    cmd,
    stdin: "ignore",
    stdout: "pipe",
    stderr: "pipe",
    cwd: process.cwd(),
  });

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
  const { stdout } = await runCommand(["cargo", "run", "--quiet", "--bin", "kobe", "--", ...kobeArgs, ...args]);
  return JSON.parse(stdout) as T;
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

function activeLeaseCount(status: KobeStatus, profile: string): number {
  return (status.leases ?? []).filter((lease) => lease.profile === profile && lease.phase !== "recycling").length;
}

async function printPoolDiagnostics(reason: string): Promise<void> {
  const status = await fetchStatus();
  const poolAfter = selectPool(status, pool);
  const matchingLease = leaseId ? (status.leases ?? []).find((lease) => lease.id === leaseId) : undefined;
  const activeLeases = activeLeaseCount(status, pool);

  errorLine("");
  errorLine("Pool smoke diagnostics");
  errorLine(`  reason     ${reason}`);
  errorLine(`  endpoint   ${endpointUrl || "-"} (${endpointVersion || "-"})`);
  errorLine(`  target     ${targetName || "-"}`);
  errorLine(`  lease      ${leaseId || "-"}`);
  errorLine("");
  errorLine("  pool");
  if (poolBefore) {
    errorLine(`    before  ${renderPool(poolBefore)}`);
  }
  errorLine(`    after   ${renderPool(poolAfter)}`);
  errorLine("");
  errorLine("  expectations");
  errorLine(`    warm target         ${warmTarget}`);
  errorLine(`    active leases       >= 1`);
  errorLine(`    refill in progress  ready + creating >= ${warmTarget}`);
  errorLine(`    refill settled      ready >= ${warmTarget}`);
  errorLine(`    observed leases     ${activeLeases}`);
  if (matchingLease) {
    errorLine("");
    errorLine("  lease status");
    errorLine(
      `    ${matchingLease.id} phase=${matchingLease.phase ?? "-"} cluster=${matchingLease.clusterName ?? "-"} profile=${matchingLease.profile ?? "-"}`,
    );
  }
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
  const leasesBefore = activeLeaseCount(status, pool);

  info(
    `Kobe target='${targetName}' endpoint='${endpointUrl}' cli=${cliVersion} endpointVersion=${endpointVersion}`,
  );

  if (!endpointVersion) {
    throw new Error("🚫 Endpoint version is missing.\n   Refusing to run pool smoke test without a compatibility check.");
  }
  if (!versionGte(endpointVersion, minEndpointVersion)) {
    throw new Error(
      `🚫 Endpoint ${endpointVersion} is too old for this pool smoke test.\n   Expected at least ${minEndpointVersion}.`,
    );
  }
  if (poolBefore.ready <= 0) {
    throw new Error(
      `🚫 Pool '${pool}' is not warm.\n   Expected at least one ready cluster.\n   Current state: ${renderPool(poolBefore)}`,
    );
  }

  info(`Pool '${pool}': ${renderPool(poolBefore)}`);
  info(`Requesting lease from pool '${pool}' (ttl=${ttl}, lease wait timeout=${leaseWaitTimeout})...`);

  const lease = await kobeJson<LeaseResponse>([
    "lease",
    pool,
    "--ttl",
    ttl,
    "--wait-timeout",
    leaseWaitTimeout,
    "-o",
    "json",
  ]);

  leaseId = lease.id;
  if (!leaseId) {
    throw new Error("Lease response did not include an id");
  }

  info(`Lease acquired: ${leaseId}`);
  info("Waiting for pool refill to start...");

  const refillStartedDeadline = Date.now() + 15_000;
  while (Date.now() < refillStartedDeadline) {
    const currentStatus = await fetchStatus();
    const currentPool = selectPool(currentStatus, pool);
    const currentLeases = activeLeaseCount(currentStatus, pool);

    if (currentLeases >= leasesBefore + 1 && currentPool.ready + currentPool.creating >= warmTarget) {
      info(
        `Refill started: leases=${currentLeases} ready=${currentPool.ready} creating=${currentPool.creating}`,
      );
      break;
    }

    await Bun.sleep(1_000);
  }

  info(`Waiting for pool to settle back to warm target ${warmTarget}...`);
  const settleDeadline = Date.now() + refillTimeoutSeconds * 1000;
  let lastPool = poolBefore;
  let lastLeases = leasesBefore;
  let attempt = 0;

  while (Date.now() < settleDeadline) {
    attempt += 1;
    const currentStatus = await fetchStatus();
    const currentPool = selectPool(currentStatus, pool);
    const currentLeases = activeLeaseCount(currentStatus, pool);
    lastPool = currentPool;
    lastLeases = currentLeases;

    if (currentLeases >= leasesBefore + 1 && currentPool.ready >= warmTarget) {
      info(
        `Pool converged after ${attempt * refillRetrySeconds}s: ${renderPool(currentPool)} activeLeases=${currentLeases}`,
      );
      console.log(
        JSON.stringify({
          leaseId,
          pool,
          ttl,
          endpoint: endpointUrl,
          endpointVersion,
          before: poolBefore,
          after: currentPool,
          activeLeases: currentLeases,
        }),
      );
      return;
    }

    info(
      `  [${attempt}] waiting for warm refill - ${renderPool(currentPool)} activeLeases=${currentLeases}`,
    );
    await Bun.sleep(refillRetrySeconds * 1000);
  }

  errorLine(
    `Timed out waiting for pool '${pool}' to recover warm capacity after ${refillTimeoutSeconds}s`,
  );
  errorLine(
    `Last observed state: ${renderPool(lastPool)} activeLeases=${lastLeases}`,
  );
  await printPoolDiagnostics("pool did not converge back to warm target after acquiring a lease");
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
