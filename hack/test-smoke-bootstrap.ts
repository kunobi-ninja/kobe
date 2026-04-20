type KobeStatus = {
  cliVersion: string;
  target?: string | null;
  endpoint?: string | null;
  endpointVersion?: string | null;
  pools: PoolStatus[];
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
  kubeconfigPath?: string | null;
  clusterName?: string | null;
};

type KubeconfigView = {
  clusters: Array<{ name: string; cluster: { server: string } }>;
  contexts: Array<{ name: string }>;
  users: Array<{ name: string; user: { token?: string } }>;
};

const [
  pool = "e2e-vkobe-etcd-bootstrap",
  namespace = "default",
  resourceKind = "configmap",
  resourceName = "bootstrap-marker",
  ttl = "2m",
  ...kobeArgs
] = Bun.argv.slice(2);

const leaseWaitTimeout = Bun.env.LEASE_WAIT_TIMEOUT ?? "15s";
const warmupTimeoutSeconds = parsePositiveInt(
  Bun.env.POOL_WARMUP_TIMEOUT_SECONDS ?? "30",
  "POOL_WARMUP_TIMEOUT_SECONDS",
);
const warmupRetrySeconds = parsePositiveInt(
  Bun.env.POOL_WARMUP_RETRY_SECONDS ?? "2",
  "POOL_WARMUP_RETRY_SECONDS",
);

let leaseId = "";
let released = false;
let kubeconfigPath = "";
let serverUrl = "";

function parsePositiveInt(value: string, name: string): number {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive integer, got '${value}'`);
  }
  return parsed;
}

function info(message = ""): void {
  console.log(message);
}

async function runCommand(
  cmd: string[],
  options?: { allowFailure?: boolean },
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  const proc = Bun.spawn({
    cmd,
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

async function kubectlJson<T>(kubeconfig: string, args: string[]): Promise<T> {
  const { stdout } = await runCommand(["kubectl", "--kubeconfig", kubeconfig, ...args]);
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

function renderPool(poolStatus: PoolStatus): string {
  return `ready=${poolStatus.ready} leased=${poolStatus.leased} creating=${poolStatus.creating} recycling=${poolStatus.recycling ?? 0} queue=${poolStatus.queueDepth}`;
}

async function waitForWarmPool(name: string): Promise<PoolStatus> {
  let current = selectPool(await fetchStatus(), name);
  if (current.ready > 0) return current;

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
    `Pool '${name}' did not become warm within ${warmupTimeoutSeconds}s.\nLast state: ${renderPool(current)}`,
  );
}

async function releaseLease(): Promise<void> {
  if (!leaseId || released) return;
  info(`Releasing lease ${leaseId}...`);
  await kobeJson(["release", leaseId, "-o", "json"]);
  released = true;
}

async function authedJson(path: string, token: string): Promise<unknown> {
  const response = await fetch(`${serverUrl}/${path}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!response.ok) {
    throw new Error(`GET /${path} returned HTTP ${response.status}: ${await response.text()}`);
  }
  return response.json();
}

async function main(): Promise<void> {
  info("Checking bootstrap pool state...");
  const status = await fetchStatus();
  info(
    `Kobe target='${status.target ?? "default"}' endpoint='${status.endpoint ?? "-"}' cli=${status.cliVersion} endpointVersion=${status.endpointVersion ?? "-"}`,
  );
  const warmPool = await waitForWarmPool(pool);
  info(`Pool '${pool}': ${renderPool(warmPool)}`);

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
  kubeconfigPath = lease.kubeconfigPath ?? "";
  if (!leaseId || !kubeconfigPath) {
    throw new Error("Lease response did not include id and kubeconfigPath");
  }

  info(`Lease acquired: ${leaseId}`);
  const kubeconfig = await kubectlJson<KubeconfigView>(kubeconfigPath, ["config", "view", "--raw", "-o", "json"]);
  serverUrl = kubeconfig.clusters[0]?.cluster.server ?? "";
  const token = kubeconfig.users[0]?.user?.token ?? "";
  if (!serverUrl || !token) {
    throw new Error("Lease kubeconfig did not contain expected server URL and token");
  }

  info(`Verifying bootstrap namespace '${namespace}'...`);
  await authedJson(`api/v1/namespaces/${namespace}`, token);
  info(`Verifying bootstrap ${resourceKind} '${namespace}/${resourceName}'...`);
  const resourcePath = `api/v1/namespaces/${namespace}/${resourceKind}s/${resourceName}`;
  await authedJson(resourcePath, token);

  info(`Bootstrap verified for pool '${pool}'.`);
}

try {
  await main();
} finally {
  await releaseLease();
}
