// Provision→Ready→restart→recycle CI smoke gate for the kobe operator's k3s
// backend.
//
// Unlike test-smoke.ts (which leases through the kobe HTTP proxy and short-
// circuits kubectl verification for local NodePort endpoints), this gate
// talks DIRECTLY to the HOST kind cluster via `kubectl --context kind-<cluster>`
// and asserts guest readiness from the host's ClusterInstance/StatefulSet
// status. There is intentionally no `shouldSkipKubectlVerification` path here.
//
// It exists because three regressions reached prod that unit tests cannot see:
//
//   (A) the k3s readiness probe was changed to an HTTPS GET on /readyz, which
//       k3s answers with 401 to an unauthenticated kubelet probe → the server
//       pod never goes Ready → the instance never reaches Ready and recycles
//       forever. Assertion (A) below provisions a REAL single-server k3s
//       cluster (via the e2e-k3s pool's scaling.minReady=1 warm member) and
//       fails if it does not reach `status.phase == Ready` with the server
//       StatefulSet reporting `readyReplicas >= 1` inside the budget.
//
//   (B) the k3s server kept its node password at /etc/rancher/node/password —
//       the container's overlay rw layer, which the kubelet discards whenever
//       it rebuilds a container — while the datastore holding that password's
//       hash lived on the `data` volume, which survives a container restart.
//       So the FIRST transient restart left the hash intact but rolled a fresh
//       password, k3s rejected its own node with
//       `NodePasswordValidationFailed: hash does not match`, and because the
//       file is regenerated on every attempt the retry never converged: one
//       restart bricked the control plane permanently (#145). Assertion (B)
//       below restarts the server container and fails unless the cluster comes
//       back and STAYS back.
//
//       Note the shape of this one, because it generalizes: nothing was
//       mis-written, something was merely absent from the pod spec, so no
//       assertion about what the spec CONTAINS could have failed. Only
//       crossing the restart boundary exposes it. Treat (B) as the guard for
//       that whole class — any guest state that must outlive a container
//       restart but sits on the overlay — not just for node passwords.
//
//   (C) the k3s backend deleted a PodDisruptionBudget on every recycle, but
//       the Helm chart's ClusterRole lacked the `policy/poddisruptionbudgets`
//       grant. RBAC is checked before existence, so even single-server
//       instances (which never had a PDB) got 403 Forbidden on delete; the
//       instance-cleanup finalizer was never released and the pool wedged in
//       Recycling forever. Assertion (C) below deletes the ClusterInstance and
//       fails unless it is ACTUALLY GONE inside the budget (not merely that the
//       delete call returned), AND that no orphaned `data-<name>-server-*` PVC
//       is left behind (the #154 PVC-reaping path).
//
// The operator under test is installed via the REAL Helm chart (charts/kobe),
// so its real rbac.yaml is in effect — a reverted PDB grant would 403 here.

const cluster = Bun.env.E2E_CLUSTER ?? "e2e-kobe";
const namespace = Bun.env.E2E_NAMESPACE ?? "kobe-system";
const pool = Bun.env.E2E_K3S_POOL ?? "e2e-k3s";
const context = `kind-${cluster}`;
const poolLabel = `kobe.kunobi.ninja/pool=${pool}`;

const readyTimeoutSeconds = parsePositiveInt(
  Bun.env.K3S_READY_TIMEOUT_SECONDS ?? "600",
  "K3S_READY_TIMEOUT_SECONDS",
);
const recycleTimeoutSeconds = parsePositiveInt(
  Bun.env.K3S_RECYCLE_TIMEOUT_SECONDS ?? "90",
  "K3S_RECYCLE_TIMEOUT_SECONDS",
);
// A restart reuses the `data` volume (certs, DB and images are all still
// there), so recovery is far cheaper than the cold provision budget above.
const restartTimeoutSeconds = parsePositiveInt(
  Bun.env.K3S_RESTART_TIMEOUT_SECONDS ?? "300",
  "K3S_RESTART_TIMEOUT_SECONDS",
);
// How long the server must hold Ready after recovering. Without it the gate
// would pass on a cluster that merely oscillates: #145's signature was a
// restart count climbing 1→2→3→4, and the very first recovery looks healthy.
const restartSettleSeconds = parsePositiveInt(
  Bun.env.K3S_RESTART_SETTLE_SECONDS ?? "45",
  "K3S_RESTART_SETTLE_SECONDS",
);
const pollRetrySeconds = parsePositiveInt(
  Bun.env.K3S_POLL_RETRY_SECONDS ?? "5",
  "K3S_POLL_RETRY_SECONDS",
);

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

// kubectl against the HOST kind cluster (not the leased guest).
async function kubectl(
  args: string[],
  options?: { allowFailure?: boolean },
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  return runCommand(["kubectl", "--context", context, ...args], options);
}

async function kubectlJson<T>(args: string[]): Promise<T> {
  const { stdout } = await kubectl([...args, "-o", "json"]);
  return JSON.parse(stdout) as T;
}

type InstanceList = {
  items: Array<{
    metadata: { name?: string; deletionTimestamp?: string };
    status?: { phase?: string };
  }>;
};

async function listInstances(): Promise<InstanceList["items"]> {
  const list = await kubectlJson<InstanceList>([
    "get",
    "clusterinstances.kobe.kunobi.ninja",
    "-n",
    namespace,
    "-l",
    poolLabel,
  ]);
  return list.items ?? [];
}

// `readyReplicas` for the `<name>-server` StatefulSet. Missing/0 ⇒ 0.
async function serverReadyReplicas(instanceName: string): Promise<number> {
  const { stdout, exitCode } = await kubectl(
    [
      "get",
      "statefulset",
      "-n",
      namespace,
      `${instanceName}-server`,
      "-o",
      "jsonpath={.status.readyReplicas}",
    ],
    { allowFailure: true },
  );
  if (exitCode !== 0) return 0;
  const parsed = Number.parseInt(stdout.trim(), 10);
  return Number.isFinite(parsed) ? parsed : 0;
}

// Orphaned volumeClaimTemplate PVCs for a recycled instance: exactly
// `data-<name>-server-<ordinal>` (matches src/backend/k3s.rs is_server_data_pvc).
async function orphanedServerPvcs(instanceName: string): Promise<string[]> {
  const { stdout, exitCode } = await kubectl(
    [
      "get",
      "pvc",
      "-n",
      namespace,
      "-o",
      "jsonpath={range .items[*]}{.metadata.name}{\"\\n\"}{end}",
    ],
    { allowFailure: true },
  );
  if (exitCode !== 0) return [];
  const prefix = `data-${instanceName}-server-`;
  return stdout
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .filter((name) => {
      if (!name.startsWith(prefix)) return false;
      const ordinal = name.slice(prefix.length);
      // Numeric ordinal only — mirrors is_server_data_pvc so a *different*
      // cluster literally named `<name>-server` can't false-match.
      return /^[0-9]+$/.test(ordinal);
    });
}

async function printDiagnostics(reason: string, instanceName?: string): Promise<void> {
  errorLine("");
  errorLine("k3s smoke diagnostics");
  errorLine(`  reason     ${reason}`);
  errorLine(`  context    ${context}`);
  errorLine(`  namespace  ${namespace}`);
  errorLine(`  pool       ${pool}`);
  errorLine(`  instance   ${instanceName ?? "-"}`);

  errorLine("");
  errorLine("  clusterpool");
  const poolDump = await kubectl(
    ["get", "clusterpool.kobe.kunobi.ninja", "-n", namespace, pool, "-o", "wide"],
    { allowFailure: true },
  );
  errorLine(indent(poolDump.stdout || poolDump.stderr || "(none)"));

  errorLine("");
  errorLine("  clusterinstances");
  const instDump = await kubectl(
    ["get", "clusterinstances.kobe.kunobi.ninja", "-n", namespace, "-l", poolLabel, "-o", "wide"],
    { allowFailure: true },
  );
  errorLine(indent(instDump.stdout || instDump.stderr || "(none)"));

  if (instanceName) {
    errorLine("");
    errorLine(`  describe clusterinstance/${instanceName}`);
    const describe = await kubectl(
      ["describe", "clusterinstance.kobe.kunobi.ninja", "-n", namespace, instanceName],
      { allowFailure: true },
    );
    errorLine(indent(describe.stdout || describe.stderr || "(none)"));

    errorLine("");
    errorLine(`  statefulset/${instanceName}-server`);
    const sts = await kubectl(
      ["get", "statefulset", "-n", namespace, `${instanceName}-server`, "-o", "wide"],
      { allowFailure: true },
    );
    errorLine(indent(sts.stdout || sts.stderr || "(none)"));

    errorLine("");
    errorLine(`  pods for ${instanceName}`);
    const pods = await kubectl(
      ["get", "pods", "-n", namespace, "-l", `kobe.kunobi.ninja/cluster=${instanceName}`, "-o", "wide"],
      { allowFailure: true },
    );
    errorLine(indent(pods.stdout || pods.stderr || "(none)"));
  }

  errorLine("");
  errorLine("  operator logs (tail)");
  const logs = await kubectl(
    [
      "logs",
      "-n",
      namespace,
      "-l",
      "app.kubernetes.io/name=kobe",
      "--tail",
      "120",
      "--all-containers",
    ],
    { allowFailure: true },
  );
  errorLine(indent(logs.stdout || logs.stderr || "(none)"));
}

function indent(text: string): string {
  return text
    .split("\n")
    .map((line) => (line.length ? `    ${line}` : line))
    .join("\n");
}

// ── (A) provision → Ready ──────────────────────────────────────────────────
// Poll until SOME ClusterInstance labeled pool=e2e-k3s has
// status.phase == "Ready" AND its <name>-server StatefulSet reports
// readyReplicas >= 1, within readyTimeoutSeconds. A reverted /readyz probe
// 401s → the server pod never becomes Ready → readyReplicas stays 0 → the
// instance never reaches Ready → this times out and FAILS the gate.
async function waitForReadyInstance(): Promise<string> {
  info(`(A) Waiting up to ${readyTimeoutSeconds}s for a Ready k3s instance in pool '${pool}'...`);
  const deadline = Date.now() + readyTimeoutSeconds * 1000;
  let attempt = 0;
  let lastSummary = "no instances observed yet";

  while (Date.now() < deadline) {
    attempt += 1;
    const instances = await listInstances();

    for (const instance of instances) {
      const name = instance.metadata.name;
      if (!name) continue;
      const phase = instance.status?.phase ?? "(none)";
      if (phase === "Ready") {
        const readyReplicas = await serverReadyReplicas(name);
        if (readyReplicas >= 1) {
          const elapsed = Math.floor((Date.now() - (deadline - readyTimeoutSeconds * 1000)) / 1000);
          info(
            `(A) PASS: instance '${name}' reached Ready with ${name}-server readyReplicas=${readyReplicas} after ~${elapsed}s.`,
          );
          return name;
        }
        lastSummary = `instance '${name}' phase=Ready but ${name}-server readyReplicas=${readyReplicas} (<1)`;
      } else {
        lastSummary = `instance '${name}' phase=${phase}`;
      }
    }

    const remaining = Math.max(0, Math.ceil((deadline - Date.now()) / 1000));
    info(`  [${attempt}] ${remaining}s left - ${lastSummary}`);
    await Bun.sleep(pollRetrySeconds * 1000);
  }

  errorLine(
    `(A) FAIL: no k3s instance in pool '${pool}' reached Ready (phase=Ready + ${"<name>"}-server readyReplicas>=1) within ${readyTimeoutSeconds}s.`,
  );
  errorLine(`     Last observed: ${lastSummary}`);
  errorLine(
    "     This is the readiness-probe regression class: a /readyz probe 401s, so the server pod never goes Ready.",
  );
  await printDiagnostics("instance did not reach Ready within the provisioning budget");
  process.exit(1);
}

// ── (B) restart → recovers, and STAYS recovered ──────────────────────────────
// The server pod's status, as far as this gate cares: does it exist, is it
// Ready, and how many times has the k3s-server container been rebuilt.
type ServerPodStatus = {
  exists: boolean;
  ready: boolean;
  restartCount: number;
};

async function serverPodStatus(instanceName: string): Promise<ServerPodStatus> {
  const absent: ServerPodStatus = { exists: false, ready: false, restartCount: 0 };
  const { stdout, exitCode } = await kubectl(
    ["get", "pod", "-n", namespace, `${instanceName}-server-0`, "-o", "json"],
    { allowFailure: true },
  );
  if (exitCode !== 0) return absent;

  let pod: {
    status?: {
      conditions?: Array<{ type?: string; status?: string }>;
      containerStatuses?: Array<{ name?: string; restartCount?: number }>;
    };
  };
  try {
    pod = JSON.parse(stdout);
  } catch {
    return absent;
  }

  const ready = (pod.status?.conditions ?? []).some(
    (condition) => condition.type === "Ready" && condition.status === "True",
  );
  const server = (pod.status?.containerStatuses ?? []).find(
    (container) => container.name === "k3s-server",
  );
  return { exists: true, ready, restartCount: server?.restartCount ?? 0 };
}

// Restart the k3s-server CONTAINER (not the pod) and assert the cluster comes
// back and holds. Container-scoped is the whole point: the kubelet rebuilds the
// container filesystem from the image while the pod's `data` volume survives
// untouched — precisely the asymmetry that #145 turned into a permanent
// outage. Deleting the pod instead would discard the emptyDir too and hide it.
async function restartAndAssertRecovers(instanceName: string): Promise<void> {
  const pod = `${instanceName}-server-0`;
  info("");
  info(`(B) Restarting the k3s-server container in '${pod}' and asserting it recovers...`);

  const before = await serverPodStatus(instanceName);
  if (!before.exists) {
    errorLine(`(B) FAIL: server pod '${pod}' not found; cannot exercise the restart path.`);
    await printDiagnostics("server pod missing before restart", instanceName);
    process.exit(1);
  }
  info(`(B) Baseline: ready=${before.ready} restartCount=${before.restartCount}.`);

  // SIGTERM to PID 1 (the k3s server process). NOT SIGKILL: PID 1 inside a
  // namespace only receives signals it has installed a handler for, and the
  // kernel drops an uncaught SIGKILL aimed at it — k3s handles SIGTERM, so
  // this is both deliverable and a realistic restart. The exec itself is
  // EXPECTED to fail (the connection dies with the process), so its exit code
  // proves nothing; the restart count below is the real evidence.
  await kubectl(
    ["exec", "-n", namespace, pod, "-c", "k3s-server", "--", "sh", "-c", "kill 1"],
    { allowFailure: true },
  );

  // 1. The container must actually have been rebuilt, or the rest of this
  //    assertion would pass vacuously against a server that never restarted.
  const restartDeadline = Date.now() + restartTimeoutSeconds * 1000;
  let observed = before;
  while (Date.now() < restartDeadline) {
    observed = await serverPodStatus(instanceName);
    if (observed.exists && observed.restartCount > before.restartCount) break;
    await Bun.sleep(pollRetrySeconds * 1000);
  }
  if (observed.restartCount <= before.restartCount) {
    errorLine(
      `(B) FAIL: k3s-server in '${pod}' never restarted within ${restartTimeoutSeconds}s ` +
        `(restartCount stuck at ${observed.restartCount}); the gate could not exercise the restart path.`,
    );
    await printDiagnostics("server container did not restart", instanceName);
    process.exit(1);
  }
  const induced = observed.restartCount;
  info(`(B) Container rebuilt (restartCount ${before.restartCount} → ${induced}); waiting for Ready...`);

  // 2. It must come back: pod Ready AND the StatefulSet counting it ready.
  while (Date.now() < restartDeadline) {
    const status = await serverPodStatus(instanceName);
    if (status.ready && (await serverReadyReplicas(instanceName)) >= 1) {
      info(`(B) Server recovered after the restart.`);
      break;
    }
    const remaining = Math.max(0, Math.ceil((restartDeadline - Date.now()) / 1000));
    info(`  ${remaining}s left - ready=${status.ready} restartCount=${status.restartCount}`);
    await Bun.sleep(pollRetrySeconds * 1000);
  }
  const recovered = await serverPodStatus(instanceName);
  if (!recovered.ready || (await serverReadyReplicas(instanceName)) < 1) {
    errorLine(
      `(B) FAIL: '${pod}' did not return to Ready within ${restartTimeoutSeconds}s of a single ` +
        `container restart (restartCount=${recovered.restartCount}).`,
    );
    errorLine(
      "     This is the #145 node-identity class: state the guest must not lose across a container",
    );
    errorLine(
      "     restart (there, /etc/rancher/node/password) is sitting on the container's overlay rw layer",
    );
    errorLine(
      "     while the datastore that must agree with it sits on the `data` volume. The rebuilt container",
    );
    errorLine(
      "     re-registers with fresh state, the server rejects it, and no retry can ever converge.",
    );
    errorLine("     Check the guest's own logs for NodePasswordValidationFailed.");
    await printDiagnostics("server did not recover from a container restart", instanceName);
    process.exit(1);
  }

  // 3. It must STAY back. #145 recovered on the first restart too — it was the
  //    restart AFTER that which never converged, so a gate that stops at the
  //    first Ready would have shipped the bug green.
  info(`(B) Holding for ${restartSettleSeconds}s to prove the recovery is stable...`);
  const settleDeadline = Date.now() + restartSettleSeconds * 1000;
  while (Date.now() < settleDeadline) {
    await Bun.sleep(pollRetrySeconds * 1000);
    const status = await serverPodStatus(instanceName);
    if (status.restartCount > induced) {
      errorLine(
        `(B) FAIL: '${pod}' restarted again after recovering (restartCount ${induced} → ` +
          `${status.restartCount}) — the server is crashlooping, not healthy.`,
      );
      errorLine(
        "     A cluster that oscillates is exactly the #145 signature (restart count climbing 1→2→3→4).",
      );
      await printDiagnostics("server crashlooped after restarting", instanceName);
      process.exit(1);
    }
  }

  info(`(B) PASS: server survived a container restart and held Ready for ${restartSettleSeconds}s.`);
}

// ── (C) recycle → clean teardown ─────────────────────────────────────────────
// Delete the ClusterInstance, then assert it is ACTUALLY GONE within
// recycleTimeoutSeconds (the delete call returning is NOT enough — the
// instance-cleanup finalizer must be released), and that no orphaned
// data-<name>-server-* PVC survives. A missing policy/poddisruptionbudgets
// RBAC grant makes the backend delete() 403 (if it propagates the error), the
// finalizer is never removed, and the instance lingers in Recycling forever →
// this times out and FAILS.
async function recycleAndAssertGone(instanceName: string): Promise<void> {
  // Capture the doomed object's UID first: the pool controller replaces a
  // deleted member within milliseconds, and on an otherwise-empty pool the
  // replacement REUSES the lowest free index — i.e. the SAME NAME. A
  // name-based "is it gone" poll then sees the healthy replacement forever
  // and times out even though teardown worked perfectly (#34, round 2). The
  // UID is the identity of the old object: same name + different UID ⇒ the
  // old instance is gone and what we see is its replacement.
  const { stdout: uidOut, exitCode: uidExit } = await kubectl(
    [
      "get",
      "clusterinstance.kobe.kunobi.ninja",
      "-n",
      namespace,
      instanceName,
      "-o",
      "jsonpath={.metadata.uid}",
    ],
    { allowFailure: true },
  );
  const doomedUid = uidExit === 0 ? uidOut.trim() : "";

  info(`(C) Recycling instance '${instanceName}' (uid=${doomedUid || "?"}) via kubectl delete...`);
  // --wait=false: do NOT block on the finalizer here; the assertion below is
  // exactly that the finalizer is eventually released and the object vanishes.
  await kubectl(
    [
      "delete",
      "clusterinstance.kobe.kunobi.ninja",
      "-n",
      namespace,
      instanceName,
      "--wait=false",
      "--ignore-not-found",
    ],
    { allowFailure: true },
  );

  info(`(C) Waiting up to ${recycleTimeoutSeconds}s for instance '${instanceName}' to be fully gone...`);
  const deadline = Date.now() + recycleTimeoutSeconds * 1000;
  let attempt = 0;
  let lastPhase = "(unknown)";

  const assertNoOrphanedPvcs = async (goneHow: string): Promise<void> => {
    const orphans = await orphanedServerPvcs(instanceName);
    if (orphans.length > 0) {
      errorLine(
        `(C) FAIL: instance '${instanceName}' was deleted but orphaned PVC(s) remain: ${orphans.join(", ")}`,
      );
      errorLine("     This is the #154 PVC-reaping regression class.");
      await printDiagnostics("recycle left orphaned server data PVCs", instanceName);
      process.exit(1);
    }
    const elapsed = Math.floor((Date.now() - (deadline - recycleTimeoutSeconds * 1000)) / 1000);
    info(
      `(C) PASS: instance '${instanceName}' is fully gone (${goneHow}) after ~${elapsed}s and no data-${instanceName}-server-* PVC was orphaned.`,
    );
  };

  while (Date.now() < deadline) {
    attempt += 1;
    const { stdout, exitCode } = await kubectl(
      [
        "get",
        "clusterinstance.kobe.kunobi.ninja",
        "-n",
        namespace,
        instanceName,
        "-o",
        "jsonpath={.metadata.uid}{\"/\"}{.status.phase}",
      ],
      { allowFailure: true },
    );

    if (exitCode !== 0) {
      // get failed ⇒ the object is gone (NotFound).
      await assertNoOrphanedPvcs("NotFound");
      return;
    }

    const [uid, phase] = stdout.trim().split("/", 2);
    if (doomedUid && uid && uid !== doomedUid) {
      // Same name, different UID: the old object is fully deleted and the
      // pool has already created its replacement. Teardown succeeded.
      await assertNoOrphanedPvcs(`replaced by new instance uid=${uid}`);
      return;
    }

    lastPhase = phase?.trim() || "(empty)";
    const remaining = Math.max(0, Math.ceil((deadline - Date.now()) / 1000));
    info(`  [${attempt}] ${remaining}s left - instance still present, phase=${lastPhase}`);
    await Bun.sleep(pollRetrySeconds * 1000);
  }

  errorLine(
    `(C) FAIL: instance '${instanceName}' was not fully removed within ${recycleTimeoutSeconds}s (last phase=${lastPhase}).`,
  );
  errorLine(
    "     This is the RBAC-403 recycle-wedge class: a missing policy/poddisruptionbudgets grant makes the",
  );
  errorLine(
    "     backend delete() 403, the instance-cleanup finalizer is never released, and the instance lingers in Recycling.",
  );
  await printDiagnostics("instance was not fully removed after recycle", instanceName);
  process.exit(1);
}

async function main(): Promise<void> {
  info(`k3s smoke gate: context='${context}' namespace='${namespace}' pool='${pool}'`);

  // Sanity: the pool must exist (the e2e harness applies it).
  const poolCheck = await kubectl(
    ["get", "clusterpool.kobe.kunobi.ninja", "-n", namespace, pool],
    { allowFailure: true },
  );
  if (poolCheck.exitCode !== 0) {
    errorLine(`🚫 ClusterPool '${pool}' not found in namespace '${namespace}' on context '${context}'.`);
    errorLine("   Run the e2e harness first: bun run ./hack/e2e.ts up [--cluster NAME]");
    await printDiagnostics("pool not found");
    process.exit(1);
  }

  const instanceName = await waitForReadyInstance();
  await restartAndAssertRecovers(instanceName);
  await recycleAndAssertGone(instanceName);

  info("");
  info("k3s smoke gate PASSED (provision → Ready → survives restart → clean recycle).");
}

try {
  await main();
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  errorLine(message);
  process.exitCode = 1;
}
