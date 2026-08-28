import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { join, relative } from "node:path";

const DEFAULT_CLUSTER = "e2e-kobe";
const DEFAULT_NAMESPACE = "kobe-system";
const DEFAULT_RELEASE = "kobe";
const DEFAULT_IMAGE_TAG = "local";
const TEMP_DIR = `${process.cwd()}/.tmp/e2e-images`;
const KIND_CONFIG = `${process.cwd()}/.tmp/e2e-kind.yaml`;
const STATE_FILE = `${process.cwd()}/.tmp/e2e-state.json`;
const DEMO_TOKEN = "e2e-dev-token";
const DEMO_TOKEN_SECRET = "e2e-local-token";
const DEMO_POLICY = "e2e-local-token";
const DEMO_OTHER_TOKEN = "e2e-other-token";
const DEMO_OTHER_TOKEN_SECRET = "e2e-other-token";
const DEMO_OTHER_POLICY = "e2e-other-token";
const DEMO_SANDBOX_POOL_MANAGEMENT = "e2e-sandbox-management-trusted";
const DEMO_SANDBOX_POOL_CHILD = "e2e-sandbox-child-k3s-trusted";
// The default `kobe` release publishes this retained managed BootstrapConfig.
// The E2E harness consumes the chart output instead of maintaining a second
// operator-authored runtime bundle.
const DEMO_SANDBOX_BOOTSTRAP = "kobe-agent-sandbox-v1-0-0";
const SANDBOX_REGISTRY_IMAGE = "registry:2.8.3@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373";
const SANDBOX_REGISTRY_LABEL = "kobe.kunobi.ninja/e2e-sandbox-registry";
const DEMO_K0S_POOL = "e2e-k0s";
const DEMO_K0S_VERSION = "v1.35.1+k0s.0";
// k0s guest image the k0s backend launches for DEMO_K0S_VERSION.
//
// DERIVED, not hand-written: `k0s_image()` (src/backend/k0s.rs) builds the tag
// as `version.replace('+', "-")` — the `+` build-metadata separator is not a
// legal OCI tag character. Applying the same transform here means a version
// bump cannot silently desync the two. A hand-pinned constant could, and the
// failure would be quiet: the preload would fetch an image nothing launches,
// the guest would pull from the registry inside kind at provision time, and
// that uncontrolled fetch would land back inside the pool's creatingTimeout —
// exactly the problem pre-loading exists to remove.
const K0S_GUEST_IMAGE = `k0sproject/k0s:${DEMO_K0S_VERSION.replace("+", "-")}`;
// Single-server k3s pool exercised by the provision→Ready→recycle CI smoke
// gate (hack/test-e2e-k3s.ts). Uses embedded SQLite (no shared datastore in
// kind) and warms one member via scaling.minReady=1. The matching guest image
// is pre-loaded into the kind nodes (see K3S_GUEST_IMAGE) so provisioning
// stays inside the smoke gate's wait_ready budget.
const DEMO_K3S_POOL = "e2e-k3s";
const DEMO_K3S_VERSION = "v1.31.3+k3s1";
// k3s guest image the k3s backend launches for `version: v1.31.3+k3s1`.
// The backend rewrites the `+` build-metadata separator to `-` because OCI
// tags forbid `+` (see k3s_image() in src/backend/k3s.rs). Keep this in sync
// with DEMO_K3S_VERSION.
const K3S_GUEST_IMAGE = "rancher/k3s:v1.31.3-k3s1";
const DEMO_VKOBE_ETCD_POOL = "e2e-vkobe-etcd";
const DEMO_VKOBE_BOOTSTRAP_POOL = "e2e-vkobe-etcd-bootstrap";
const DEMO_VKOBE_ETCD_STORE = "e2e-vkobe-store-etcd";
const DEMO_VKOBE_ETCD_BACKEND = "e2e-vkobe-etcd";
const DEMO_VKOBE_KINE_POOL = "e2e-vkobe-kine-sqlite";
const DEMO_VKOBE_KINE_BOOTSTRAP_POOL = "e2e-vkobe-kine-sqlite-bootstrap";
const DEMO_VKOBE_KINE_STORE = "e2e-vkobe-store-kine-sqlite";
const DEMO_VKOBE_KINE_BACKEND = "e2e-vkobe-kine-sqlite";
// vcluster backend: upstream loft-sh/vcluster deployed via Helm
// per-instance. Each instance gets its own host namespace
// `vcluster-<instance>`, which is the cleanup boundary.
const DEMO_VCLUSTER_POOL = "e2e-vcluster";
const DEMO_VCLUSTER_BOOTSTRAP_POOL = "e2e-vcluster-bootstrap";
const DEMO_BOOTSTRAP_CONFIG = "e2e-basic-bootstrap";
const DEMO_BOOTSTRAP_NAMESPACE = "default";
const DEMO_BOOTSTRAP_CONFIGMAP = "bootstrap-marker";
const DEMO_FLUX_BOOTSTRAP_CONFIG = "flux";
const DEMO_FLUX_NAMESPACE = "flux-system";
const DEMO_VKOBE_VERSION = "1.35";
const LOCAL_TARGET = "e2e";
const LOCAL_OTHER_TARGET = "e2e-other";
const LOCAL_ENDPOINT = "http://127.0.0.1:8080";
const LOCAL_NODE_PORT = 30080;
// Where an injected failure's ORIGINAL state is parked until `clear-failure`.
// On disk rather than in memory because the two halves are separate process
// invocations: a conformance scenario injects, asserts, and clears from three
// different `bun run` calls, and an in-memory capture would be gone by the
// second one.
const FAILURE_DIR = `${process.cwd()}/.tmp/e2e-failures`;
const EXECUTION_CRASH_ENV = "KOBE_TEST_EXECUTION_CRASH";
const EXECUTION_CRASH_EXIT_CODE = 86;
const OPERATOR_CONTAINER = "kobe-operator";
// Coordination Lease the operator's leader election holds (src/main.rs).
// Restarting is only half of "restart": the HTTP server answers from any
// replica, but the reconcilers run solely in whichever replica owns this.
const OPERATOR_LEADER_LEASE = "kobe-operator";
// Label the admission ledger stamps on a lease's quota/alias reservations
// (SANDBOX_RESERVATION_LEASE_UID_LABEL in src/api/sandbox.rs). `reap-lease`
// needs it because a quarantined lease's reservations outlive the lease.
const SANDBOX_LEASE_UID_LABEL = "kobe.kunobi.ninja/sandbox-lease-uid";
const SANDBOX_LEDGER_NAMESPACE_LABEL = "kobe.kunobi.ninja/sandbox-ledger=true";
// Label every backend stamps on the resources of one child cluster
// (`cluster_labels` in src/backend/k3s.rs and its k0s/vkobe siblings). It is
// how `inject-failure --kind=child-api-unreachable` finds the Service in front
// of a child API server without knowing which backend built it.
const CHILD_CLUSTER_LABEL = "kobe.kunobi.ninja/cluster";
// Sentinel selector a severed Service is given. Nothing carries this label, so
// the Service resolves to zero endpoints and the child API stops answering —
// while every object behind it stays exactly where it was.
const UNREACHABLE_SELECTOR = { "kobe.kunobi.ninja/e2e-unreachable": "true" };
// The two reads whose 403 the operator treats as DURABLE uncertainty rather
// than a transient error: `claim_absence()` and the child-receipt lookup in
// src/controllers/sandbox.rs. Revoking `get` on exactly these is what makes a
// teardown unverifiable — and therefore what makes quarantine reachable —
// without breaking anything else the operator does.
const UNVERIFIABLE_TEARDOWN_REVOCATIONS: ReadonlyArray<RevocationTarget> = [
  { apiGroup: "extensions.agents.x-k8s.io", resource: "sandboxclaims", verb: "get" },
  { apiGroup: "kobe.kunobi.ninja", resource: "clusterleases", verb: "get" },
];
const REQUIRED_MISE_TOOLS = ["bun", "helm", "kind", "kubectl"];
const FINGERPRINT_INPUTS = [
  "Cargo.toml",
  "Cargo.lock",
  "charts/kobe",
  "docker",
  "docker-bake.hcl",
  "hack/e2e.ts",
  "justfile",
  "mise.toml",
  "src",
];

/// Everything this script can be asked to do.
///
/// `up`/`down` own the environment. The rest exist because #76's matrix needs
/// the target *disturbed* — restarted mid-phase, deliberately broken, driven
/// through a real terminal — and the conformance suite deliberately cannot do
/// any of that: a suite able to break its own target could also mask a break it
/// did not intend.
const COMMANDS = [
  "up",
  "down",
  "sandbox-conformance-preflight",
  "restart-operator",
  "inject-failure",
  "clear-failure",
  "reap-lease",
  "attach-pty",
  "port-forward",
] as const;

type Command = (typeof COMMANDS)[number];

/// Ways the target can be deliberately broken.
///
/// #76 uses the teardown/RBAC/network faults. #82 uses the execution
/// crash windows, each scoped to one exact lease and idempotency key.
const FAILURE_KINDS = [
  "teardown-unverifiable",
  "rbac-revoke",
  "child-api-unreachable",
  "execution-after-running-before-target-reservation",
  "execution-before-spawn",
  "execution-after-spawn-before-ack",
  "execution-after-ack-before-status",
] as const;

type FailureKind = (typeof FAILURE_KINDS)[number];

/// One verb, on one resource, in one API group.
type RevocationTarget = {
  apiGroup: string;
  resource: string;
  verb: string;
};

type Args = {
  command: Command;
  cluster: string;
  namespace: string;
  release: string;
  imageTag: string;
  /// Conformance backend this environment is being brought up for, when it is
  /// known. Only used to decide which guest images are worth pre-loading —
  /// every pool is still applied regardless.
  backend?: string;
  /// Provision the managed runtime, two identities, both Sandbox placements,
  /// and the private workload image needed by the #76 live gate.
  sandboxConformance: boolean;
  /// kubectl context to drive. Defaults to the kind context for `--cluster`,
  /// which is what `up` creates; overridable so the same subcommands work
  /// against a CI cluster that kind did not build.
  kubeContext?: string;
  /// Kobe HTTP endpoint used to confirm the operator is serving again.
  endpoint: string;
  /// SandboxLease to observe, restart at, or reap.
  lease?: string;
  /// Stage that lease must reach before the disturbance is applied.
  waitForStage?: string;
  timeoutSeconds: number;
  failure: FailureKind;
  /// Exact public request key, paired with `lease`, allowed to trigger a crashpoint.
  idempotencyKey?: string;
  revocation: Partial<RevocationTarget>;
  /// ClusterInstance whose child API is to be severed.
  instance?: string;
  /// The `kobe` binary the pty harness drives. A path, not a shell string:
  /// it is passed to the pty as argv[0] and never re-parsed.
  kobeBin: string;
  /// Exact CLI target whose identity opens the upgraded stream.
  cliTarget: string;
  /// Keystroke payloads, in order. Escapes are decoded by `decodeKeystrokes`.
  send: string[];
  sendDelayMs: number;
  settleMs: number;
  /// Substring the attached session must produce for the run to pass.
  expect?: string;
  /// Exit code `kobe attach` must terminate with.
  expectExit?: number;
  /// HTTP status an upgraded port-forward handshake must be refused with.
  expectHttpStatus?: number;
  /// Terminal size applied after `resizeAfter` appears in the transcript.
  resize?: { width: number; height: number };
  /// Transcript marker proving the remote terminal is ready to observe resize.
  resizeAfter?: string;
  /// Pool-declared remote port driven by the port-forward harness.
  remotePort: string;
  /// Argv handed to `kobe attach ... -- <argv>`, after a bare `--`.
  attachArgv: string[];
};

type E2eState = {
  cluster: string;
  namespace: string;
  release: string;
  imageTag: string;
  endpoint: string;
  fingerprint: string;
  backend?: string;
  sandboxConformance: boolean;
  sandboxFixture?: SandboxFixture;
};

export type SandboxFixture = {
  imageRef: string;
  registrySource: string;
  mirrorEndpoint: string;
};

const toolCache = new Map<string, string>();

function info(message = ""): void {
  console.log(message);
}

function step(message: string): void {
  info(`==> ${message}`);
}

function fail(message: string): never {
  console.error(`error: ${message}`);
  process.exit(1);
}

async function runCommand(
  cmd: string[],
  options?: {
    env?: Record<string, string>;
    allowFailure?: boolean;
    step?: string;
    stream?: boolean;
    /** Feed this file to the child's stdin (e.g. piping an image archive
     * into `docker exec -i … ctr images import -`). */
    stdinFile?: string;
  },
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  const stream = options?.stream ?? false;
  const proc = Bun.spawn({
    cmd,
    stdin: options?.stdinFile ? Bun.file(options.stdinFile) : undefined,
    stdout: stream ? "inherit" : "pipe",
    stderr: stream ? "inherit" : "pipe",
    cwd: process.cwd(),
    env: {
      ...process.env,
      ...options?.env,
    },
  });

  const [stdoutBuf, stderrBuf, exitCode] = stream
    ? await Promise.all([Promise.resolve(""), Promise.resolve(""), proc.exited])
    : await Promise.all([
        new Response(proc.stdout).text(),
        new Response(proc.stderr).text(),
        proc.exited,
      ]);

  if (exitCode !== 0 && !options?.allowFailure) {
    const rendered = [stdoutBuf.trim(), stderrBuf.trim()].filter(Boolean).join("\n");
    const prefix = options?.step ? `${options.step}: ` : "";
    throw new Error(prefix + (rendered || `Command failed (${cmd.join(" ")}) with exit code ${exitCode}`));
  }

  return { stdout: stdoutBuf, stderr: stderrBuf, exitCode };
}

async function resolveTool(name: string): Promise<string> {
  const cached = toolCache.get(name);
  if (cached) return cached;

  const fromMise = await runCommand(["mise", "which", name], { allowFailure: true });
  const candidate = fromMise.stdout.trim();
  const resolved = fromMise.exitCode === 0 && candidate ? candidate : name;
  toolCache.set(name, resolved);
  return resolved;
}

async function ensureMiseTools(): Promise<void> {
  step(`Ensuring mise tools (${REQUIRED_MISE_TOOLS.join(", ")})`);
  await runCommand(["mise", "install", ...REQUIRED_MISE_TOOLS], {
    step: "failed to install required mise tools",
  });
}

function collectFiles(path: string): string[] {
  if (!existsSync(path)) return [];

  const stat = statSync(path);
  if (stat.isFile()) return [path];
  if (!stat.isDirectory()) return [];

  const files: string[] = [];
  for (const entry of readdirSync(path, { withFileTypes: true })) {
    files.push(...collectFiles(join(path, entry.name)));
  }
  return files;
}

function computeFingerprint(): string {
  const hash = createHash("sha256");
  const files = FINGERPRINT_INPUTS.flatMap((input) => collectFiles(join(process.cwd(), input))).sort();

  for (const file of files) {
    hash.update(relative(process.cwd(), file));
    hash.update("\0");
    hash.update(readFileSync(file));
    hash.update("\0");
  }

  return hash.digest("hex");
}

function loadState(): E2eState | null {
  if (!existsSync(STATE_FILE)) return null;

  try {
    return JSON.parse(readFileSync(STATE_FILE, "utf8")) as E2eState;
  } catch {
    return null;
  }
}

async function saveState(args: Args, fingerprint: string, sandboxFixture?: SandboxFixture): Promise<void> {
  await runCommand(["mkdir", "-p", `${process.cwd()}/.tmp`], {
    step: "failed to create temp directory for e2e state",
  });
  await Bun.write(
    STATE_FILE,
    JSON.stringify(
      {
        cluster: args.cluster,
        namespace: args.namespace,
        release: args.release,
        imageTag: args.imageTag,
        endpoint: args.endpoint,
        fingerprint,
        backend: args.backend,
        sandboxConformance: args.sandboxConformance,
        sandboxFixture,
      } satisfies E2eState,
      null,
      2,
    ),
  );
}

function clearStateFiles(): void {
  rmSync(STATE_FILE, { force: true });
  rmSync(`${process.cwd()}/.kobe.toml`, { force: true });
}

function canReuseExistingEnvironment(args: Args, fingerprint: string): boolean {
  // The conformance image is served by a run-owned registry outside Kind.
  // Re-observe and republish it on every `up`; a stale state file cannot prove
  // that a fresh child cluster can still pull the fixture.
  if (args.sandboxConformance) return false;
  const state = loadState();
  if (!state) return false;

  return (
    state.cluster === args.cluster &&
    state.namespace === args.namespace &&
    state.release === args.release &&
    state.imageTag === args.imageTag &&
    state.endpoint === args.endpoint &&
    state.fingerprint === fingerprint &&
    state.backend === args.backend &&
    state.sandboxConformance === args.sandboxConformance
  );
}

function isCommand(token: string | undefined): token is Command {
  return COMMANDS.includes(token as Command);
}

function isFailureKind(token: string): token is FailureKind {
  return FAILURE_KINDS.includes(token as FailureKind);
}

export function parseArgs(argv: string[]): Args {
  const args = {
    command: "up" as const,
    cluster: process.env.E2E_CLUSTER ?? DEFAULT_CLUSTER,
    namespace: DEFAULT_NAMESPACE,
    release: DEFAULT_RELEASE,
    imageTag: DEFAULT_IMAGE_TAG,
    endpoint: process.env.KOBE_ENDPOINT ?? LOCAL_ENDPOINT,
    sandboxConformance: false,
    timeoutSeconds: 300,
    failure: "teardown-unverifiable" as const,
    revocation: {},
    kobeBin: process.env.KOBE_BIN ?? "kobe",
    cliTarget: LOCAL_TARGET,
    send: [],
    // Long enough for the attach WebSocket to be established and the CLI to
    // have entered raw mode. Keystrokes written before that are typed into a
    // pty nobody is reading yet and are simply lost — which reads exactly like
    // "the keystroke never reached the workload", the failure this harness
    // exists to detect. Better to spend two seconds than to report it falsely.
    sendDelayMs: 300,
    settleMs: 2000,
    remotePort: "http",
    attachArgv: [],
  } as Args;

  const [maybeCommand, ...rest] = argv;
  const tokens = isCommand(maybeCommand) ? rest : argv;
  if (isCommand(maybeCommand)) {
    args.command = maybeCommand;
  }

  for (let i = 0; i < tokens.length; i += 1) {
    const token = tokens[i];
    const next = tokens[i + 1];

    // Everything after a bare `--` belongs to the attached session, not to
    // this script. Parsing it here would eat the workload's own flags.
    if (token === "--") {
      args.attachArgv = tokens.slice(i + 1);
      break;
    }
    if (token === "--cluster" && next) {
      args.cluster = next;
      i += 1;
      continue;
    }
    if (token === "--namespace" && next) {
      args.namespace = next;
      i += 1;
      continue;
    }
    if (token === "--release" && next) {
      args.release = next;
      i += 1;
      continue;
    }
    if (token === "--image-tag" && next) {
      args.imageTag = next;
      i += 1;
      continue;
    }
    if (token === "--backend" && next) {
      args.backend = next;
      i += 1;
      continue;
    }
    if (token === "--sandbox-conformance") {
      args.sandboxConformance = true;
      continue;
    }
    if (token === "--kube-context" && next) {
      args.kubeContext = next;
      i += 1;
      continue;
    }
    if (token === "--endpoint" && next) {
      args.endpoint = next;
      i += 1;
      continue;
    }
    if (token === "--lease" && next) {
      args.lease = next;
      i += 1;
      continue;
    }
    // `--after-phase` is what #138 wrote; `--wait-for-phase` is what it means.
    // Both accepted so a recipe copied from the issue still runs.
    if ((token === "--wait-for-phase" || token === "--after-phase") && next) {
      args.waitForStage = next;
      i += 1;
      continue;
    }
    if (token === "--timeout" && next) {
      args.timeoutSeconds = parsePositiveInt(next, "--timeout");
      i += 1;
      continue;
    }
    if (token === "--kind" && next) {
      if (!isFailureKind(next)) {
        throw new Error(`unknown failure kind '${next}' (expected one of: ${FAILURE_KINDS.join(", ")})`);
      }
      args.failure = next;
      i += 1;
      continue;
    }
    if (token === "--idempotency-key" && next) {
      args.idempotencyKey = next;
      i += 1;
      continue;
    }
    if (token === "--api-group" && next !== undefined) {
      // Deliberately not `&& next`: the core API group is the empty string,
      // and rejecting it would make every core-resource revocation impossible.
      args.revocation.apiGroup = next;
      i += 1;
      continue;
    }
    if (token === "--resource" && next) {
      args.revocation.resource = next;
      i += 1;
      continue;
    }
    if (token === "--verb" && next) {
      args.revocation.verb = next;
      i += 1;
      continue;
    }
    if (token === "--instance" && next) {
      args.instance = next;
      i += 1;
      continue;
    }
    if (token === "--kobe" && next) {
      args.kobeBin = next;
      i += 1;
      continue;
    }
    if (token === "--target" && next) {
      args.cliTarget = next;
      i += 1;
      continue;
    }
    if (token === "--send" && next !== undefined) {
      args.send.push(next);
      i += 1;
      continue;
    }
    if (token === "--send-delay" && next) {
      args.sendDelayMs = parsePositiveInt(next, "--send-delay");
      i += 1;
      continue;
    }
    if (token === "--settle" && next) {
      args.settleMs = parsePositiveInt(next, "--settle");
      i += 1;
      continue;
    }
    if (token === "--expect" && next !== undefined) {
      args.expect = next;
      i += 1;
      continue;
    }
    if (token === "--expect-exit" && next) {
      args.expectExit = parsePositiveInt(next, "--expect-exit", { allowZero: true });
      i += 1;
      continue;
    }
    if (token === "--expect-http-status" && next) {
      const status = parsePositiveInt(next, "--expect-http-status");
      if (status < 100 || status > 599) {
        throw new Error("--expect-http-status must be between 100 and 599");
      }
      args.expectHttpStatus = status;
      i += 1;
      continue;
    }
    if (token === "--resize" && next) {
      args.resize = parseTerminalSize(next);
      i += 1;
      continue;
    }
    if (token === "--resize-after" && next !== undefined) {
      args.resizeAfter = next;
      i += 1;
      continue;
    }
    if (token === "--port" && next) {
      args.remotePort = next;
      i += 1;
      continue;
    }
    if (token === "--help" || token === "-h") {
      printHelpAndExit();
    }
  }

  return args;
}

export function parseTerminalSize(value: string): { width: number; height: number } {
  const match = /^(\d+)x(\d+)$/.exec(value);
  if (!match) {
    throw new Error(`--resize must be WIDTHxHEIGHT, got '${value}'`);
  }
  const width = parsePositiveInt(match[1], "--resize width");
  const height = parsePositiveInt(match[2], "--resize height");
  if (width > 4096 || height > 4096) {
    throw new Error("--resize dimensions must be <= 4096");
  }
  return { width, height };
}

function parsePositiveInt(value: string, name: string, options?: { allowZero?: boolean }): number {
  const parsed = Number.parseInt(value, 10);
  const floor = options?.allowZero ? 0 : 1;
  if (!Number.isFinite(parsed) || parsed < floor) {
    throw new Error(`${name} must be an integer >= ${floor}, got '${value}'`);
  }
  return parsed;
}

function printHelpAndExit(): never {
  info("Usage:");
  info(
    "  bun run ./hack/e2e.ts up [--cluster NAME] [--namespace NS] [--release NAME] [--image-tag TAG] [--backend NAME] [--sandbox-conformance]",
  );
  info("  bun run ./hack/e2e.ts down [--cluster NAME]");
  info("  bun run ./hack/e2e.ts sandbox-conformance-preflight [--cluster NAME] [--timeout SECONDS]");
  info("      Fail unless `up --sandbox-conformance` created and certified both live placements.");
  info("");
  info("Conformance harness (#138) — disturbs the target so #76's matrix can be run.");
  info("All of these accept [--cluster NAME] [--namespace NS] [--release NAME]");
  info("[--kube-context CTX] [--timeout SECONDS].");
  info("");
  info("  bun run ./hack/e2e.ts restart-operator [--wait-for-phase STAGE] [--lease ID] [--endpoint URL]");
  info("      Restart the operator and wait until it is BOTH serving and leading again.");
  info(`      Stages: ${Object.keys(LEASE_STAGES).join(", ")}`);
  info("");
  info("  bun run ./hack/e2e.ts inject-failure [--kind KIND] [--idempotency-key KEY] [--api-group G --resource R --verb V] [--instance NAME|--lease ID]");
  info("  bun run ./hack/e2e.ts clear-failure  [--kind KIND]");
  info(`      Kinds: ${FAILURE_KINDS.join(", ")} (default: teardown-unverifiable)`);
  info("      rbac-revoke needs --api-group/--resource/--verb;");
  info("      child-api-unreachable needs --instance, or --lease to resolve one from the CR.");
  info("      execution crash windows need --lease and --idempotency-key; some restart the operator.");
  info("");
  info("  bun run ./hack/e2e.ts reap-lease --lease ID");
  info("      Trigger a repaired quarantine's evidence retry, require its protected ledger empty,");
  info("      then delete the clean record. No reservation is removed ahead of teardown proof.");
  info("");
  info("  bun run ./hack/e2e.ts attach-pty --lease ID [--send KEYS]... [--expect TEXT] [--expect-exit N]");
  info("                                   [--resize WIDTHxHEIGHT --resize-after TEXT]");
  info("                                   [--kobe PATH] [--settle MS] [--send-delay MS] [-- ARGV...]");
  info("      Drive `kobe attach` through a real pty. --send accepts \\r \\n \\t \\e \\xNN.");
  info("");
  info("  bun run ./hack/e2e.ts port-forward --lease ID [--port NAME] [--expect TEXT] [--kobe PATH]");
  info("      Drive a real loopback connection through `kobe port-forward`.");
  process.exit(0);
}

function nativePlatform(): string {
  return process.arch === "x64" ? "linux/amd64" : "linux/arm64";
}

function kubeContext(cluster: string): string {
  return `kind-${cluster}`;
}

async function clusterExists(cluster: string): Promise<boolean> {
  const kind = await resolveTool("kind");
  const { stdout } = await runCommand([kind, "get", "clusters"], { allowFailure: true });
  return stdout.split("\n").map((line) => line.trim()).includes(cluster);
}

async function ensureCluster(cluster: string): Promise<void> {
  if (await clusterExists(cluster)) {
    info(`kind cluster '${cluster}' already exists`);
    return;
  }

  step(`Creating kind cluster '${cluster}'`);
  const kind = await resolveTool("kind");
  await runCommand(["mkdir", "-p", `${process.cwd()}/.tmp`], {
    step: "failed to create temp directory for kind config",
  });
  await Bun.write(
    KIND_CONFIG,
    `kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraPortMappings:
      - containerPort: ${LOCAL_NODE_PORT}
        hostPort: 8080
        protocol: TCP
`,
  );
  await runCommand([kind, "create", "cluster", "--name", cluster, "--config", KIND_CONFIG], {
    step: `failed to create kind cluster '${cluster}'`,
  });
}

function sandboxRegistryContainer(cluster: string): string {
  const suffix = createHash("sha256").update(cluster).digest("hex").slice(0, 12);
  return `kobe-e2e-registry-${suffix}`;
}

async function dockerInspect(container: string, format: string): Promise<string | undefined> {
  const result = await runCommand(["docker", "inspect", "--format", format, container], {
    allowFailure: true,
  });
  if (result.exitCode !== 0) return undefined;
  return result.stdout.trim();
}

async function waitForRegistry(endpoint: string): Promise<void> {
  const deadline = Date.now() + 30_000;
  let lastError = "no response";
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${endpoint}/v2/`, { signal: AbortSignal.timeout(1_000) });
      if (response.ok) return;
      lastError = `HTTP ${response.status}`;
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error);
    }
    // This is readiness polling, not a guessed startup delay: every iteration
    // observes the registry endpoint and the bound ends in a concrete error.
    await Bun.sleep(100);
  }
  throw new Error(`sandbox fixture registry at ${endpoint} did not become ready: ${lastError}`);
}

async function ensureSandboxRegistry(cluster: string, imageTag: string): Promise<SandboxFixture> {
  const container = sandboxRegistryContainer(cluster);
  const owner = await dockerInspect(container, `{{ index .Config.Labels "${SANDBOX_REGISTRY_LABEL}" }}`);
  if (owner !== undefined && owner !== cluster) {
    throw new Error(
      `refusing to reuse Docker container '${container}': expected ${SANDBOX_REGISTRY_LABEL}=${cluster}, got ${owner || "no ownership label"}`,
    );
  }

  if (owner === undefined) {
    step(`Starting Sandbox fixture registry '${container}'`);
    await runCommand([
      "docker",
      "run",
      "-d",
      "--name",
      container,
      "--label",
      `${SANDBOX_REGISTRY_LABEL}=${cluster}`,
      "-p",
      "127.0.0.1::5000",
      SANDBOX_REGISTRY_IMAGE,
    ], { step: "failed to start Sandbox fixture registry" });
  } else if ((await dockerInspect(container, "{{.State.Running}}")) !== "true") {
    await runCommand(["docker", "start", container], {
      step: `failed to restart Sandbox fixture registry '${container}'`,
    });
  }

  const kindIpBefore = await dockerInspect(container, `{{ with index .NetworkSettings.Networks "kind" }}{{ .IPAddress }}{{ end }}`);
  if (!kindIpBefore) {
    await runCommand(["docker", "network", "connect", "kind", container], {
      step: `failed to connect Sandbox fixture registry '${container}' to the kind network`,
    });
  }

  const portResult = await runCommand(["docker", "port", container, "5000/tcp"], {
    step: "failed to resolve Sandbox fixture registry host port",
  });
  const hostPort = portResult.stdout.trim().split(":").pop();
  const kindIp = await dockerInspect(container, `{{ (index .NetworkSettings.Networks "kind").IPAddress }}`);
  if (!hostPort || !/^\d+$/.test(hostPort) || !kindIp) {
    throw new Error(`Sandbox fixture registry '${container}' has no usable host port or kind-network address`);
  }

  const registrySource = `127.0.0.1:${hostPort}`;
  await waitForRegistry(`http://${registrySource}`);
  return {
    imageRef: `${registrySource}/kobe-sandbox-e2e:${imageTag}`,
    registrySource,
    mirrorEndpoint: `http://${kindIp}:5000`,
  };
}

async function removeSandboxRegistry(cluster: string): Promise<void> {
  const container = sandboxRegistryContainer(cluster);
  const owner = await dockerInspect(container, `{{ index .Config.Labels "${SANDBOX_REGISTRY_LABEL}" }}`);
  if (owner === undefined) return;
  if (owner !== cluster) {
    throw new Error(
      `refusing to remove Docker container '${container}': expected ${SANDBOX_REGISTRY_LABEL}=${cluster}, got ${owner || "no ownership label"}`,
    );
  }
  step(`Removing Sandbox fixture registry '${container}'`);
  await runCommand(["docker", "rm", "-f", container], {
    step: `failed to remove Sandbox fixture registry '${container}'`,
  });
}

async function buildImages(imageTag: string, sandboxFixture?: SandboxFixture): Promise<void> {
  step(`Building local images (tag=${imageTag}, platform=${nativePlatform()})`);
  const targets = sandboxFixture ? ["default", "sandbox-e2e"] : [];
  await runCommand(["docker", "buildx", "bake", "-f", "docker-bake.hcl", ...targets, "--load"], {
    env: {
      IMAGE_TAG: imageTag,
      PLATFORM: nativePlatform(),
      ...(sandboxFixture ? { SANDBOX_E2E_IMAGE: sandboxFixture.imageRef } : {}),
    },
    step: "failed to build local images",
    stream: true,
  });
}

async function pushSandboxFixture(fixture: SandboxFixture): Promise<void> {
  step(`Publishing Sandbox fixture ${fixture.imageRef} to the run-owned registry`);
  await runCommand(["docker", "push", fixture.imageRef], {
    step: `failed to publish Sandbox fixture '${fixture.imageRef}'`,
    stream: true,
  });
}

async function recreateTempDir(): Promise<void> {
  await runCommand(["rm", "-rf", TEMP_DIR], {
    step: "failed to clear temp image directory",
  });
  await runCommand(["mkdir", "-p", TEMP_DIR], {
    step: "failed to create temp image directory",
  });
}

async function saveImages(imageTag: string, sandboxFixture?: SandboxFixture): Promise<void> {
  await recreateTempDir();
  step(`Saving local images to ${TEMP_DIR}`);
  await runCommand(["docker", "save", `zondax/kobe-operator:${imageTag}`, "-o", `${TEMP_DIR}/kobe-operator.tar`], {
    step: "failed to save kobe-operator image archive",
  });
  await runCommand(["docker", "save", `zondax/kobe-sync:${imageTag}`, "-o", `${TEMP_DIR}/kobe-sync.tar`], {
    step: "failed to save kobe-sync image archive",
  });
  if (sandboxFixture) {
    await runCommand(["docker", "save", sandboxFixture.imageRef, "-o", `${TEMP_DIR}/sandbox-e2e.tar`], {
      step: "failed to save Sandbox fixture image archive",
    });
  }
}

async function kindNodes(cluster: string): Promise<string[]> {
  const kind = await resolveTool("kind");
  const { stdout } = await runCommand([kind, "get", "nodes", "--name", cluster], {
    step: `failed to list kind nodes for cluster '${cluster}'`,
  });
  return stdout
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
}

async function importArchiveToNode(cluster: string, node: string, archivePath: string): Promise<void> {
  const archiveName = archivePath.split("/").pop();
  const kind = await resolveTool("kind");

  info(`  - importing ${archiveName} into ${node}`);
  await runCommand([kind, "load", "image-archive", archivePath, "--name", cluster], {
    step: `failed to load ${archiveName} into kind cluster '${cluster}'`,
  });
}

async function verifyImageInNode(node: string, imageRef: string): Promise<void> {
  const { stdout } = await runCommand(["docker", "exec", node, "ctr", "-n", "k8s.io", "images", "ls"], {
    allowFailure: true,
  });

  const acceptableRefs = [imageRef, `docker.io/${imageRef}`];
  if (!acceptableRefs.some((ref) => stdout.includes(ref))) {
    throw new Error(`Image '${imageRef}' not present in node '${node}' after import`);
  }

  info(`  - verified ${imageRef} on ${node}`);
}

async function loadRemoteImagesIntoKind(cluster: string, images: string[]): Promise<void> {
  if (images.length === 0) return;
  step(`Pre-loading guest images into kind cluster '${cluster}'`);
  const nodes = await kindNodes(cluster);
  for (const image of images) {
    info(`  - pulling ${image}`);
    await runCommand(["docker", "pull", "--platform", nativePlatform(), image], {
      step: `failed to pull guest image '${image}'`,
      stream: true,
    });

    // Deliberately NOT `kind load docker-image` (#34): for a registry-pulled
    // multi-arch image, `docker save` can emit an archive that still carries
    // the multi-arch index, and kind's internal `ctr images import
    // --all-platforms` then fails trying to resolve the foreign-platform
    // manifests that were never pulled — and kind swallows ctr's stderr, so
    // the nightly matrix died for weeks with an opaque "exit status 1".
    // Import the archive ourselves WITHOUT `--all-platforms` (only the
    // pulled platform must resolve, and it always does) and with stderr on
    // the failure path.
    const tarPath = `${TEMP_DIR}/guest-${image.replace(/[^a-zA-Z0-9._-]/g, "_")}.tar`;
    info(`  - saving ${image} to ${tarPath}`);
    await runCommand(["docker", "save", image, "-o", tarPath], {
      step: `failed to save guest image '${image}'`,
    });
    for (const node of nodes) {
      info(`  - importing ${image} into ${node}`);
      await runCommand(
        [
          "docker",
          "exec",
          "-i",
          node,
          "ctr",
          "--namespace=k8s.io",
          "images",
          "import",
          "--digests",
          "--snapshotter=overlayfs",
          "-",
        ],
        {
          stdinFile: tarPath,
          step: `failed to import guest image '${image}' into node '${node}'`,
        },
      );
      await verifyImageInNode(node, image);
    }
  }
}

export function guestImagesForBackend(backend?: string): string[] {
  const images = [K3S_GUEST_IMAGE];
  if (backend === "k0s") {
    images.push(K0S_GUEST_IMAGE);
  }
  return images;
}

async function loadImagesIntoKind(
  cluster: string,
  imageTag: string,
  backend?: string,
  sandboxFixture?: SandboxFixture,
): Promise<void> {
  step(`Loading images into kind cluster '${cluster}'`);
  await saveImages(imageTag, sandboxFixture);

  const nodes = await kindNodes(cluster);
  info(`  - nodes: ${nodes.join(", ")}`);
  for (const node of nodes) {
    await importArchiveToNode(cluster, node, `${TEMP_DIR}/kobe-operator.tar`);
    await importArchiveToNode(cluster, node, `${TEMP_DIR}/kobe-sync.tar`);
    if (sandboxFixture) {
      await importArchiveToNode(cluster, node, `${TEMP_DIR}/sandbox-e2e.tar`);
    }
    await verifyImageInNode(node, `zondax/kobe-operator:${imageTag}`);
    await verifyImageInNode(node, `zondax/kobe-sync:${imageTag}`);
    if (sandboxFixture) {
      await verifyImageInNode(node, sandboxFixture.imageRef);
    }
  }

  // Pre-load guest backend images so a leased/warmed instance doesn't have to
  // pull them inside the smoke gate's wait_ready budget. k3s is launched with
  // the default IfNotPresent pull policy for its tagged image, so a node-local
  // copy means the kubelet never reaches out to the registry.
  // k3s is pre-loaded unconditionally because `e2e-k3s` is the one pool with
  // `scaling.minReady: 1` — it warms in EVERY leg, so every leg needs its
  // guest image. The scale-to-zero pools only provision when their own leg
  // leases from them, so pre-loading their images everywhere would tax each
  // leg with a pull it never uses (and add a registry dependency, which is a
  // fresh way for an unrelated leg to fail). Pull those only when the leg
  // that needs them is the one coming up.
  await loadRemoteImagesIntoKind(cluster, guestImagesForBackend(backend));
}

async function prepareHelm(): Promise<void> {
  step("Preparing Helm dependencies");
  const helm = await resolveTool("helm");
  await runCommand([helm, "dependency", "build", "./charts/kobe"], {
    step: "failed to build Helm chart dependencies",
  });
}

async function installChart(args: Args): Promise<void> {
  step(`Installing Helm release '${args.release}' into namespace '${args.namespace}'`);
  // CRDs in charts/kobe/crds/ are installed by Helm on first install. On upgrades,
  // re-apply with server-side apply using the "helm" field manager so ownership
  // stays consistent with what Helm uses internally (avoids field-manager conflicts).
  const kubectl = await resolveTool("kubectl");
  await runCommand(
    [
      kubectl,
      "--context",
      kubeContext(args.cluster),
      "apply",
      "--server-side",
      "--force-conflicts",
      "--field-manager=helm",
      "-f",
      "./charts/kobe/crds",
    ],
    {
      step: "failed to apply Kobe CRDs",
    },
  );
  const helm = await resolveTool("helm");
  const rolloutNonce = Date.now().toString();
  const command = [
    helm,
    "upgrade",
    "--install",
    args.release,
    "./charts/kobe",
    "--namespace",
    args.namespace,
    "--kube-context",
    kubeContext(args.cluster),
    "--wait",
    "--timeout",
    "5m",
    "--set",
    "replicas=1",
    "--set",
    "service.type=NodePort",
    "--set",
    `service.nodePort=${LOCAL_NODE_PORT}`,
    "--set",
    `operatorNamespace=${args.namespace}`,
    "--set",
    "image.repository=zondax/kobe-operator",
    "--set",
    `image.tag=${args.imageTag}`,
    "--set",
    "image.pullPolicy=IfNotPresent",
    "--set",
    "kobeSync.image.repository=zondax/kobe-sync",
    "--set",
    `kobeSync.image.tag=${args.imageTag}`,
    "--set-string",
    `podAnnotations.e2e-rollout=${rolloutNonce}`,
  ];
  if (args.sandboxConformance) {
    command.push("--set", "agentSandbox.mode=managed");
  }
  await runCommand(command, {
    step: `failed to install Helm release '${args.release}'`,
    stream: true,
  });
}


export function sandboxConformanceManifest(namespace: string, fixture: SandboxFixture): string {
  const poolSpec = (placement: string) => `spec:
  warmCapacity: 1
  defaultTtl: "10m"
  maxTtl: "20m"
  provisioningTimeout: "5m"
  placement:
${placement}
  template:
    defaultContainer: workspace
    runnerPath: /kobe-runner
    containers:
      - name: workspace
        image: ${fixture.imageRef}
        command: ["/bin/sh", "-c"]
        args: ["trap 'exit 0' TERM INT; while :; do sleep 1; done"]
        resources:
          requests:
            cpu: "50m"
            memory: "64Mi"
            ephemeralStorage: "64Mi"
          limits:
            cpu: "500m"
            memory: "256Mi"
            ephemeralStorage: "512Mi"
    exposedPorts:
      - name: http
        container: workspace
        port: 8080
  # Kind and its nested k3s child intentionally use the ordinary runtime. The
  # trusted tier makes that limitation explicit and never claims gVisor/Kata.
  isolation:
    tier: trusted-runc
  readiness:
    canary:
      argv: ["/bin/sh", "-c", "test -x /kobe-runner"]
      timeout: "30s"`;

  return `apiVersion: v1
kind: Secret
metadata:
  name: ${DEMO_OTHER_TOKEN_SECRET}
  namespace: ${namespace}
stringData:
  token: ${DEMO_OTHER_TOKEN}
---
apiVersion: kobe.kunobi.ninja/v1alpha1
kind: AccessPolicy
metadata:
  name: ${DEMO_OTHER_POLICY}
  namespace: ${namespace}
spec:
  auth:
    token:
      secretRef: ${DEMO_OTHER_TOKEN_SECRET}
  rules:
    - pools: []
      maxTtl: "1h"
      maxConcurrentLeases: 0
      maxExtensions: 0
      sandbox:
        pools: ["${DEMO_SANDBOX_POOL_MANAGEMENT}", "${DEMO_SANDBOX_POOL_CHILD}"]
        verbs: ["lease", "exec", "logs", "port-forward", "release"]
        maxTtl: "20m"
        maxConcurrentLeases: 8
        resourceCeiling:
          maxCpu: "1"
          maxMemory: "512Mi"
---
apiVersion: kobe.kunobi.ninja/v1alpha1
kind: SandboxPool
metadata:
  name: ${DEMO_SANDBOX_POOL_MANAGEMENT}
  namespace: ${namespace}
${poolSpec("    type: management")}
---
apiVersion: kobe.kunobi.ninja/v1alpha1
kind: SandboxPool
metadata:
  name: ${DEMO_SANDBOX_POOL_CHILD}
  namespace: ${namespace}
${poolSpec(`    type: childCluster\n    clusterPoolRef: ${DEMO_K3S_POOL}`)}
`;
}

export function bootstrapManifest(namespace: string, sandboxFixture?: SandboxFixture): string {
  return `apiVersion: v1
kind: Secret
metadata:
  name: ${DEMO_TOKEN_SECRET}
  namespace: ${namespace}
stringData:
  token: ${DEMO_TOKEN}
---
apiVersion: kobe.kunobi.ninja/v1alpha1
kind: AccessPolicy
metadata:
  name: ${DEMO_POLICY}
  namespace: ${namespace}
spec:
  auth:
    token:
      secretRef: ${DEMO_TOKEN_SECRET}
  rules:
    - pools: ["*"]
      maxTtl: "2h"
      maxConcurrentLeases: 10
      maxExtensions: 5
${sandboxFixture ? `      sandbox:
        pools: ["${DEMO_SANDBOX_POOL_MANAGEMENT}", "${DEMO_SANDBOX_POOL_CHILD}"]
        verbs: ["lease", "exec", "logs", "port-forward", "release"]
        maxTtl: "20m"
        maxConcurrentLeases: 8
        resourceCeiling:
          maxCpu: "1"
          maxMemory: "512Mi"
` : ""}---
apiVersion: kobe.kunobi.ninja/v1alpha1
kind: ClusterPool
metadata:
  name: ${DEMO_K0S_POOL}
  namespace: ${namespace}
spec:
  size: 1
  ttl: "1h"
  backend:
    type: k0s
  cluster:
    version: "${DEMO_K0S_VERSION}"
    servers: 1
  healthCheck:
    intervalSeconds: 30
    failureThreshold: 3
  scaling:
    minReady: 0
    maxClusters: 2
    scaleUpThreshold: 0
    scaleDownAfter: "5m"
    # Must exceed the recipe LEASE_WAIT_TIMEOUT: a server-side cap shorter
    # than the client wait expires the queued claim regardless of how
    # long the client is willing to wait.
    queueTimeout: "12m"
    # Caps ONE provisioning attempt: past it the operator recycles that
    # instance as wedged. The claim itself survives and a later attempt can
    # still serve it, up to the waits above — so this is a chosen retry
    # policy, not a hard bound on the claim. Sized to fit a cold start now
    # that the guest image is pre-loaded into the kind nodes
    # (K0S_GUEST_IMAGE); without that it would be timing a registry pull.
    creatingTimeout: "8m"
  resources:
    limits:
      cpu: "1"
      memory: "1Gi"
---
# Single-server k3s pool for the provision→Ready→recycle CI smoke gate.
# Modeled on deploy/profiles/e2e-direct-k3s.yaml but with the shared-Postgres
# backend.datastore block dropped (the kunobi-postgres secret doesn't exist in
# kind) so each k3s instance uses embedded SQLite. Ordinary e2e keeps it bare;
# --sandbox-conformance consumes the chart-published pinned runtime bootstrap
# and the run-owned fixture registry mirror. scaling.minReady=1 warms one member.
apiVersion: kobe.kunobi.ninja/v1alpha1
kind: ClusterPool
metadata:
  name: ${DEMO_K3S_POOL}
  namespace: ${namespace}
spec:
  size: 1
  ttl: "1h"
  backend:
    type: k3s
  cluster:
    version: "${DEMO_K3S_VERSION}"
    servers: 1
    agents: 0
${sandboxFixture ? `    registryMirrors:
      "${sandboxFixture.registrySource}":
        - "${sandboxFixture.mirrorEndpoint}"
  bootstraps:
    - name: ${DEMO_SANDBOX_BOOTSTRAP}
` : ""}  healthCheck:
    intervalSeconds: 30
    failureThreshold: 3
  scaling:
    minReady: 1
    maxClusters: 2
    scaleUpThreshold: 0
    scaleDownAfter: "5m"
    queueTimeout: "5m"
  resources:
    limits:
      cpu: "1"
      memory: "1Gi"
---
${sandboxFixture ? `${sandboxConformanceManifest(namespace, sandboxFixture)}---\n` : ""}apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${DEMO_VKOBE_ETCD_BACKEND}
  namespace: ${namespace}
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: ${DEMO_VKOBE_ETCD_BACKEND}
  template:
    metadata:
      labels:
        app.kubernetes.io/name: ${DEMO_VKOBE_ETCD_BACKEND}
    spec:
      containers:
        - name: etcd
          image: quay.io/coreos/etcd:v3.5.18
          command:
            - /usr/local/bin/etcd
          args:
            - --name=${DEMO_VKOBE_ETCD_BACKEND}
            - --data-dir=/var/lib/etcd
            - --listen-client-urls=http://0.0.0.0:2379
            - --advertise-client-urls=http://${DEMO_VKOBE_ETCD_BACKEND}.${namespace}.svc:2379
            - --listen-peer-urls=http://0.0.0.0:2380
            - --initial-advertise-peer-urls=http://${DEMO_VKOBE_ETCD_BACKEND}.${namespace}.svc:2380
            - --initial-cluster=${DEMO_VKOBE_ETCD_BACKEND}=http://${DEMO_VKOBE_ETCD_BACKEND}.${namespace}.svc:2380
            - --initial-cluster-state=new
          ports:
            - name: client
              containerPort: 2379
            - name: peer
              containerPort: 2380
          volumeMounts:
            - name: data
              mountPath: /var/lib/etcd
      volumes:
        - name: data
          emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: ${DEMO_VKOBE_ETCD_BACKEND}
  namespace: ${namespace}
spec:
  selector:
    app.kubernetes.io/name: ${DEMO_VKOBE_ETCD_BACKEND}
  ports:
    - name: client
      port: 2379
      targetPort: client
    - name: peer
      port: 2380
      targetPort: peer
---
apiVersion: kobe.kunobi.ninja/v1alpha1
kind: KobeStore
metadata:
  name: ${DEMO_VKOBE_ETCD_STORE}
  namespace: ${namespace}
spec:
  driver: etcd
  endpoints:
    - http://${DEMO_VKOBE_ETCD_BACKEND}.${namespace}.svc:2379
  capacity:
    maxClusters: 10
  replicas: 1
---
apiVersion: kobe.kunobi.ninja/v1alpha1
kind: BootstrapConfig
metadata:
  name: ${DEMO_BOOTSTRAP_CONFIG}
  namespace: ${namespace}
spec:
  files:
    10-configmap.yaml: |
      apiVersion: v1
      kind: ConfigMap
      metadata:
        name: ${DEMO_BOOTSTRAP_CONFIGMAP}
        namespace: ${DEMO_BOOTSTRAP_NAMESPACE}
      data:
        installed: "true"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${DEMO_VKOBE_KINE_BACKEND}
  namespace: ${namespace}
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: ${DEMO_VKOBE_KINE_BACKEND}
  template:
    metadata:
      labels:
        app.kubernetes.io/name: ${DEMO_VKOBE_KINE_BACKEND}
    spec:
      containers:
        - name: kine
          image: rancher/kine:latest
          args:
            - --endpoint=sqlite:///data/kine.db
            - --listen-address=0.0.0.0:2379
            - --metrics-bind-address=0
            - --log-format=json
          ports:
            - name: client
              containerPort: 2379
          volumeMounts:
            - name: data
              mountPath: /data
      volumes:
        - name: data
          emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: ${DEMO_VKOBE_KINE_BACKEND}
  namespace: ${namespace}
spec:
  selector:
    app.kubernetes.io/name: ${DEMO_VKOBE_KINE_BACKEND}
  ports:
    - name: client
      port: 2379
      targetPort: client
---
apiVersion: kobe.kunobi.ninja/v1alpha1
kind: KobeStore
metadata:
  name: ${DEMO_VKOBE_KINE_STORE}
  namespace: ${namespace}
spec:
  driver: kine-sqlite
  endpoints:
    - http://${DEMO_VKOBE_KINE_BACKEND}.${namespace}.svc:2379
  capacity:
    maxClusters: 10
  replicas: 1
---
apiVersion: kobe.kunobi.ninja/v1alpha1
kind: ClusterPool
metadata:
  name: ${DEMO_VKOBE_ETCD_POOL}
  namespace: ${namespace}
spec:
  size: 1
  ttl: "1h"
  backend:
    type: vkobe
    vkobe:
      dataStoreRef:
        name: ${DEMO_VKOBE_ETCD_STORE}
      version: "${DEMO_VKOBE_VERSION}"
      syncers:
        - pods
        - services
        - configmaps
        - secrets
        - endpoints
        - ingresses
  cluster:
    version: "${DEMO_VKOBE_VERSION}"
    servers: 1
  healthCheck:
    intervalSeconds: 30
    failureThreshold: 3
  scaling:
    minReady: 0
    maxClusters: 2
    scaleUpThreshold: 0
    scaleDownAfter: "5m"
    # Must exceed the recipe LEASE_WAIT_TIMEOUT: this is a server-side
    # cap, so a shorter value here expires the queued claim regardless of
    # how long the client waits (scale-to-zero pools provision on demand).
    queueTimeout: "12m"
    # Caps ONE provisioning attempt: past it the operator recycles that
    # instance as wedged. The claim itself survives and a later attempt can
    # still serve it, up to the waits above — so this is a chosen retry
    # policy, not a hard bound on the claim. Sized to fit a cold start in
    # one attempt so the leg measures provisioning rather than retries.
    creatingTimeout: "8m"
  resources:
    limits:
      cpu: "500m"
      memory: "512Mi"
---
apiVersion: kobe.kunobi.ninja/v1alpha1
kind: ClusterPool
metadata:
  name: ${DEMO_VKOBE_BOOTSTRAP_POOL}
  namespace: ${namespace}
spec:
  size: 1
  ttl: "1h"
  backend:
    type: vkobe
    vkobe:
      dataStoreRef:
        name: ${DEMO_VKOBE_ETCD_STORE}
      version: "${DEMO_VKOBE_VERSION}"
      syncers:
        - pods
        - services
        - configmaps
        - secrets
        - endpoints
        - ingresses
  cluster:
    version: "${DEMO_VKOBE_VERSION}"
    servers: 1
  bootstraps:
    - name: ${DEMO_BOOTSTRAP_CONFIG}
  healthCheck:
    intervalSeconds: 30
    failureThreshold: 3
  scaling:
    minReady: 0
    maxClusters: 2
    scaleUpThreshold: 0
    scaleDownAfter: "5m"
    queueTimeout: "30m"
  resources:
    limits:
      cpu: "500m"
      memory: "512Mi"
---
apiVersion: kobe.kunobi.ninja/v1alpha1
kind: ClusterPool
metadata:
  name: ${DEMO_VKOBE_KINE_POOL}
  namespace: ${namespace}
spec:
  size: 1
  ttl: "1h"
  backend:
    type: vkobe
    vkobe:
      dataStoreRef:
        name: ${DEMO_VKOBE_KINE_STORE}
      version: "${DEMO_VKOBE_VERSION}"
      syncers:
        - pods
        - services
        - configmaps
        - secrets
        - endpoints
        - ingresses
  cluster:
    version: "${DEMO_VKOBE_VERSION}"
    servers: 1
  healthCheck:
    intervalSeconds: 30
    failureThreshold: 3
  scaling:
    minReady: 0
    maxClusters: 2
    scaleUpThreshold: 0
    scaleDownAfter: "5m"
    # Must exceed the recipe LEASE_WAIT_TIMEOUT: this is a server-side
    # cap, so a shorter value here expires the queued claim regardless of
    # how long the client waits (scale-to-zero pools provision on demand).
    queueTimeout: "12m"
    # Caps ONE provisioning attempt: past it the operator recycles that
    # instance as wedged. The claim itself survives and a later attempt can
    # still serve it, up to the waits above — so this is a chosen retry
    # policy, not a hard bound on the claim. Sized to fit a cold start in
    # one attempt so the leg measures provisioning rather than retries.
    creatingTimeout: "8m"
  resources:
    limits:
      cpu: "500m"
      memory: "512Mi"
---
apiVersion: kobe.kunobi.ninja/v1alpha1
kind: ClusterPool
metadata:
  name: ${DEMO_VKOBE_KINE_BOOTSTRAP_POOL}
  namespace: ${namespace}
spec:
  size: 1
  ttl: "1h"
  backend:
    type: vkobe
    vkobe:
      dataStoreRef:
        name: ${DEMO_VKOBE_KINE_STORE}
      version: "${DEMO_VKOBE_VERSION}"
      syncers:
        - pods
        - services
        - configmaps
        - secrets
        - endpoints
        - ingresses
  cluster:
    version: "${DEMO_VKOBE_VERSION}"
    servers: 1
  bootstraps:
    - name: ${DEMO_FLUX_BOOTSTRAP_CONFIG}
  healthCheck:
    intervalSeconds: 30
    failureThreshold: 3
  scaling:
    minReady: 0
    maxClusters: 2
    scaleUpThreshold: 0
    scaleDownAfter: "5m"
    queueTimeout: "30m"
  resources:
    limits:
      cpu: "500m"
      memory: "512Mi"
---
# vcluster backend: bare pool. The operator runs
# \`helm upgrade --install loft-sh/vcluster\` per ClusterInstance into
# its own host namespace (vcluster-<instance>), so unlike the vkobe
# pools above this needs no KobeStore reference and no syncer list.
apiVersion: kobe.kunobi.ninja/v1alpha1
kind: ClusterPool
metadata:
  name: ${DEMO_VCLUSTER_POOL}
  namespace: ${namespace}
spec:
  size: 1
  ttl: "1h"
  backend:
    type: vcluster
    # Empty vcluster block means "use operator defaults": chart version
    # pinned in src/backend/vcluster.rs (DEFAULT_CHART_VERSION),
    # exportKubeConfig.server set to the in-cluster DNS form.
    vcluster: {}
  cluster:
    # Used verbatim as the ghcr.io/loft-sh/kubernetes image tag, so it must
    # be a real published tag: v-prefixed with a full patch version. A bare
    # "1.34" is not one, and was silently ignored until the backend started
    # honouring this field.
    version: "v1.34.0"
    servers: 1
  healthCheck:
    intervalSeconds: 30
    failureThreshold: 3
  scaling:
    minReady: 0
    maxClusters: 2
    scaleUpThreshold: 0
    scaleDownAfter: "5m"
    # Must exceed the recipe LEASE_WAIT_TIMEOUT: this is a server-side
    # cap, so a shorter value here expires the queued claim regardless of
    # how long the client waits (scale-to-zero pools provision on demand).
    queueTimeout: "20m"
    # Caps ONE provisioning attempt: past it the operator recycles that
    # instance as wedged. The claim itself survives and a later attempt can
    # still serve it, up to the waits above — so this is a chosen retry
    # policy, not a hard bound on the claim. Sized to fit a cold start in
    # one attempt so the leg measures provisioning rather than retries.
    creatingTimeout: "12m"
  resources:
    limits:
      cpu: "500m"
      memory: "512Mi"
---
# vcluster backend with Flux bootstrap. End-to-end smoke that the
# vcluster instance is genuinely usable for the same workload that
# the legacy in-house vkobe backend struggled with for 8 days at
# an internal cluster (Bug A: SA token volume not propagated → Flux
# controllers CrashLoopBackOff). vcluster handles SA token projection
# natively, so this pool should reach Healthy on the first attempt.
apiVersion: kobe.kunobi.ninja/v1alpha1
kind: ClusterPool
metadata:
  name: ${DEMO_VCLUSTER_BOOTSTRAP_POOL}
  namespace: ${namespace}
spec:
  size: 1
  ttl: "1h"
  backend:
    type: vcluster
    vcluster: {}
  cluster:
    # Used verbatim as the ghcr.io/loft-sh/kubernetes image tag, so it must
    # be a real published tag: v-prefixed with a full patch version. A bare
    # "1.34" is not one, and was silently ignored until the backend started
    # honouring this field.
    version: "v1.34.0"
    servers: 1
  bootstraps:
    - name: ${DEMO_FLUX_BOOTSTRAP_CONFIG}
  healthCheck:
    intervalSeconds: 30
    failureThreshold: 3
  scaling:
    minReady: 0
    maxClusters: 2
    scaleUpThreshold: 0
    scaleDownAfter: "5m"
    queueTimeout: "30m"
  resources:
    limits:
      cpu: "500m"
      memory: "512Mi"
`;
}

async function bootstrapLocalResources(
  cluster: string,
  namespace: string,
  sandboxFixture?: SandboxFixture,
): Promise<void> {
  step("Bootstrapping local demo token and pool");
  await runCommand(
    [
      "/bin/sh",
      "-lc",
      `CTX=${kubeContext(cluster)}
for pool in ${DEMO_K0S_POOL} ${DEMO_K3S_POOL}; do
for name in $(kubectl --context "$CTX" get clusterinstances.kobe.kunobi.ninja -n ${namespace} -l kobe.kunobi.ninja/pool=$pool -o jsonpath='{range .items[*]}{.metadata.name}{"\\n"}{end}' 2>/dev/null); do
  kubectl --context "$CTX" delete statefulset -n ${namespace} "\${name}-server" --ignore-not-found >/dev/null 2>&1 || true
  kubectl --context "$CTX" delete deployment -n ${namespace} "\${name}-agent" --ignore-not-found >/dev/null 2>&1 || true
  kubectl --context "$CTX" delete service -n ${namespace} "\${name}-server" --ignore-not-found >/dev/null 2>&1 || true
  kubectl --context "$CTX" delete configmap -n ${namespace} "\${name}-k0s-config" "\${name}-kubeconfig-publisher" --ignore-not-found >/dev/null 2>&1 || true
  kubectl --context "$CTX" delete secret -n ${namespace} "\${name}-token" "\${name}-kubeconfig" --ignore-not-found >/dev/null 2>&1 || true
  kubectl --context "$CTX" delete pvc -n ${namespace} -l "kobe.kunobi.ninja/cluster=\${name}" --ignore-not-found >/dev/null 2>&1 || true
done
done
for pool in ${DEMO_VKOBE_ETCD_POOL} ${DEMO_VKOBE_BOOTSTRAP_POOL} ${DEMO_VKOBE_KINE_POOL} ${DEMO_VKOBE_KINE_BOOTSTRAP_POOL}; do
for name in $(kubectl --context "$CTX" get clusterinstances.kobe.kunobi.ninja -n ${namespace} -l kobe.kunobi.ninja/pool=$pool -o jsonpath='{range .items[*]}{.metadata.name}{"\\n"}{end}' 2>/dev/null); do
  kubectl --context "$CTX" delete deployment -n ${namespace} "\${name}-vkobe" --ignore-not-found >/dev/null 2>&1 || true
  kubectl --context "$CTX" delete service -n ${namespace} "\${name}-api" --ignore-not-found >/dev/null 2>&1 || true
  kubectl --context "$CTX" delete configmap -n ${namespace} "\${name}-config" --ignore-not-found >/dev/null 2>&1 || true
  kubectl --context "$CTX" delete secret -n ${namespace} "\${name}-certs" "\${name}-kubeconfig" --ignore-not-found >/dev/null 2>&1 || true
  kubectl --context "$CTX" delete rolebinding.rbac.authorization.k8s.io -n ${namespace} "\${name}-vkobe" --ignore-not-found >/dev/null 2>&1 || true
  kubectl --context "$CTX" delete rolebinding.rbac.authorization.k8s.io -n kube-system "\${name}-vkobe-auth-reader" --ignore-not-found >/dev/null 2>&1 || true
  kubectl --context "$CTX" delete role.rbac.authorization.k8s.io -n ${namespace} "\${name}-vkobe" --ignore-not-found >/dev/null 2>&1 || true
  kubectl --context "$CTX" delete serviceaccount -n ${namespace} "\${name}-vkobe" --ignore-not-found >/dev/null 2>&1 || true
  kubectl --context "$CTX" delete clusterrolebinding.rbac.authorization.k8s.io "\${name}-vkobe-nodes" --ignore-not-found >/dev/null 2>&1 || true
  kubectl --context "$CTX" delete clusterrole.rbac.authorization.k8s.io "\${name}-vkobe-nodes" --ignore-not-found >/dev/null 2>&1 || true
done
done
kubectl --context "$CTX" delete clusterinstances.kobe.kunobi.ninja -n ${namespace} -l kobe.kunobi.ninja/pool=${DEMO_K0S_POOL} --ignore-not-found >/dev/null 2>&1 || true
kubectl --context "$CTX" delete clusterinstances.kobe.kunobi.ninja -n ${namespace} -l kobe.kunobi.ninja/pool=${DEMO_K3S_POOL} --ignore-not-found >/dev/null 2>&1 || true
kubectl --context "$CTX" delete clusterinstances.kobe.kunobi.ninja -n ${namespace} -l kobe.kunobi.ninja/pool=${DEMO_VKOBE_ETCD_POOL} --ignore-not-found >/dev/null 2>&1 || true
kubectl --context "$CTX" delete clusterinstances.kobe.kunobi.ninja -n ${namespace} -l kobe.kunobi.ninja/pool=${DEMO_VKOBE_BOOTSTRAP_POOL} --ignore-not-found >/dev/null 2>&1 || true
kubectl --context "$CTX" delete clusterinstances.kobe.kunobi.ninja -n ${namespace} -l kobe.kunobi.ninja/pool=${DEMO_VKOBE_KINE_POOL} --ignore-not-found >/dev/null 2>&1 || true
kubectl --context "$CTX" delete clusterinstances.kobe.kunobi.ninja -n ${namespace} -l kobe.kunobi.ninja/pool=${DEMO_VKOBE_KINE_BOOTSTRAP_POOL} --ignore-not-found >/dev/null 2>&1 || true
kubectl --context "$CTX" delete clusterinstances.kobe.kunobi.ninja -n ${namespace} -l kobe.kunobi.ninja/pool=${DEMO_VCLUSTER_POOL} --ignore-not-found >/dev/null 2>&1 || true
kubectl --context "$CTX" delete clusterinstances.kobe.kunobi.ninja -n ${namespace} -l kobe.kunobi.ninja/pool=${DEMO_VCLUSTER_BOOTSTRAP_POOL} --ignore-not-found >/dev/null 2>&1 || true
# vcluster instances each live in their own host namespace
# (vcluster-<name>); reap the namespaces directly so any orphan
# Helm release / projected resource is gone.
for ns in $(kubectl --context "$CTX" get namespace -l kobe.kunobi.ninja/backend=vcluster -o jsonpath='{range .items[*]}{.metadata.name}{"\\n"}{end}' 2>/dev/null); do
  kubectl --context "$CTX" delete namespace "$ns" --ignore-not-found >/dev/null 2>&1 || true
done
kubectl --context "$CTX" delete clusterpool.kobe.kunobi.ninja -n ${namespace} ${DEMO_K0S_POOL} ${DEMO_K3S_POOL} ${DEMO_VKOBE_ETCD_POOL} ${DEMO_VKOBE_BOOTSTRAP_POOL} ${DEMO_VKOBE_KINE_POOL} ${DEMO_VKOBE_KINE_BOOTSTRAP_POOL} ${DEMO_VCLUSTER_POOL} ${DEMO_VCLUSTER_BOOTSTRAP_POOL} --ignore-not-found >/dev/null 2>&1 || true
kubectl --context "$CTX" delete bootstrapconfig.kobe.kunobi.ninja -n ${namespace} ${DEMO_BOOTSTRAP_CONFIG} --ignore-not-found >/dev/null 2>&1 || true
kubectl --context "$CTX" delete kobestore.kobe.kunobi.ninja -n ${namespace} ${DEMO_VKOBE_ETCD_STORE} ${DEMO_VKOBE_KINE_STORE} --ignore-not-found >/dev/null 2>&1 || true
kubectl --context "$CTX" delete service -n ${namespace} ${DEMO_VKOBE_ETCD_BACKEND} ${DEMO_VKOBE_KINE_BACKEND} --ignore-not-found >/dev/null 2>&1 || true
kubectl --context "$CTX" delete deployment -n ${namespace} ${DEMO_VKOBE_ETCD_BACKEND} ${DEMO_VKOBE_KINE_BACKEND} --ignore-not-found >/dev/null 2>&1 || true`,
    ],
    {
      step: "failed to clean up existing local demo pool resources",
    },
  );
  await runCommand(
    ["/bin/sh", "-lc", `cat <<'EOF' | kubectl --context ${kubeContext(cluster)} apply -f -
${bootstrapManifest(namespace, sandboxFixture)}EOF`],
    {
      step: "failed to apply local demo token/policy/pool",
    },
  );
}

async function writeLocalCliConfig(): Promise<void> {
  step("Writing local .kobe.toml");
  const content = `current_target = "${LOCAL_TARGET}"

[targets.${LOCAL_TARGET}]
endpoint = "${LOCAL_ENDPOINT}"
auth = "token"
token = "${DEMO_TOKEN}"

[targets.${LOCAL_OTHER_TARGET}]
endpoint = "${LOCAL_ENDPOINT}"
auth = "token"
token = "${DEMO_OTHER_TOKEN}"
`;
  await runCommand(
    ["/bin/sh", "-lc", `cat <<'EOF' > .kobe.toml
${content}EOF`],
    { step: "failed to write .kobe.toml" },
  );
}

async function printContext(cluster: string, namespace: string): Promise<void> {
  info("");
  step("Local e2e environment is ready");
  info(`Context: kind-${cluster}`);
  info(`Namespace: ${namespace}`);
  info(
    `Demo pools: ${DEMO_K0S_POOL}, ${DEMO_K3S_POOL}, ${DEMO_VKOBE_ETCD_POOL}, ${DEMO_VKOBE_BOOTSTRAP_POOL}, ${DEMO_VKOBE_KINE_POOL}, ${DEMO_VKOBE_KINE_BOOTSTRAP_POOL}, ${DEMO_VCLUSTER_POOL}, ${DEMO_VCLUSTER_BOOTSTRAP_POOL}`,
  );
  info(`Demo vkobe stores: ${DEMO_VKOBE_ETCD_STORE} -> ${DEMO_VKOBE_ETCD_BACKEND}, ${DEMO_VKOBE_KINE_STORE} -> ${DEMO_VKOBE_KINE_BACKEND}`);
  info(`Demo bootstrap: ${DEMO_BOOTSTRAP_CONFIG} -> ${DEMO_BOOTSTRAP_NAMESPACE}/${DEMO_BOOTSTRAP_CONFIGMAP}`);
  info(`Demo bootstrap: ${DEMO_FLUX_BOOTSTRAP_CONFIG} -> installs Flux into ${DEMO_FLUX_NAMESPACE}`);
  info(`Demo token: ${DEMO_TOKEN}`);
  info(`Local config: .kobe.toml`);
  info("Next:");
  info(`  kubectl config use-context kind-${cluster}`);
  info(`  kubectl get pods -n ${namespace}`);
  info(`  curl ${LOCAL_ENDPOINT}/v1/status`);
  info(`  cargo run --bin kobe -- status`);
}

async function up(args: Args): Promise<void> {
  await ensureMiseTools();
  const clusterAlreadyExists = await clusterExists(args.cluster);
  const fingerprint = computeFingerprint();

  if (clusterAlreadyExists && canReuseExistingEnvironment(args, fingerprint)) {
    step(`Reusing existing e2e environment '${args.cluster}' (no local changes detected)`);
    await writeLocalCliConfig();
    await printContext(args.cluster, args.namespace);
    return;
  }

  if (clusterAlreadyExists) {
    step(`Refreshing e2e environment '${args.cluster}' (local changes detected)`);
  }

  await ensureCluster(args.cluster);
  const sandboxFixture = args.sandboxConformance
    ? await ensureSandboxRegistry(args.cluster, args.imageTag)
    : undefined;
  await buildImages(args.imageTag, sandboxFixture);
  if (sandboxFixture) {
    await pushSandboxFixture(sandboxFixture);
  }
  await loadImagesIntoKind(args.cluster, args.imageTag, args.backend, sandboxFixture);
  await prepareHelm();
  await runCommand(["/bin/sh", "-lc", `kubectl --context ${kubeContext(args.cluster)} create namespace ${args.namespace} --dry-run=client -o yaml | kubectl --context ${kubeContext(args.cluster)} apply -f -`], {
    step: `failed to ensure namespace '${args.namespace}'`,
  });
  await installChart(args);
  await bootstrapLocalResources(args.cluster, args.namespace, sandboxFixture);
  await writeLocalCliConfig();
  await saveState(args, fingerprint, sandboxFixture);
  await printContext(args.cluster, args.namespace);
}

type ConformanceObject = {
  metadata?: { generation?: number };
  spec?: Record<string, unknown>;
  status?: {
    observedGeneration?: number;
    conditions?: Array<{
      type?: string;
      status?: string;
      observedGeneration?: number;
      reason?: string;
      message?: string;
    }>;
  };
};

function requireConformance(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(`Sandbox conformance preflight: ${message}`);
}

function assertSandboxPolicy(policy: ConformanceObject, name: string): void {
  const rules = policy.spec?.rules;
  requireConformance(Array.isArray(rules), `AccessPolicy/${name} has no rules`);
  const requiredPools = [DEMO_SANDBOX_POOL_MANAGEMENT, DEMO_SANDBOX_POOL_CHILD];
  const requiredVerbs = ["lease", "exec", "logs", "port-forward", "release"];
  const grant = rules.find((candidate) => {
    if (!candidate || typeof candidate !== "object") return false;
    const sandbox = (candidate as Record<string, unknown>).sandbox;
    if (!sandbox || typeof sandbox !== "object") return false;
    const fields = sandbox as Record<string, unknown>;
    return requiredPools.every((pool) => Array.isArray(fields.pools) && fields.pools.includes(pool))
      && requiredVerbs.every((verb) => Array.isArray(fields.verbs) && fields.verbs.includes(verb));
  });
  requireConformance(grant, `AccessPolicy/${name} lacks the complete two-pool Sandbox grant`);
}

function assertCertifiedPool(pool: ConformanceObject, name: string): void {
  const generation = pool.metadata?.generation;
  requireConformance(generation !== undefined, `SandboxPool/${name} has no generation`);
  requireConformance(
    pool.status?.observedGeneration === generation,
    `SandboxPool/${name} status is stale (observed ${pool.status?.observedGeneration ?? "none"}, current ${generation})`,
  );
  const ready = (pool.status?.conditions ?? []).filter((condition) => condition.type === "Ready");
  requireConformance(ready.length === 1, `SandboxPool/${name} must have exactly one Ready condition`);
  requireConformance(
    ready[0].status === "True" && ready[0].observedGeneration === generation,
    `SandboxPool/${name} is not currently certified: ${ready[0].reason ?? "unknown"}: ${ready[0].message ?? ""}`,
  );
}

/// Return the current-generation pool condition that cannot converge without
/// operator intervention.
///
/// Most `Ready=False` reasons are ordinary certification progress and must be
/// allowed to reconcile. `CleanupBlocked` is terminal: waiting the full CI
/// timeout cannot change it and hides the exact reason maintainers need.
export function sandboxPoolCertificationBlocker(
  pool: ConformanceObject,
  name: string,
): string | undefined {
  const generation = pool.metadata?.generation;
  const ready = (pool.status?.conditions ?? []).find((condition) => condition.type === "Ready");
  if (
    generation === undefined
    || pool.status?.observedGeneration !== generation
    || ready?.observedGeneration !== generation
    || ready.status !== "False"
    || ready.reason !== "CleanupBlocked"
  ) {
    return undefined;
  }
  return `SandboxPool/${name} is fail-closed at ${ready.reason}: ${ready.message ?? "no detail"}`;
}

async function waitForCertifiedPool(args: Args, name: string): Promise<void> {
  const deadline = Date.now() + args.timeoutSeconds * 1000;
  let lastError = `SandboxPool/${name} has not reported certification`;
  while (Date.now() < deadline) {
    let current: ConformanceObject;
    try {
      current = await kubectlJson<ConformanceObject>(args, [
        "get", "sandboxpool.kobe.kunobi.ninja", name, "-n", args.namespace,
      ]);
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error);
      await Bun.sleep(1_000);
      continue;
    }
    const blocker = sandboxPoolCertificationBlocker(current, name);
    requireConformance(blocker === undefined, blocker ?? "unreachable certification blocker");
    try {
      assertCertifiedPool(current, name);
      return;
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error);
    }
    await Bun.sleep(1_000);
  }
  throw new Error(`${lastError} (timed out after ${args.timeoutSeconds}s)`);
}

/// Privileged setup evidence for #76, deliberately separate from the public
/// contract suite. It proves the harness created the exact two identities,
/// managed runtime, receipt-capable child pool, and both current-generation
/// SandboxPool certifications before any caller assertion is allowed to run.
async function sandboxConformancePreflight(args: Args): Promise<void> {
  const state = loadState();
  requireConformance(state, "no e2e state exists; run `up --sandbox-conformance` first");
  requireConformance(state.cluster === args.cluster, `state belongs to cluster '${state.cluster}', not '${args.cluster}'`);
  requireConformance(state.endpoint === args.endpoint, `state belongs to endpoint '${state.endpoint}', not '${args.endpoint}'`);
  requireConformance(state.sandboxConformance, "environment was not created with --sandbox-conformance");
  requireConformance(state.sandboxFixture, "environment did not record a Sandbox workload fixture");
  requireConformance(
    /^127\.0\.0\.1:\d+$/.test(state.sandboxFixture.registrySource),
    `fixture registry source is not loopback-only: '${state.sandboxFixture.registrySource}'`,
  );
  requireConformance(
    state.sandboxFixture.imageRef.startsWith(`${state.sandboxFixture.registrySource}/kobe-sandbox-e2e:`),
    `fixture image '${state.sandboxFixture.imageRef}' does not belong to the run-owned registry`,
  );
  await waitForRegistry(`http://${state.sandboxFixture.registrySource}`);
  await runCommand(["docker", "manifest", "inspect", "--insecure", state.sandboxFixture.imageRef], {
    step: `run-owned registry no longer contains '${state.sandboxFixture.imageRef}'`,
  });
  await waitForEndpointServing(args);

  step("Verifying exact Sandbox conformance fixtures");
  for (const [resource, name] of [
    ["secret", DEMO_TOKEN_SECRET],
    ["secret", DEMO_OTHER_TOKEN_SECRET],
    ["bootstrapconfig.kobe.kunobi.ninja", DEMO_SANDBOX_BOOTSTRAP],
  ]) {
    await kubectl(args, ["get", resource, name, "-n", args.namespace], {
      step: `required fixture ${resource}/${name} is absent`,
    });
  }

  const clusterPool = await kubectlJson<ConformanceObject>(args, [
    "get", "clusterpool.kobe.kunobi.ninja", DEMO_K3S_POOL, "-n", args.namespace,
  ]);
  const clusterSpec = clusterPool.spec ?? {};
  const backend = clusterSpec.backend as Record<string, unknown> | undefined;
  requireConformance(backend?.type === "k3s", `ClusterPool/${DEMO_K3S_POOL} is not a receipt-capable k3s backend`);
  requireConformance(clusterSpec.diagnostics === undefined, `ClusterPool/${DEMO_K3S_POOL} enables unreceipted diagnostics`);
  const bootstraps = clusterSpec.bootstraps;
  requireConformance(
    Array.isArray(bootstraps)
      && bootstraps.some((entry) => entry && typeof entry === "object" && (entry as Record<string, unknown>).name === DEMO_SANDBOX_BOOTSTRAP),
    `ClusterPool/${DEMO_K3S_POOL} does not name BootstrapConfig/${DEMO_SANDBOX_BOOTSTRAP}`,
  );
  const cluster = clusterSpec.cluster as Record<string, unknown> | undefined;
  requireConformance(cluster?.kubeletSharedMount === undefined, `ClusterPool/${DEMO_K3S_POOL} exposes an unreceipted kubelet mount`);
  const mirrors = cluster?.registryMirrors as Record<string, unknown> | undefined;
  requireConformance(
    Array.isArray(mirrors?.[state.sandboxFixture.registrySource])
      && (mirrors?.[state.sandboxFixture.registrySource] as unknown[]).includes(state.sandboxFixture.mirrorEndpoint),
    `ClusterPool/${DEMO_K3S_POOL} does not route '${state.sandboxFixture.registrySource}' through the run-owned registry`,
  );

  for (const [policyName, secretName] of [
    [DEMO_POLICY, DEMO_TOKEN_SECRET],
    [DEMO_OTHER_POLICY, DEMO_OTHER_TOKEN_SECRET],
  ] as const) {
    const policy = await kubectlJson<ConformanceObject>(args, [
      "get", "accesspolicy.kobe.kunobi.ninja", policyName, "-n", args.namespace,
    ]);
    const auth = policy.spec?.auth as Record<string, unknown> | undefined;
    const tokenAuth = auth?.token as Record<string, unknown> | undefined;
    requireConformance(tokenAuth?.secretRef === secretName, `AccessPolicy/${policyName} does not reference Secret/${secretName}`);
    assertSandboxPolicy(policy, policyName);
  }

  for (const [name, placement] of [
    [DEMO_SANDBOX_POOL_MANAGEMENT, "management"],
    [DEMO_SANDBOX_POOL_CHILD, "childCluster"],
  ] as const) {
    const pool = await kubectlJson<ConformanceObject>(args, [
      "get", "sandboxpool.kobe.kunobi.ninja", name, "-n", args.namespace,
    ]);
    const actualPlacement = pool.spec?.placement as Record<string, unknown> | undefined;
    const template = pool.spec?.template as Record<string, unknown> | undefined;
    const containers = template?.containers;
    requireConformance(actualPlacement?.type === placement, `SandboxPool/${name} has placement ${String(actualPlacement?.type)}, expected ${placement}`);
    if (placement === "childCluster") {
      requireConformance(actualPlacement.clusterPoolRef === DEMO_K3S_POOL, `SandboxPool/${name} does not target ClusterPool/${DEMO_K3S_POOL}`);
    }
    requireConformance(template?.runnerPath === "/kobe-runner", `SandboxPool/${name} does not enable durable execution`);
    requireConformance(
      Array.isArray(containers)
        && containers.some((container) => container && typeof container === "object" && (container as Record<string, unknown>).image === state.sandboxFixture?.imageRef),
      `SandboxPool/${name} does not use the run-owned fixture image`,
    );
    const ready = (pool.status?.conditions ?? []).find((condition) => condition.type === "Ready");
    if (ready?.status === "False" && ready.message?.includes("not implemented")) {
      throw new Error(
        `Sandbox conformance preflight: SandboxPool/${name} reports an unresolved certification implementation: ${ready.message}`,
      );
    }
  }

  await kubectl(args, [
    "rollout", "status", "deployment/agent-sandbox-controller", "-n", "agent-sandbox-system", `--timeout=${args.timeoutSeconds}s`,
  ], { step: "managed Agent Sandbox controller did not become available" });
  await kubectl(args, [
    "wait", `clusterpool.kobe.kunobi.ninja/${DEMO_K3S_POOL}`, "-n", args.namespace,
    "--for=jsonpath={.status.ready}=1", `--timeout=${args.timeoutSeconds}s`,
  ], { step: `ClusterPool/${DEMO_K3S_POOL} did not retain one Ready child fixture` });

  await waitForCertifiedPool(args, DEMO_SANDBOX_POOL_MANAGEMENT);
  await waitForCertifiedPool(args, DEMO_SANDBOX_POOL_CHILD);
  step("Management and child placement pools are certified");
}

async function down(args: Args): Promise<void> {
  await ensureMiseTools();
  await removeSandboxRegistry(args.cluster);
  if (!(await clusterExists(args.cluster))) {
    clearStateFiles();
    info(`kind cluster '${args.cluster}' does not exist`);
    return;
  }

  step(`Deleting kind cluster '${args.cluster}'`);
  const kind = await resolveTool("kind");
  await runCommand([kind, "delete", "cluster", "--name", args.cluster], {
    step: `failed to delete kind cluster '${args.cluster}'`,
  });
  clearStateFiles();
}

// ---------------------------------------------------------------------------
// Conformance harness (#138)
//
// Three capabilities the dual-placement suite (tests/sandbox_conformance.rs)
// cannot have and must not have. The suite asserts only through the public
// HTTP API, because a suite that could reach around the API could pass while
// the API was broken — and one that could break its own target could mask a
// break it did not intend. So the disturbance lives here, on the other side of
// a process boundary, and the suite still asserts nothing but the contract.
// ---------------------------------------------------------------------------

/// The shape of a `SandboxLease` this harness reads. Deliberately partial:
/// naming only the fields that are waited on means a CRD field added later
/// cannot silently change what a stage means.
type SandboxLeaseObject = {
  metadata?: {
    name?: string;
    uid?: string;
    annotations?: Record<string, string>;
  };
  status?: {
    phase?: string;
    provisioningDeadline?: string;
    readyAt?: string;
    releaseCause?: string;
    target?: {
      namespace?: string;
      childClusterLease?: { uid?: string };
      childClusterInstance?: { name?: string; uid?: string };
      sandboxClaim?: { uid?: string };
      sandbox?: { uid?: string };
      pod?: { uid?: string };
    };
    conditions?: Array<{ type?: string; status?: string; reason?: string }>;
  };
};

type LeaseStage = {
  /// What the operator has finished doing, in the words of #76's matrix.
  readonly describe: string;
  readonly reached: (lease: SandboxLeaseObject) => boolean;
};

function conditionIsTrue(lease: SandboxLeaseObject, type: string): boolean {
  return (lease.status?.conditions ?? []).some(
    (condition) => condition.type === type && condition.status === "True",
  );
}

/// The points a restart can be aimed at.
///
/// Every one of these is a signal the operator writes. Identity markers are
/// monotonic; transient phase windows are paired with their durable checkpoint
/// so a default or partially-written status cannot satisfy the stage.
///
/// One stage #76 asks for is deliberately ABSENT:
///
/// - `bootstrap`: management placement checkpoints `SandboxTemplate` or
///   `SandboxWarmPool` provenance, but child placement exposes no equivalent
///   outer-lease marker. This stage registry is shared by both placements, so
///   a placement-neutral bootstrap stage would hang for child leases.
export const LEASE_STAGES: Record<string, LeaseStage> = {
  admitted: {
    describe: "the HTTP API has admitted the lease and the controller may act",
    reached: (lease) =>
      lease.metadata?.annotations?.["kobe.kunobi.ninja/sandbox-admission"] === "admitted",
  },
  provisioning: {
    describe: "provisioning has begun and its absolute deadline is checkpointed",
    reached: (lease) =>
      lease.status?.phase === "Provisioning" && Boolean(lease.status?.provisioningDeadline),
  },
  provenance: {
    describe: "the first provenance write has landed",
    reached: (lease) => Boolean(lease.status?.target?.namespace),
  },
  bind: {
    describe: "the internal ClusterLease for a child-placed Sandbox is bound and recorded",
    reached: (lease) => Boolean(lease.status?.target?.childClusterLease?.uid),
  },
  instance: {
    describe: "the child ClusterInstance is recorded by UID",
    reached: (lease) => Boolean(lease.status?.target?.childClusterInstance?.uid),
  },
  claim: {
    describe: "the upstream SandboxClaim exists and is recorded by UID",
    reached: (lease) => Boolean(lease.status?.target?.sandboxClaim?.uid),
  },
  access: {
    describe: "the Pod a per-lease scoped credential can name is recorded",
    reached: (lease) => Boolean(lease.status?.target?.pod?.uid),
  },
  canary: {
    describe: "the readiness canary has run inside the Sandbox and passed",
    reached: (lease) => conditionIsTrue(lease, "ReadinessCanary"),
  },
  ready: {
    describe: "the lease is Ready and its runtime TTL has started",
    reached: (lease) => lease.status?.phase === "Ready",
  },
  teardown: {
    describe: "release has begun and its cause is checkpointed",
    reached: (lease) =>
      lease.status?.phase === "Releasing" && Boolean(lease.status?.releaseCause),
  },
  quarantined: {
    describe: "teardown could not be proven and capacity is withheld",
    reached: (lease) => lease.status?.phase === "Quarantined",
  },
  settled: {
    describe: "the lease reached a clean terminal state",
    reached: (lease) => lease.status?.phase === "Released" || lease.status?.phase === "Expired",
  },
};

export function leaseStageReached(stage: string, lease: SandboxLeaseObject): boolean {
  const definition = LEASE_STAGES[stage];
  if (!definition) {
    throw new Error(`unknown stage '${stage}' (expected one of: ${Object.keys(LEASE_STAGES).join(", ")})`);
  }
  return definition.reached(lease);
}

function contextFor(args: Args): string {
  return args.kubeContext ?? kubeContext(args.cluster);
}

async function kubectl(
  args: Args,
  argv: string[],
  options?: { allowFailure?: boolean; step?: string; stream?: boolean },
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  const bin = await resolveTool("kubectl");
  return runCommand([bin, "--context", contextFor(args), ...argv], options);
}

async function kubectlJson<T>(args: Args, argv: string[], options?: { step?: string }): Promise<T> {
  const { stdout } = await kubectl(args, [...argv, "-o", "json"], options);
  return JSON.parse(stdout) as T;
}

/// Read one SandboxLease, or `null` while it does not exist yet.
///
/// Absence is not an error here: `restart-operator --wait-for-phase` is
/// routinely started in parallel with the lease's own creation, and treating
/// the gap as a failure would make the harness lose a race it is meant to win.
async function readSandboxLease(args: Args, lease: string): Promise<SandboxLeaseObject | null> {
  const { stdout, exitCode } = await kubectl(
    args,
    ["get", "sandboxleases.kobe.kunobi.ninja", "-n", args.namespace, lease, "-o", "json"],
    { allowFailure: true },
  );
  if (exitCode !== 0) return null;
  return JSON.parse(stdout) as SandboxLeaseObject;
}

async function waitForLeaseStage(args: Args, lease: string, stage: string): Promise<void> {
  const definition = LEASE_STAGES[stage];
  if (!definition) {
    throw new Error(`unknown stage '${stage}' (expected one of: ${Object.keys(LEASE_STAGES).join(", ")})`);
  }

  step(`Waiting for sandbox lease '${lease}' to reach '${stage}' (${definition.describe})`);
  const deadline = Date.now() + args.timeoutSeconds * 1000;
  let lastPhase = "<absent>";
  for (;;) {
    const observed = await readSandboxLease(args, lease);
    if (observed && definition.reached(observed)) {
      info(`  - reached '${stage}' (phase=${observed.status?.phase ?? "<none>"})`);
      return;
    }
    lastPhase = observed?.status?.phase ?? "<absent>";
    if (Date.now() >= deadline) {
      throw new Error(
        `sandbox lease '${lease}' never reached '${stage}' within ${args.timeoutSeconds}s (last phase: ${lastPhase})`,
      );
    }
    await Bun.sleep(1000);
  }
}

/// Resolve the operator Deployment by selector rather than by name.
///
/// Its name is the Helm template `kobe.fullname`, which is `kobe` for a release
/// called `kobe` and `<release>-kobe` for anything else. Hardcoding either
/// would, against the other, restart nothing at all — and `kubectl rollout
/// restart` on a name that does not exist is the kind of failure that reads as
/// "the restart had no effect" rather than as a broken harness.
async function operatorDeployment(args: Args): Promise<string> {
  const { stdout } = await kubectl(args, [
    "get",
    "deployment",
    "-n",
    args.namespace,
    "-l",
    `app.kubernetes.io/name=kobe,app.kubernetes.io/instance=${args.release}`,
    "-o",
    "jsonpath={range .items[*]}{.metadata.name}{\"\\n\"}{end}",
  ]);
  const names = stdout.split("\n").map((line) => line.trim()).filter(Boolean);
  if (names.length !== 1) {
    throw new Error(
      `expected exactly one operator Deployment in '${args.namespace}' for release '${args.release}', found: ${names.join(", ") || "none"}`,
    );
  }
  return names[0];
}

type CoordinationLease = { spec?: { holderIdentity?: string; renewTime?: string } };

async function leaderRenewTime(args: Args): Promise<string | undefined> {
  const { stdout, exitCode } = await kubectl(
    args,
    ["get", "lease.coordination.k8s.io", "-n", args.namespace, OPERATOR_LEADER_LEASE, "-o", "json"],
    { allowFailure: true },
  );
  if (exitCode !== 0) return undefined;
  return (JSON.parse(stdout) as CoordinationLease).spec?.renewTime;
}

/// Wait until the operator answers `/readyz`.
///
/// Necessary but NOT sufficient — see `waitForFreshLeader`.
async function waitForEndpointServing(args: Args): Promise<void> {
  step(`Waiting for ${args.endpoint}/readyz`);
  const deadline = Date.now() + args.timeoutSeconds * 1000;
  let lastError = "no attempt made";
  for (;;) {
    try {
      const response = await fetch(`${args.endpoint}/readyz`);
      if (response.ok) {
        info("  - serving");
        return;
      }
      lastError = `HTTP ${response.status}: ${(await response.text()).trim()}`;
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error);
    }
    if (Date.now() >= deadline) {
      throw new Error(`operator did not serve /readyz within ${args.timeoutSeconds}s (${lastError})`);
    }
    await Bun.sleep(1000);
  }
}

/// Wait until a NEW process is renewing the leader Lease.
///
/// `kubectl rollout status` returning and `/readyz` answering both only prove
/// the HTTP server is up, and the HTTP server is up in every replica. The
/// reconcilers — the thing a restart scenario is actually about — run solely in
/// whichever replica holds this Lease, and it is acquired after the server
/// starts. Acting on the sooner signal would drive a cluster whose controllers
/// are not running yet, and the scenario would blame the operator for a race
/// the harness created.
///
/// Freshness is judged by `renewTime` advancing rather than by matching
/// `holderIdentity` against a pod name: the identity format belongs to the
/// leader-election library, and a harness that asserted its shape would break
/// on a dependency bump for no reason.
async function waitForFreshLeader(args: Args, before: string | undefined): Promise<void> {
  step("Waiting for a fresh leader to renew the operator Lease");
  const deadline = Date.now() + args.timeoutSeconds * 1000;
  for (;;) {
    const now = await leaderRenewTime(args);
    if (now && now !== before) {
      info(`  - leading again (renewTime=${now})`);
      return;
    }
    if (Date.now() >= deadline) {
      throw new Error(
        `no replica took the '${OPERATOR_LEADER_LEASE}' Lease within ${args.timeoutSeconds}s (renewTime still ${before ?? "<absent>"})`,
      );
    }
    await Bun.sleep(1000);
  }
}

async function restartOperator(args: Args): Promise<void> {
  if (args.waitForStage) {
    if (!args.lease) {
      throw new Error("--wait-for-phase needs --lease: a stage is a property of one lease, not of the cluster");
    }
    await waitForLeaseStage(args, args.lease, args.waitForStage);
  }

  const deployment = await operatorDeployment(args);
  // Captured BEFORE the restart: the comparison in `waitForFreshLeader` is
  // against this exact value, and reading it afterwards would compare the new
  // leader with itself and return immediately.
  const renewedBefore = await leaderRenewTime(args);

  step(`Restarting deployment '${deployment}' in namespace '${args.namespace}'`);
  await kubectl(args, ["rollout", "restart", `deployment/${deployment}`, "-n", args.namespace], {
    step: `failed to restart deployment '${deployment}'`,
  });
  await waitForOperatorRollout(args, deployment, renewedBefore);
  step("Operator is serving and leading again");
}

/// Wait for an already-requested Deployment mutation to replace the operator
/// and restore both its HTTP and controller halves.
async function waitForOperatorRollout(
  args: Args,
  deployment: string,
  renewedBefore: string | undefined,
): Promise<void> {
  await kubectl(
    args,
    [
      "rollout",
      "status",
      `deployment/${deployment}`,
      "-n",
      args.namespace,
      `--timeout=${args.timeoutSeconds}s`,
    ],
    { step: `deployment '${deployment}' did not roll out`, stream: true },
  );

  await waitForEndpointServing(args);
  await waitForFreshLeader(args, renewedBefore);
}

// ---------------------------------------------------------------------------
// Failure injection
// ---------------------------------------------------------------------------

type PolicyRule = {
  apiGroups?: string[];
  resources?: string[];
  verbs?: string[];
  resourceNames?: string[];
};

type FailureState = {
  kind: FailureKind;
  capturedAt: string;
  clusterRole?: { name: string; rules: PolicyRule[] };
  services?: Array<{ namespace: string; name: string; selector: Record<string, string> | null }>;
  operatorEnvironment?: {
    deployment: string;
    previousValue?: string;
    previouslyPresent: boolean;
    expectProcessExit: boolean;
    pods: OperatorPodSnapshot[];
  };
};

type OperatorPodSnapshot = {
  name: string;
  uid: string;
  restartCount: number;
  lastExitCode?: number;
};

type DeploymentObject = {
  spec?: {
    template?: {
      spec?: {
        containers?: Array<{
          name?: string;
          env?: Array<{ name?: string; value?: string; valueFrom?: unknown }>;
        }>;
      };
    };
  };
};

type PodListObject = {
  items?: Array<{
    metadata?: { name?: string; uid?: string };
    status?: {
      containerStatuses?: Array<{
        name?: string;
        restartCount?: number;
        lastState?: { terminated?: { exitCode?: number } };
      }>;
    };
  }>;
};

function isExecutionCrashFailure(kind: FailureKind): boolean {
  return kind.startsWith("execution-");
}

function failureStatePath(kind: FailureKind): string {
  return `${FAILURE_DIR}/${kind}.json`;
}

/// Remove one verb from one resource in one API group, leaving every other
/// grant in the ClusterRole byte-identical.
///
/// RBAC has no deny, so the only way to take a permission away is to narrow the
/// rule that grants it — and a rule usually grants several resources at once.
/// Narrowing the whole rule would revoke the verb from its siblings too, and
/// the scenario would then be testing a much larger breakage than it named. So
/// a matching rule is SPLIT: the siblings keep everything they had, and the
/// target resource gets its own rule minus the one verb.
///
/// A wildcard rule is refused rather than edited. `*` cannot be narrowed by
/// subtraction — the split would leave the wildcard rule still granting the
/// verb, and the injection would silently do nothing at all.
export function revokeVerb(
  rules: PolicyRule[],
  target: RevocationTarget,
): { rules: PolicyRule[]; revoked: number } {
  let revoked = 0;
  const next: PolicyRule[] = [];

  for (const rule of rules) {
    const groups = rule.apiGroups ?? [];
    const resources = rule.resources ?? [];
    const verbs = rule.verbs ?? [];

    const grants =
      (groups.includes("*") || groups.includes(target.apiGroup)) &&
      (resources.includes("*") || resources.includes(target.resource)) &&
      (verbs.includes("*") || verbs.includes(target.verb));
    if (!grants) {
      next.push(rule);
      continue;
    }

    const named =
      groups.includes(target.apiGroup) && resources.includes(target.resource) && verbs.includes(target.verb);
    if (!named) {
      throw new Error(
        `cannot revoke ${target.apiGroup || "core"}/${target.resource}:${target.verb}: rule ${JSON.stringify(rule)} grants it through a wildcard, which subtraction cannot narrow`,
      );
    }

    revoked += 1;
    const otherGroups = groups.filter((group) => group !== target.apiGroup);
    if (otherGroups.length > 0) {
      next.push({ ...rule, apiGroups: otherGroups });
    }
    const otherResources = resources.filter((resource) => resource !== target.resource);
    if (otherResources.length > 0) {
      next.push({ ...rule, apiGroups: [target.apiGroup], resources: otherResources });
    }
    const remainingVerbs = verbs.filter((verb) => verb !== target.verb);
    if (remainingVerbs.length > 0) {
      next.push({
        ...rule,
        apiGroups: [target.apiGroup],
        resources: [target.resource],
        verbs: remainingVerbs,
      });
    }
  }

  return { rules: next, revoked };
}

function loadFailureState(kind: FailureKind): FailureState | null {
  const path = failureStatePath(kind);
  if (!existsSync(path)) return null;
  return JSON.parse(readFileSync(path, "utf8")) as FailureState;
}

async function saveFailureState(state: FailureState): Promise<void> {
  await runCommand(["mkdir", "-p", FAILURE_DIR], { step: "failed to create the failure state directory" });
  await Bun.write(failureStatePath(state.kind), JSON.stringify(state, null, 2));
}

/// Refuse to inject a failure that is already injected.
///
/// The second capture would record the ALREADY BROKEN state as the original,
/// and `clear-failure` would then faithfully restore the breakage — leaving a
/// cluster that looks repaired and is not. Every scenario after it would fail
/// for a reason that has nothing to do with what it asserts.
function refuseDoubleInjection(kind: FailureKind): void {
  const existing = loadFailureState(kind);
  if (existing) {
    throw new Error(
      `failure '${kind}' is already injected (captured ${existing.capturedAt}); run 'clear-failure --kind ${kind}' first`,
    );
  }
}

function revocationsFor(args: Args): RevocationTarget[] {
  if (args.failure === "teardown-unverifiable") {
    return [...UNVERIFIABLE_TEARDOWN_REVOCATIONS];
  }
  const { apiGroup, resource, verb } = args.revocation;
  if (apiGroup === undefined || !resource || !verb) {
    throw new Error("--kind rbac-revoke needs --api-group, --resource and --verb");
  }
  return [{ apiGroup, resource, verb }];
}

async function operatorPodSnapshots(args: Args): Promise<OperatorPodSnapshot[]> {
  const pods = await kubectlJson<PodListObject>(args, [
    "get",
    "pod",
    "-n",
    args.namespace,
    "-l",
    `app.kubernetes.io/name=kobe,app.kubernetes.io/instance=${args.release}`,
  ]);
  return (pods.items ?? []).flatMap((pod) => {
    const status = pod.status?.containerStatuses?.find((candidate) => candidate.name === OPERATOR_CONTAINER);
    const name = pod.metadata?.name;
    const uid = pod.metadata?.uid;
    if (!name || !uid || !status) return [];
    return [
      {
        name,
        uid,
        restartCount: status.restartCount ?? 0,
        lastExitCode: status.lastState?.terminated?.exitCode,
      },
    ];
  });
}

async function mutateOperatorEnvironment(args: Args, deployment: string, assignment: string): Promise<void> {
  const renewedBefore = await leaderRenewTime(args);
  await kubectl(
    args,
    [
      "set",
      "env",
      `deployment/${deployment}`,
      "-n",
      args.namespace,
      `--containers=${OPERATOR_CONTAINER}`,
      assignment,
    ],
    { step: `failed to set ${EXECUTION_CRASH_ENV} on deployment '${deployment}'` },
  );
  await waitForOperatorRollout(args, deployment, renewedBefore);
}

/// Arm one exact process boundary without exposing a crash selector through the
/// public execution request. The Deployment environment is administrator
/// state; the value also carries one lease and idempotency key so unrelated
/// traffic cannot trip the fault while the live scenario runs.
async function injectExecutionCrash(args: Args): Promise<void> {
  if (!args.lease || !args.idempotencyKey) {
    throw new Error(`--kind ${args.failure} needs --lease and --idempotency-key`);
  }
  refuseDoubleInjection(args.failure);

  const deployment = await operatorDeployment(args);
  const object = await kubectlJson<DeploymentObject>(args, [
    "get",
    "deployment",
    deployment,
    "-n",
    args.namespace,
  ]);
  const container = object.spec?.template?.spec?.containers?.find(
    (candidate) => candidate.name === OPERATOR_CONTAINER,
  );
  if (!container) {
    throw new Error(`deployment '${deployment}' has no '${OPERATOR_CONTAINER}' container`);
  }
  const previous = container.env?.find((entry) => entry.name === EXECUTION_CRASH_ENV);
  if (previous?.valueFrom) {
    throw new Error(`${EXECUTION_CRASH_ENV} uses valueFrom; refusing to replace administrator-owned configuration`);
  }

  const state: FailureState = {
    kind: args.failure,
    capturedAt: new Date().toISOString(),
    operatorEnvironment: {
      deployment,
      previouslyPresent: previous !== undefined,
      previousValue: previous?.value,
      // The two target-side windows kill the short-lived runner exec inside the
      // Sandbox. The control-plane boundaries kill the operator container.
      expectProcessExit: args.failure === "execution-after-running-before-target-reservation"
        || args.failure === "execution-after-ack-before-status",
      pods: [],
    },
  };
  // Persist the original before mutation, so a killed harness can still put
  // the Deployment back exactly as it found it.
  await saveFailureState(state);
  await mutateOperatorEnvironment(
    args,
    deployment,
    `${EXECUTION_CRASH_ENV}=${args.failure}:${args.lease}:${args.idempotencyKey}`,
  );

  const pods = await operatorPodSnapshots(args);
  if (pods.length === 0) {
    throw new Error(`deployment '${deployment}' has no observable '${OPERATOR_CONTAINER}' container after rollout`);
  }
  state.operatorEnvironment!.pods = pods;
  await saveFailureState(state);
  step(`Injected '${args.failure}' for SandboxLease '${args.lease}'`);
}

async function waitForInjectedOperatorExit(args: Args, baselines: OperatorPodSnapshot[]): Promise<void> {
  const deadline = Date.now() + args.timeoutSeconds * 1000;
  let last = "no pod observation";
  for (;;) {
    const current = await operatorPodSnapshots(args);
    for (const baseline of baselines) {
      const observed = current.find((pod) => pod.uid === baseline.uid);
      if (
        observed &&
        observed.restartCount > baseline.restartCount &&
        observed.lastExitCode === EXECUTION_CRASH_EXIT_CODE
      ) {
        info(
          `  - observed ${observed.name} exit ${EXECUTION_CRASH_EXIT_CODE} (restart ${baseline.restartCount} -> ${observed.restartCount})`,
        );
        return;
      }
    }
    last = current
      .map((pod) => `${pod.name}:uid=${pod.uid},restarts=${pod.restartCount},last=${pod.lastExitCode ?? "none"}`)
      .join("; ");
    if (Date.now() >= deadline) {
      throw new Error(
        `operator never exited with injected status ${EXECUTION_CRASH_EXIT_CODE} within ${args.timeoutSeconds}s (${last})`,
      );
    }
    await Bun.sleep(500);
  }
}

async function injectRbacRevocation(args: Args): Promise<void> {
  // Resolved before anything is read or written: an incomplete request should
  // say so, not fail three calls later with a message about a Deployment.
  const targets = revocationsFor(args);
  refuseDoubleInjection(args.failure);
  // Same name as the Deployment: both render from `kobe.fullname`. Resolving
  // the Deployment first means a release named anything at all still finds its
  // own ClusterRole rather than a same-labelled one from another release.
  const name = await operatorDeployment(args);
  const role = await kubectlJson<{ rules: PolicyRule[] }>(args, ["get", "clusterrole", name], {
    step: `failed to read ClusterRole '${name}'`,
  });
  const original = role.rules;

  let rules = original;
  for (const target of targets) {
    const result = revokeVerb(rules, target);
    if (result.revoked === 0) {
      throw new Error(
        `ClusterRole '${name}' never granted ${target.apiGroup || "core"}/${target.resource}:${target.verb}, so revoking it would prove nothing`,
      );
    }
    info(`  - revoking ${target.apiGroup || "core"}/${target.resource}:${target.verb} (${result.revoked} rule(s))`);
    rules = result.rules;
  }

  await saveFailureState({
    kind: args.failure,
    capturedAt: new Date().toISOString(),
    clusterRole: { name, rules: original },
  });
  await kubectl(args, ["patch", "clusterrole", name, "--type=merge", "-p", JSON.stringify({ rules })], {
    step: `failed to narrow ClusterRole '${name}'`,
  });
  step(`Injected '${args.failure}' into ClusterRole '${name}'`);
}

type ServiceList = {
  items: Array<{
    metadata: { name: string; namespace: string };
    spec?: { selector?: Record<string, string> };
  }>;
};

/// Make a child cluster's API server unreachable without destroying it.
///
/// The Service in front of it keeps existing; only its selector is swapped for
/// one nothing carries, so it resolves to zero endpoints. Deleting the
/// StatefulSet instead would have made teardown succeed for the WRONG reason —
/// the property under test is what the operator does when it cannot REACH a
/// cluster that is still there, which is the case where releasing capacity
/// would be a double-booking rather than a cleanup.
async function injectChildApiUnreachable(args: Args): Promise<void> {
  // `--lease` rather than `--instance` is the form a conformance scenario can
  // actually use: the API strips `childClusterInstance` from what a caller may
  // read, on purpose, so the suite never learns the name. The harness reads it
  // from the CR instead — which is the whole reason the harness exists.
  refuseDoubleInjection(args.failure);
  const instance = args.instance ?? (await childInstanceOf(args));

  const found = await kubectlJson<ServiceList>(args, [
    "get",
    "service",
    "--all-namespaces",
    "-l",
    `${CHILD_CLUSTER_LABEL}=${instance}`,
  ]);
  if (found.items.length === 0) {
    throw new Error(
      `no Service carries ${CHILD_CLUSTER_LABEL}=${instance}; the instance may not exist, or its backend (vcluster installs an upstream Helm chart) may not stamp the label`,
    );
  }

  const captured = found.items.map((service) => ({
    namespace: service.metadata.namespace,
    name: service.metadata.name,
    selector: service.spec?.selector ?? null,
  }));
  await saveFailureState({
    kind: args.failure,
    capturedAt: new Date().toISOString(),
    services: captured,
  });

  for (const service of captured) {
    info(`  - severing ${service.namespace}/${service.name} (instance ${instance})`);
    await kubectl(
      args,
      [
        "patch",
        "service",
        service.name,
        "-n",
        service.namespace,
        "--type=merge",
        "-p",
        JSON.stringify({ spec: { selector: UNREACHABLE_SELECTOR } }),
      ],
      { step: `failed to sever Service '${service.namespace}/${service.name}'` },
    );
  }
  step(`Injected '${args.failure}' for ClusterInstance '${instance}'`);
}

/// Resolve the child cluster behind a lease, by reading the CR.
async function childInstanceOf(args: Args): Promise<string> {
  if (!args.lease) {
    throw new Error("--kind child-api-unreachable needs --instance <ClusterInstance> or --lease <id>");
  }
  const lease = await readSandboxLease(args, args.lease);
  if (!lease) {
    throw new Error(`sandbox lease '${args.lease}' does not exist`);
  }
  const instance = lease.status?.target?.childClusterInstance?.name;
  if (!instance) {
    throw new Error(
      `sandbox lease '${args.lease}' records no child ClusterInstance; a management-placed lease has no child API to sever`,
    );
  }
  return instance;
}

async function injectFailure(args: Args): Promise<void> {
  if (isExecutionCrashFailure(args.failure)) {
    await injectExecutionCrash(args);
    return;
  }
  if (args.failure === "child-api-unreachable") {
    await injectChildApiUnreachable(args);
    return;
  }
  await injectRbacRevocation(args);
}

async function clearFailure(args: Args): Promise<void> {
  const state = loadFailureState(args.failure);
  if (!state) {
    // Not an error. `clear-failure` is what a scenario runs on its way out,
    // including on the path where the injection itself failed — making that
    // path noisy would bury the real failure under a second one.
    info(`no '${args.failure}' failure is injected`);
    return;
  }

  let triggerFailure: Error | undefined;
  if (state.operatorEnvironment?.expectProcessExit) {
    step(`Waiting for the '${state.kind}' process exit`);
    try {
      await waitForInjectedOperatorExit(args, state.operatorEnvironment.pods);
    } catch (error) {
      triggerFailure = error instanceof Error ? error : new Error(String(error));
    }
  }

  if (state.operatorEnvironment) {
    const operator = state.operatorEnvironment;
    step(`Restoring ${EXECUTION_CRASH_ENV} on Deployment '${operator.deployment}'`);
    const assignment = operator.previouslyPresent
      ? `${EXECUTION_CRASH_ENV}=${operator.previousValue ?? ""}`
      : `${EXECUTION_CRASH_ENV}-`;
    await mutateOperatorEnvironment(args, operator.deployment, assignment);
  }

  if (state.clusterRole) {
    step(`Restoring ClusterRole '${state.clusterRole.name}'`);
    await kubectl(
      args,
      [
        "patch",
        "clusterrole",
        state.clusterRole.name,
        "--type=merge",
        "-p",
        JSON.stringify({ rules: state.clusterRole.rules }),
      ],
      { step: `failed to restore ClusterRole '${state.clusterRole.name}'` },
    );
  }

  for (const service of state.services ?? []) {
    step(`Restoring Service '${service.namespace}/${service.name}'`);
    await kubectl(
      args,
      [
        "patch",
        "service",
        service.name,
        "-n",
        service.namespace,
        "--type=merge",
        "-p",
        JSON.stringify({ spec: { selector: service.selector } }),
      ],
      { step: `failed to restore Service '${service.namespace}/${service.name}'` },
    );
  }

  // Removed LAST. A state file deleted before the restore landed would leave a
  // broken cluster that no longer knows it is broken.
  rmSync(failureStatePath(args.failure), { force: true });
  step(`Cleared '${args.failure}'`);
  if (triggerFailure) throw triggerFailure;
}

/// Delete a SandboxLease and the admission reservations it still holds.
///
/// Quarantine is deliberately terminal and deliberately keeps consuming
/// capacity: an operator can reconcile an under-counted pool, but nobody can
/// see a Sandbox that was quietly double-booked. That is the right product
/// behaviour and the wrong test behaviour — a scenario that proves quarantine
/// happens would otherwise withhold a slot from every scenario after it, and
/// they would fail by queueing, for a reason none of them assert.
///
/// So the exit exists here, in the harness, and nowhere in the API. That is the
/// point: the "operator intervention" quarantine requires is exactly what this
/// is, performed against the cluster rather than through the contract. It only
/// wakes the controller and verifies its proof-first cleanup; it never deletes
/// protected reservations itself.
async function reapLease(args: Args): Promise<void> {
  if (!args.lease) {
    throw new Error("reap-lease needs --lease <id>");
  }
  const lease = await readSandboxLease(args, args.lease);
  if (!lease) {
    info(`sandbox lease '${args.lease}' does not exist`);
    return;
  }

  const uid = lease.metadata?.uid;
  if (!uid) throw new Error(`sandbox lease '${args.lease}' has no UID; refusing an unfenced reap`);

  const ledgers = await kubectlJson<{ items?: Array<{ metadata?: { name?: string } }> }>(args, [
    "get",
    "namespace",
    "-l",
    SANDBOX_LEDGER_NAMESPACE_LABEL,
  ]);
  const ledgerNamespaces = (ledgers.items ?? []).flatMap((namespace) => namespace.metadata?.name ?? []);
  if (ledgerNamespaces.length !== 1) {
    throw new Error(
      `expected exactly one ${SANDBOX_LEDGER_NAMESPACE_LABEL} namespace, found ${ledgerNamespaces.length}: ${ledgerNamespaces.join(", ")}`,
    );
  }

  // Clearing the injected failure restores evidence, but a quarantined lease
  // otherwise waits for its periodic retry. Touch metadata to enqueue it now;
  // the controller must prove absence and release its own ledger objects in
  // the safe order. The harness never impersonates the protected writer and
  // never frees capacity ahead of that proof.
  step(`Requesting an immediate evidence retry for sandbox lease '${args.lease}'`);
  await kubectl(
    args,
    [
      "annotate",
      "sandboxleases.kobe.kunobi.ninja",
      "-n",
      args.namespace,
      args.lease,
      `kobe.kunobi.ninja/e2e-reap-at=${Date.now()}`,
      "--overwrite",
    ],
    { step: `failed to enqueue sandbox lease '${args.lease}' for evidence retry` },
  );

  const deadline = Date.now() + args.timeoutSeconds * 1000;
  for (;;) {
    const current = await readSandboxLease(args, args.lease);
    if (!current) break;
    const phase = current.status?.phase;
    if (
      (phase === "Released" || phase === "Expired")
      && conditionIsTrue(current, "FootprintAbsent")
      && conditionIsTrue(current, "CleanupVerified")
    ) {
      break;
    }
    if (Date.now() >= deadline) {
      throw new Error(
        `sandbox lease '${args.lease}' did not prove teardown after intervention (phase=${phase ?? "none"})`,
      );
    }
    await Bun.sleep(1_000);
  }

  const remaining = await kubectlJson<{ items?: Array<{ metadata?: { name?: string } }> }>(args, [
    "get",
    "lease.coordination.k8s.io",
    "-n",
    ledgerNamespaces[0],
    "-l",
    `${SANDBOX_LEASE_UID_LABEL}=${uid}`,
  ]);
  const reservationNames = (remaining.items ?? []).flatMap((reservation) => reservation.metadata?.name ?? []);
  if (reservationNames.length !== 0) {
    throw new Error(
      `sandbox lease '${args.lease}' settled but still owns admission reservations: ${reservationNames.join(", ")}`,
    );
  }

  step(`Deleting sandbox lease '${args.lease}'`);
  await kubectl(
    args,
    [
      "delete",
      "sandboxleases.kobe.kunobi.ninja",
      "-n",
      args.namespace,
      args.lease,
      "--ignore-not-found",
      `--timeout=${args.timeoutSeconds}s`,
    ],
    { step: `failed to delete sandbox lease '${args.lease}'` },
  );
}

// ---------------------------------------------------------------------------
// pty harness
// ---------------------------------------------------------------------------

/// Decode a `--send` payload into the bytes a keyboard would have produced.
///
/// Control characters have to be expressible on a command line, and the ones
/// that matter most are precisely the ones that cannot be typed into an
/// argument: `\r` ends a line and `\x03` is the Ctrl-C whose arrival at the
/// workload is the property being tested.
export function decodeKeystrokes(spec: string): Uint8Array {
  const bytes: number[] = [];
  for (let i = 0; i < spec.length; i += 1) {
    if (spec[i] !== "\\") {
      bytes.push(...new TextEncoder().encode(spec[i]));
      continue;
    }
    const escape = spec[i + 1];
    i += 1;
    switch (escape) {
      case "r":
        bytes.push(0x0d);
        break;
      case "n":
        bytes.push(0x0a);
        break;
      case "t":
        bytes.push(0x09);
        break;
      case "e":
        bytes.push(0x1b);
        break;
      case "0":
        bytes.push(0x00);
        break;
      case "\\":
        bytes.push(0x5c);
        break;
      case "x": {
        const hex = spec.slice(i + 1, i + 3);
        if (!/^[0-9a-fA-F]{2}$/.test(hex)) {
          throw new Error(`\\x must be followed by two hex digits, got '${hex}'`);
        }
        bytes.push(Number.parseInt(hex, 16));
        i += 2;
        break;
      }
      default:
        throw new Error(`unknown escape '\\${escape ?? ""}' in --send payload`);
    }
  }
  return new Uint8Array(bytes);
}

/// Run argv on a pty, forward this process's stdin to it, and exit with its
/// status. `sys.argv[1:]` because `-c` occupies `sys.argv[0]`.
const PTY_SPAWN = "import os,pty,sys; sys.exit(os.waitstatus_to_exitcode(pty.spawn(sys.argv[1:])))";

/// A pty bridge whose parent can apply one deterministic resize with SIGUSR1.
///
/// The resize is deliberately out-of-band. Sending an escape sequence through
/// stdin would test a shell convention, not the terminal-size ioctl that
/// `kobe attach` observes and forwards on channel 4.
const RESIZABLE_PTY_SPAWN = String.raw`
import fcntl, os, pty, select, signal, struct, sys, termios

def set_size(spec):
    width, height = (int(part) for part in spec.split("x", 1))
    fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", height, width, 0, 0))

pid, master = pty.fork()
if pid == 0:
    os.execvp(sys.argv[1], sys.argv[1:])

set_size(os.environ.get("KOBE_E2E_PTY_INITIAL", "80x24"))
signal.signal(signal.SIGUSR1, lambda _signal, _frame: set_size(os.environ["KOBE_E2E_PTY_RESIZE"]))

try:
    while True:
        try:
            ready, _, _ = select.select([master, 0], [], [])
        except InterruptedError:
            continue
        if master in ready:
            try:
                data = os.read(master, 65536)
            except OSError:
                break
            if not data:
                break
            os.write(1, data)
        if 0 in ready:
            data = os.read(0, 65536)
            if not data:
                break
            os.write(master, data)
finally:
    try:
        os.close(master)
    except OSError:
        pass

_, status = os.waitpid(pid, 0)
sys.exit(os.waitstatus_to_exitcode(status))
`;

/// Wrap a command so it runs with a controlling terminal.
///
/// A pty is not a convenience here, it is the only option. `kobe attach`
/// reads keys through crossterm's event stream, which uses stdin only when
/// `isatty(0)` and otherwise opens `/dev/tty` — so a pipe on stdin is not read
/// at all, and in CI, where there is no controlling terminal to fall back to,
/// the stream errors out. Feeding keystrokes to attach therefore REQUIRES a
/// real terminal on the other end, which is exactly why this could not be
/// tested before.
///
/// `python3 -c 'pty.spawn(...)'` rather than `script(1)`, which is the obvious
/// choice and does not work: BSD `script` calls `tcgetattr` on ITS stdin to
/// clone the terminal settings, and a harness necessarily feeds keystrokes
/// through a pipe, so it dies with `tcgetattr/ioctl: Operation not supported on
/// socket` before the command starts. util-linux's `script` tolerates it, so
/// the harness would work in CI and fail on every maintainer's laptop —
/// and it would fail by producing no output, which is indistinguishable from
/// the keystroke-delivery bug this exists to detect. `pty.spawn` handles a
/// non-tty stdin explicitly and identically on both.
///
/// Python rather than a pty binding because this repo has no JavaScript
/// dependencies at all, and adding one would put a node_modules tree in the
/// path of every e2e run.
export function ptyCommand(python: string, argv: string[]): string[] {
  return [python, "-c", PTY_SPAWN, ...argv];
}

export function resizablePtyCommand(python: string, argv: string[]): string[] {
  return [python, "-c", RESIZABLE_PTY_SPAWN, ...argv];
}

/// Locate a Python that can allocate the pty, or say so plainly.
///
/// Named explicitly rather than falling back to `script`: two allocators with
/// different behaviour would make a failure mean two different things.
async function resolvePython(): Promise<string> {
  for (const candidate of [process.env.PYTHON ?? "python3", "python"]) {
    const { exitCode } = await runCommand([candidate, "-c", "import pty"], { allowFailure: true });
    if (exitCode === 0) return candidate;
  }
  throw new Error(
    "attach-pty needs a python3 with the stdlib `pty` module to allocate a terminal; set PYTHON to one",
  );
}

async function attachPty(args: Args): Promise<void> {
  if (!args.lease) {
    throw new Error("attach-pty needs --lease <id>");
  }
  if (!args.expect && args.expectExit === undefined) {
    throw new Error("attach-pty needs --expect and/or --expect-exit: a session with no assertion proves nothing");
  }
  if ((args.resize === undefined) !== (args.resizeAfter === undefined)) {
    throw new Error("attach-pty needs --resize and --resize-after together");
  }

  const attach = [
    args.kobeBin,
    "--target",
    args.cliTarget,
    "attach",
    args.lease,
    ...(args.attachArgv.length > 0 ? ["--", ...args.attachArgv] : []),
  ];
  const python = await resolvePython();
  const cmd = args.resize ? resizablePtyCommand(python, attach) : ptyCommand(python, attach);
  step(`Attaching through a pty: ${attach.join(" ")}`);

  const proc = Bun.spawn({
    cmd,
    stdin: "pipe",
    stdout: "pipe",
    stderr: "pipe",
    cwd: process.cwd(),
    // A terminal type the remote shell can render into. Without one it falls
    // back to `dumb`, where a prompt may never be drawn — and a harness waiting
    // on output would then time out with nothing to show for it.
    env: {
      ...process.env,
      TERM: process.env.TERM ?? "xterm-256color",
      ...(args.resize
        ? {
            KOBE_E2E_PTY_INITIAL: "80x24",
            KOBE_E2E_PTY_RESIZE: `${args.resize.width}x${args.resize.height}`,
          }
        : {}),
    },
  });

  let transcript = "";
  const decoder = new TextDecoder();
  const drain = async (stream: ReadableStream<Uint8Array>): Promise<void> => {
    const reader = stream.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) return;
      transcript += decoder.decode(value, { stream: true });
    }
  };
  const pumped = Promise.all([drain(proc.stdout), drain(proc.stderr)]);

  const writer = proc.stdin;
  await Bun.sleep(args.settleMs);
  for (const payload of args.send) {
    writer.write(decodeKeystrokes(payload));
    await writer.flush();
    await Bun.sleep(args.sendDelayMs);
  }

  const assertionDeadline = Date.now() + args.timeoutSeconds * 1000;
  if (args.resizeAfter !== undefined) {
    while (Date.now() < assertionDeadline && !transcript.includes(args.resizeAfter)) {
      await Bun.sleep(100);
    }
    if (!transcript.includes(args.resizeAfter)) {
      writer.end();
      proc.kill();
      await proc.exited;
      await pumped;
      throw new Error(
        `the attached session never became resize-ready at ${JSON.stringify(args.resizeAfter)} within ${args.timeoutSeconds}s`,
      );
    }
    process.kill(proc.pid, "SIGUSR1");
  }

  let matched = args.expect === undefined;
  if (args.expect !== undefined) {
    while (Date.now() < assertionDeadline) {
      if (transcript.includes(args.expect)) {
        matched = true;
        break;
      }
      await Bun.sleep(200);
    }
  }

  if (args.expectExit === undefined) {
    // Nothing asserts how the session ends, so end it. Leaving it attached
    // would hold one of the lease's eight concurrent streams until the idle
    // timeout, and the next scenario would be refused with a 429 it never asked
    // about.
    //
    // stdin is closed first: that collapses the pty, which hangs up `kobe` the
    // way a closed terminal window would. `kill` alone reaches `script`, and a
    // `kobe` reparented away from it would keep the stream open exactly as if
    // nothing had been cleaned up.
    writer.end();
  }
  // Bounded either way. An attach that never exits would otherwise hang here
  // long past the timeout the caller asked for, and CI would kill the run with
  // no transcript at all — the one artefact that says what went wrong.
  //
  // A cleared timer rather than a bare sleep: an un-cleared one keeps the event
  // loop alive, and every successful run would then take the full timeout.
  let timer: ReturnType<typeof setTimeout> | undefined;
  const expired = new Promise<"timeout">((resolve) => {
    timer = setTimeout(() => resolve("timeout"), args.timeoutSeconds * 1000);
  });
  const outcome = await Promise.race([proc.exited, expired]);
  clearTimeout(timer);
  if (outcome === "timeout") {
    proc.kill();
  }
  const exitCode = outcome === "timeout" ? await proc.exited : outcome;
  await pumped;

  info("--- session transcript ---");
  info(transcript.trimEnd());
  info("--- end transcript ---");

  if (!matched) {
    throw new Error(`the attached session never produced ${JSON.stringify(args.expect)} within ${args.timeoutSeconds}s`);
  }
  if (args.expectExit !== undefined && exitCode !== args.expectExit) {
    throw new Error(`kobe attach exited ${exitCode}, expected ${args.expectExit}`);
  }
  step("Attached session satisfied every assertion");
}

export function forwardingAddress(
  transcript: string,
  lease: string,
  remote: string,
): string | undefined {
  const match = /^Forwarding 127\.0\.0\.1:([0-9]+) -> ([^:\s]+):([^\s]+)$/m.exec(transcript);
  if (!match || match[2] !== lease || match[3] !== remote) return undefined;
  const port = Number.parseInt(match[1], 10);
  if (port < 1 || port > 65_535) return undefined;
  return `127.0.0.1:${port}`;
}

/// Drive the CLI's loopback listener and prove bytes cross the upgraded
/// connection into the pool-declared remote port.
async function portForward(args: Args): Promise<void> {
  if (!args.lease) {
    throw new Error("port-forward needs --lease <id>");
  }
  if (args.expect === undefined && args.expectHttpStatus === undefined) {
    throw new Error("port-forward needs --expect <text> or --expect-http-status <status>");
  }

  const command = [
    args.kobeBin,
    "--target",
    args.cliTarget,
    "port-forward",
    args.lease,
    `0:${args.remotePort}`,
  ];
  step(`Forwarding a declared port: ${command.join(" ")}`);
  const proc = Bun.spawn({
    cmd: command,
    stdin: "ignore",
    stdout: "pipe",
    stderr: "pipe",
    cwd: process.cwd(),
    env: process.env,
  });

  let stdout = "";
  let stderr = "";
  let exited: number | undefined;
  void proc.exited.then((code) => {
    exited = code;
  });
  const drain = async (stream: ReadableStream<Uint8Array>, append: (text: string) => void): Promise<void> => {
    const decoder = new TextDecoder();
    const reader = stream.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) return;
      append(decoder.decode(value, { stream: true }));
    }
  };
  const pumped = Promise.all([
    drain(proc.stdout, (text) => {
      stdout += text;
    }),
    drain(proc.stderr, (text) => {
      stderr += text;
    }),
  ]);

  const deadline = Date.now() + args.timeoutSeconds * 1000;
  try {
    let address: string | undefined;
    while (Date.now() < deadline) {
      address = forwardingAddress(stdout, args.lease, args.remotePort);
      if (address) break;
      if (exited !== undefined) {
        throw new Error(`kobe port-forward exited ${exited} before listening:\n${stdout}${stderr}`);
      }
      await Bun.sleep(100);
    }
    if (!address) {
      throw new Error(`kobe port-forward did not listen within ${args.timeoutSeconds}s:\n${stdout}${stderr}`);
    }

    if (args.expectHttpStatus !== undefined) {
      try {
        await fetch(`http://${address}/`, {
          redirect: "error",
          signal: AbortSignal.timeout(Math.min(2_000, Math.max(1, deadline - Date.now()))),
        });
      } catch {
        // The local side is expected to see EOF when the upstream WebSocket
        // handshake is refused. The authoritative assertion is the exact HTTP
        // status printed by kobectl below.
      }
      const expectedStatus = new RegExp(`HTTP(?: error:)? ${args.expectHttpStatus}\\b`);
      while (Date.now() < deadline && !expectedStatus.test(stderr)) {
        await Bun.sleep(100);
      }
      if (!expectedStatus.test(stderr)) {
        throw new Error(
          `port-forward did not report upstream HTTP ${args.expectHttpStatus} within ${args.timeoutSeconds}s:\n${stdout}${stderr}`,
        );
      }
      info(stderr.trimEnd());
      step(`Upgraded port-forward was refused with HTTP ${args.expectHttpStatus}`);
      return;
    }

    const expected = new TextEncoder().encode(args.expect);
    let lastError = "the workload listener did not answer";
    while (Date.now() < deadline) {
      try {
        const response = await fetch(`http://${address}/`, {
          redirect: "error",
          signal: AbortSignal.timeout(Math.min(2_000, Math.max(1, deadline - Date.now()))),
        });
        const body = new Uint8Array(await response.arrayBuffer());
        const exact = body.length === expected.length && body.every((byte, index) => byte === expected[index]);
        if (!response.ok || !exact) {
          throw new Error(
            `forwarded request returned HTTP ${response.status} with ${body.length} bytes, expected exact ${expected.length} bytes`,
          );
        }
        info(new TextDecoder().decode(body).trimEnd());
        step("Declared port forwarded exact response bytes over loopback");
        return;
      } catch (error) {
        lastError = error instanceof Error ? error.message : String(error);
        await Bun.sleep(100);
      }
    }
    throw new Error(
      `forwarded request did not return exact bytes within ${args.timeoutSeconds}s: ${lastError}\n${stderr}`,
    );
  } finally {
    if (exited === undefined) proc.kill();
    await proc.exited;
    await pumped;
  }
}

async function main() {
  try {
    const args = parseArgs(Bun.argv.slice(2));

    switch (args.command) {
      case "up":
        await up(args);
        return;
      case "down":
        await down(args);
        return;
      case "sandbox-conformance-preflight":
        await sandboxConformancePreflight(args);
        return;
      case "restart-operator":
        await restartOperator(args);
        return;
      case "inject-failure":
        await injectFailure(args);
        return;
      case "clear-failure":
        await clearFailure(args);
        return;
      case "reap-lease":
        await reapLease(args);
        return;
      case "attach-pty":
        await attachPty(args);
        return;
      case "port-forward":
        await portForward(args);
        return;
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    fail(message);
  }
}

if (import.meta.main) {
  await main();
}
