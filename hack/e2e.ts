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
const DEMO_POOL = "e2e-k0s";
const DEMO_K0S_VERSION = "v1.35.1+k0s.0";
const LOCAL_TARGET = "e2e";
const LOCAL_ENDPOINT = "http://127.0.0.1:8080";
const LOCAL_NODE_PORT = 30080;
const REQUIRED_MISE_TOOLS = ["bun", "helm", "kind"];
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

type Args = {
  command: "up" | "down";
  cluster: string;
  namespace: string;
  release: string;
  imageTag: string;
};

type E2eState = {
  cluster: string;
  namespace: string;
  release: string;
  imageTag: string;
  fingerprint: string;
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
  },
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  const stream = options?.stream ?? false;
  const proc = Bun.spawn({
    cmd,
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

async function saveState(args: Args, fingerprint: string): Promise<void> {
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
        fingerprint,
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
  const state = loadState();
  if (!state) return false;

  return (
    state.cluster === args.cluster &&
    state.namespace === args.namespace &&
    state.release === args.release &&
    state.imageTag === args.imageTag &&
    state.fingerprint === fingerprint
  );
}

function parseArgs(argv: string[]): Args {
  const args = {
    command: "up" as const,
    cluster: DEFAULT_CLUSTER,
    namespace: DEFAULT_NAMESPACE,
    release: DEFAULT_RELEASE,
    imageTag: DEFAULT_IMAGE_TAG,
  };

  const [maybeCommand, ...rest] = argv;
  const tokens = maybeCommand === "up" || maybeCommand === "down" ? rest : argv;
  if (maybeCommand === "down") {
    args.command = "down";
  }

  for (let i = 0; i < tokens.length; i += 1) {
    const token = tokens[i];
    const next = tokens[i + 1];

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
    if (token === "--help" || token === "-h") {
      printHelpAndExit();
    }
  }

  return args;
}

function printHelpAndExit(): never {
  info("Usage:");
  info("  bun run ./hack/e2e.ts up [--cluster NAME] [--namespace NS] [--release NAME] [--image-tag TAG]");
  info("  bun run ./hack/e2e.ts down [--cluster NAME]");
  process.exit(0);
}

function nativePlatform(): string {
  return process.arch === "x64" ? "linux/amd64" : "linux/arm64";
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

async function buildImages(imageTag: string): Promise<void> {
  step(`Building local images (tag=${imageTag}, platform=${nativePlatform()})`);
  await runCommand(["docker", "buildx", "bake", "-f", "docker-bake.hcl", "--load"], {
    env: {
      IMAGE_TAG: imageTag,
      PLATFORM: nativePlatform(),
    },
    step: "failed to build local images",
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

async function saveImages(imageTag: string): Promise<void> {
  await recreateTempDir();
  step(`Saving local images to ${TEMP_DIR}`);
  await runCommand(["docker", "save", `zondax/kobe-operator:${imageTag}`, "-o", `${TEMP_DIR}/kobe-operator.tar`], {
    step: "failed to save kobe-operator image archive",
  });
  await runCommand(["docker", "save", `zondax/kobe-sync:${imageTag}`, "-o", `${TEMP_DIR}/kobe-sync.tar`], {
    step: "failed to save kobe-sync image archive",
  });
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

async function loadImagesIntoKind(cluster: string, imageTag: string): Promise<void> {
  step(`Loading images into kind cluster '${cluster}'`);
  await saveImages(imageTag);

  const nodes = await kindNodes(cluster);
  info(`  - nodes: ${nodes.join(", ")}`);
  for (const node of nodes) {
    await importArchiveToNode(cluster, node, `${TEMP_DIR}/kobe-operator.tar`);
    await importArchiveToNode(cluster, node, `${TEMP_DIR}/kobe-sync.tar`);
    await verifyImageInNode(node, `zondax/kobe-operator:${imageTag}`);
    await verifyImageInNode(node, `zondax/kobe-sync:${imageTag}`);
  }
}

async function prepareHelm(): Promise<void> {
  step("Preparing Helm dependencies");
  const helm = await resolveTool("helm");
  await runCommand([helm, "repo", "add", "bitnami", "https://charts.bitnami.com/bitnami"], {
    allowFailure: true,
  });
  await runCommand([helm, "dependency", "build", "./charts/kobe"], {
    step: "failed to build Helm chart dependencies",
  });
}

async function installChart(args: Args): Promise<void> {
  step(`Installing Helm release '${args.release}' into namespace '${args.namespace}'`);
  const helm = await resolveTool("helm");
  const rolloutNonce = Date.now().toString();
  await runCommand([
    helm,
    "upgrade",
    "--install",
    args.release,
    "./charts/kobe",
    "--namespace",
    args.namespace,
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
  ], {
    step: `failed to install Helm release '${args.release}'`,
    stream: true,
  });
}

function bootstrapManifest(namespace: string): string {
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
---
apiVersion: kobe.kunobi.ninja/v1alpha1
kind: ClusterPool
metadata:
  name: ${DEMO_POOL}
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
    minReady: 1
    maxClusters: 2
    scaleUpThreshold: 0
    scaleDownAfter: "30m"
    queueTimeout: "5m"
  resources:
    limits:
      cpu: "1"
      memory: "1Gi"
`;
}

async function bootstrapLocalResources(namespace: string): Promise<void> {
  step("Bootstrapping local demo token and pool");
  await runCommand(
    [
      "/bin/sh",
      "-lc",
      `for name in $(kubectl get clusterinstances.kobe.kunobi.ninja -n ${namespace} -l kobe.kunobi.ninja/pool=${DEMO_POOL} -o jsonpath='{range .items[*]}{.metadata.name}{"\\n"}{end}' 2>/dev/null); do
  kubectl delete statefulset -n ${namespace} "\${name}-server" --ignore-not-found >/dev/null 2>&1 || true
  kubectl delete deployment -n ${namespace} "\${name}-agent" --ignore-not-found >/dev/null 2>&1 || true
  kubectl delete service -n ${namespace} "\${name}-server" --ignore-not-found >/dev/null 2>&1 || true
  kubectl delete configmap -n ${namespace} "\${name}-k0s-config" "\${name}-kubeconfig-publisher" --ignore-not-found >/dev/null 2>&1 || true
  kubectl delete secret -n ${namespace} "\${name}-token" "\${name}-kubeconfig" --ignore-not-found >/dev/null 2>&1 || true
done
kubectl delete clusterinstances.kobe.kunobi.ninja -n ${namespace} -l kobe.kunobi.ninja/pool=${DEMO_POOL} --ignore-not-found >/dev/null 2>&1 || true
kubectl delete clusterpool.kobe.kunobi.ninja -n ${namespace} ${DEMO_POOL} --ignore-not-found >/dev/null 2>&1 || true`,
    ],
    {
      step: "failed to clean up existing local demo pool resources",
    },
  );
  await runCommand(
    ["/bin/sh", "-lc", `cat <<'EOF' | kubectl apply -f -
${bootstrapManifest(namespace)}EOF`],
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
  info(`Demo pool: ${DEMO_POOL}`);
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
  await buildImages(args.imageTag);
  await loadImagesIntoKind(args.cluster, args.imageTag);
  await prepareHelm();
  await runCommand(["/bin/sh", "-lc", `kubectl create namespace ${args.namespace} --dry-run=client -o yaml | kubectl apply -f -`], {
    step: `failed to ensure namespace '${args.namespace}'`,
  });
  await installChart(args);
  await bootstrapLocalResources(args.namespace);
  await writeLocalCliConfig();
  await saveState(args, fingerprint);
  await printContext(args.cluster, args.namespace);
}

async function down(args: Args): Promise<void> {
  await ensureMiseTools();
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

async function main() {
  try {
    const args = parseArgs(Bun.argv.slice(2));

    if (args.command === "up") {
      await up(args);
      return;
    }

    await down(args);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    fail(message);
  }
}

await main();
