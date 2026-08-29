import { expect, test } from "bun:test";

import {
  bootstrapManifest,
  decodeKeystrokes,
  forwardingAddress,
  guestImagesForBackend,
  LEASE_STAGES,
  leaseStageReached,
  parseArgs,
  parseTerminalSize,
  ptyCommand,
  resizablePtyCommand,
  revokeVerb,
  sandboxConformanceManifest,
  sandboxPoolCertificationBlocker,
} from "./e2e";

test("k3s only preloads the always-warm k3s guest image", () => {
  const args = parseArgs(["up", "--backend", "k3s"]);

  expect(guestImagesForBackend(args.backend)).toEqual(["rancher/k3s:v1.31.3-k3s1"]);
});

test("k0s also preloads its on-demand guest image", () => {
  const args = parseArgs(["up", "--backend", "k0s"]);

  expect(guestImagesForBackend(args.backend)).toEqual([
    "rancher/k3s:v1.31.3-k3s1",
    "k0sproject/k0s:v1.35.1-k0s.0",
  ]);
});

test("Sandbox conformance mode is explicit and the CI cluster is inherited by every harness command", () => {
  const previous = process.env.E2E_CLUSTER;
  process.env.E2E_CLUSTER = "ci-owned-kind";
  try {
    const up = parseArgs(["up", "--backend", "k3s", "--sandbox-conformance"]);
    const preflight = parseArgs(["sandbox-conformance-preflight"]);

    expect(up.cluster).toBe("ci-owned-kind");
    expect(up.sandboxConformance).toBe(true);
    expect(preflight.cluster).toBe("ci-owned-kind");
  } finally {
    if (previous === undefined) delete process.env.E2E_CLUSTER;
    else process.env.E2E_CLUSTER = previous;
  }
});

test("the ordinary e2e manifest does not silently enable Sandbox fixtures", () => {
  const manifest = bootstrapManifest("kobe-system");

  expect(manifest).not.toContain("kind: SandboxPool");
  expect(manifest).not.toContain("agent-sandbox-v1-0-0");
  expect(manifest).not.toContain("e2e-other-token");
});

test("the conformance manifest contains two exact placements and a pullable runner fixture", () => {
  const fixture = {
    imageRef: "127.0.0.1:32001/kobe-sandbox-e2e:test",
    registrySource: "127.0.0.1:32001",
    mirrorEndpoint: "http://172.19.0.9:5000",
  };
  const manifest = bootstrapManifest("kobe-system", fixture);
  const pools = sandboxConformanceManifest("kobe-system", fixture);

  expect(manifest.match(/^kind: SandboxPool$/gm)).toHaveLength(2);
  expect(manifest).toContain("name: agent-sandbox-v1-0-0");
  expect(manifest).toContain('"127.0.0.1:32001":');
  expect(manifest).toContain('"http://172.19.0.9:5000"');
  expect(pools).toContain("type: management");
  expect(pools).toContain("type: childCluster");
  expect(pools).toContain("clusterPoolRef: e2e-k3s");
  expect(pools).toContain("runnerPath: /kobe-runner");
  expect(pools).toContain("image: 127.0.0.1:32001/kobe-sandbox-e2e:test");
  expect(pools).toContain('verbs: ["lease", "exec", "logs", "port-forward", "release"]');
  expect(pools).toContain("name: e2e-other-token");
});

test("the published runner artifact proves the default spool under its restricted identity", async () => {
  const dockerfile = await Bun.file("docker/runner.Dockerfile").text();
  expect(dockerfile).toContain("install -d -o 65532 -g 65532 -m 0700 /var/run/kobe/executions");
  expect(dockerfile).toContain("USER 65532:65532");
  expect(dockerfile).toContain("/kobe-runner start");
  expect(dockerfile).not.toContain("/kobe-runner --state-dir");
  expect(dockerfile).toContain("COPY --from=smoke /kobe-runner /kobe-runner");
});

test("the conformance preflight reports durable pool blockers without waiting for timeout", () => {
  const pool = (reason: string, message: string, observedGeneration = 7) => ({
    metadata: { generation: 7 },
    status: {
      observedGeneration,
      conditions: [{ type: "Ready", status: "False", observedGeneration, reason, message }],
    },
  });

  expect(sandboxPoolCertificationBlocker(pool("CleanupBlocked", "approval required"), "management"))
    .toBe("SandboxPool/management is fail-closed at CleanupBlocked: approval required");
  expect(sandboxPoolCertificationBlocker(pool("CompositionEligible", "child receipt missing"), "child"))
    .toBe("SandboxPool/child is fail-closed at CompositionEligible: child receipt missing");
  expect(sandboxPoolCertificationBlocker(pool("CanaryRunning", "still reconciling"), "management"))
    .toBeUndefined();
  expect(sandboxPoolCertificationBlocker(pool("CleanupBlocked", "stale", 6), "management"))
    .toBeUndefined();
});

// ---------------------------------------------------------------------------
// Conformance harness (#138)
// ---------------------------------------------------------------------------

test("a bare `--` hands the rest to the attached session, not to the harness", () => {
  // Without this the workload's own flags are parsed as the harness's, and
  // `attach -- sh --norc` would silently become a harness it does not have.
  const args = parseArgs(["attach-pty", "--lease", "abc", "--expect", "hi", "--", "/bin/sh", "--norc"]);

  expect(args.lease).toBe("abc");
  expect(args.attachArgv).toEqual(["/bin/sh", "--norc"]);
});

test("the transport harness parses a bounded resize and a named declared port", () => {
  const resize = parseArgs([
    "attach-pty",
    "--lease",
    "abc",
    "--resize",
    "120x40",
    "--resize-after",
    "ready",
    "--expect",
    "40 120",
  ]);
  const forward = parseArgs(["port-forward", "--lease", "abc", "--port", "http", "--expect", "exact-body"]);
  const refused = parseArgs([
    "port-forward",
    "--target",
    "e2e-other",
    "--lease",
    "abc",
    "--port",
    "ssh",
    "--expect-http-status",
    "404",
  ]);

  expect(resize.resize).toEqual({ width: 120, height: 40 });
  expect(resize.resizeAfter).toBe("ready");
  expect(forward.remotePort).toBe("http");
  expect(forward.expect).toBe("exact-body");
  expect(refused.cliTarget).toBe("e2e-other");
  expect(refused.expectHttpStatus).toBe(404);
  expect(() => parseTerminalSize("0x40")).toThrow(/integer >= 1/);
  expect(() => parseTerminalSize("5000x40")).toThrow(/<= 4096/);
});

test("the port-forward harness accepts only the CLI's exact listening line", () => {
  expect(forwardingAddress("Forwarding 127.0.0.1:45123 -> lease:http\n", "lease", "http")).toBe(
    "127.0.0.1:45123",
  );
  expect(forwardingAddress("Forwarding 0.0.0.0:45123 -> lease:http\n", "lease", "http")).toBeUndefined();
  expect(forwardingAddress("Forwarding 127.0.0.1:45123 -> other:http\n", "lease", "http")).toBeUndefined();
  expect(forwardingAddress("Forwarding 127.0.0.1:45123 -> lease:9999\n", "lease", "http")).toBeUndefined();
  expect(forwardingAddress("kobe: 127.0.0.1:45123 failed\n", "lease", "http")).toBeUndefined();
});

test("#138's --after-phase and the clearer --wait-for-phase name the same stage", () => {
  // A recipe copied verbatim out of the issue has to run.
  expect(parseArgs(["restart-operator", "--after-phase", "claim"]).waitForStage).toBe("claim");
  expect(parseArgs(["restart-operator", "--wait-for-phase", "claim"]).waitForStage).toBe("claim");
});

test("the core API group survives argument parsing", () => {
  // The core group IS the empty string. A parser that treated it as a missing
  // value would make every core-resource revocation impossible to ask for.
  const args = parseArgs(["inject-failure", "--kind", "rbac-revoke", "--api-group", "", "--resource", "pods", "--verb", "get"]);

  expect(args.revocation).toEqual({ apiGroup: "", resource: "pods", verb: "get" });
});

test("an unknown failure kind is refused rather than defaulted", () => {
  // Silently falling back to the default would break the target in a way the
  // caller did not ask for, and the scenario would assert against it.
  expect(() => parseArgs(["inject-failure", "--kind", "chaos"])).toThrow(/unknown failure kind/);
});

test("#82 crash windows carry the exact idempotency key into the harness", () => {
  for (const kind of [
    "execution-after-running-before-target-reservation",
    "execution-before-spawn",
    "execution-after-spawn-before-ack",
    "execution-after-ack-before-status",
  ]) {
    const args = parseArgs([
      "inject-failure",
      "--kind",
      kind,
      "--lease",
      "sandbox-a",
      "--idempotency-key",
      "conformance-crash-key",
    ]);

    expect(args.failure).toBe(kind);
    expect(args.lease).toBe("sandbox-a");
    expect(args.idempotencyKey).toBe("conformance-crash-key");
  }
});

test("every stage is backed by a signal the operator actually writes", () => {
  // Guards the mistake the stage list exists to avoid: a stage nobody reaches
  // reads as covered while the restart it names never happens. Management
  // placement records bootstrap provenance; child placement has no equivalent
  // outer-lease marker, so the shared stage registry cannot expose bootstrap.
  expect(Object.keys(LEASE_STAGES)).toContain("provisioning");
  expect(Object.keys(LEASE_STAGES)).not.toContain("bootstrap");
});

test("a stage is reached by its own marker and by nothing else", () => {
  const bound = { status: { target: { namespace: "kobe-system", childClusterLease: { uid: "u" } } } };
  const deadline = "2026-08-20T12:00:00Z";

  expect(leaseStageReached("provenance", bound)).toBe(true);
  expect(leaseStageReached("bind", bound)).toBe(true);
  expect(leaseStageReached("claim", bound)).toBe(false);
  expect(leaseStageReached("ready", bound)).toBe(false);
  expect(leaseStageReached("provisioning", { status: { phase: "Provisioning" } })).toBe(false);
  expect(leaseStageReached("provisioning", { status: { provisioningDeadline: deadline } })).toBe(false);
  expect(
    leaseStageReached("provisioning", {
      status: { phase: "Provisioning", provisioningDeadline: deadline },
    }),
  ).toBe(true);
  expect(leaseStageReached("teardown", { status: { phase: "Releasing" } })).toBe(false);
  expect(leaseStageReached("teardown", { status: { releaseCause: "Requested" } })).toBe(false);
  expect(
    leaseStageReached("teardown", {
      status: { phase: "Releasing", releaseCause: "Requested" },
    }),
  ).toBe(true);
});

test("an unknown stage fails loudly instead of never matching", () => {
  // The alternative is a wait that runs to its timeout and reports the target
  // as slow, when the harness was asked for something that does not exist.
  expect(() => leaseStageReached("halfway", {})).toThrow(/unknown stage/);
});

test("revoking a verb leaves the resources sharing its rule untouched", () => {
  // The rule kobe actually ships: three upstream resources, seven verbs. If
  // the whole rule were narrowed, the scenario would be testing a far larger
  // breakage than the one it names.
  const { rules, revoked } = revokeVerb(
    [
      {
        apiGroups: ["extensions.agents.x-k8s.io"],
        resources: ["sandboxtemplates", "sandboxwarmpools", "sandboxclaims"],
        verbs: ["get", "list", "watch", "create", "update", "patch", "delete"],
      },
    ],
    { apiGroup: "extensions.agents.x-k8s.io", resource: "sandboxclaims", verb: "get" },
  );

  expect(revoked).toBe(1);
  expect(rules).toEqual([
    {
      apiGroups: ["extensions.agents.x-k8s.io"],
      resources: ["sandboxtemplates", "sandboxwarmpools"],
      verbs: ["get", "list", "watch", "create", "update", "patch", "delete"],
    },
    {
      apiGroups: ["extensions.agents.x-k8s.io"],
      resources: ["sandboxclaims"],
      verbs: ["list", "watch", "create", "update", "patch", "delete"],
    },
  ]);
});

test("a rule granting nothing relevant is passed through byte-for-byte", () => {
  const untouched = [{ apiGroups: [""], resources: ["pods"], verbs: ["get"] }];

  const { rules, revoked } = revokeVerb(untouched, { apiGroup: "policy", resource: "poddisruptionbudgets", verb: "delete" });

  expect(revoked).toBe(0);
  expect(rules).toEqual(untouched);
});

test("a wildcard grant is refused, not silently left in place", () => {
  // Subtraction cannot narrow `*`. Editing around it would produce a role that
  // still grants the verb, and the injection would prove nothing while
  // reporting success.
  expect(() =>
    revokeVerb([{ apiGroups: ["*"], resources: ["*"], verbs: ["*"] }], {
      apiGroup: "kobe.kunobi.ninja",
      resource: "clusterleases",
      verb: "get",
    }),
  ).toThrow(/wildcard/);
});

test("a verb held by several rules is revoked from all of them", () => {
  // One rule left granting it means the operator never gets a 403, and the
  // scenario waits for a quarantine that will not come.
  const { revoked } = revokeVerb(
    [
      { apiGroups: ["kobe.kunobi.ninja"], resources: ["clusterleases"], verbs: ["get", "list"] },
      { apiGroups: ["kobe.kunobi.ninja"], resources: ["clusterleases", "clusterpools"], verbs: ["get"] },
    ],
    { apiGroup: "kobe.kunobi.ninja", resource: "clusterleases", verb: "get" },
  );

  expect(revoked).toBe(2);
});

test("the control characters that cannot be typed into an argument decode", () => {
  // \r ends the line and \x03 is the Ctrl-C whose arrival at the workload is
  // the property under test. Neither can appear literally on a command line.
  expect(Array.from(decodeKeystrokes("a\\r"))).toEqual([0x61, 0x0d]);
  expect(Array.from(decodeKeystrokes("\\x03"))).toEqual([0x03]);
  expect(Array.from(decodeKeystrokes("\\e[A"))).toEqual([0x1b, 0x5b, 0x41]);
  expect(Array.from(decodeKeystrokes("back\\\\slash"))).toEqual(Array.from(new TextEncoder().encode("back\\slash")));
});

test("a malformed escape is refused rather than sent as literal text", () => {
  // Sending `\q` verbatim would put two stray characters into the workload's
  // stdin, and the resulting mismatch would be blamed on the transport.
  expect(() => decodeKeystrokes("\\q")).toThrow(/unknown escape/);
  expect(() => decodeKeystrokes("\\xZZ")).toThrow(/two hex digits/);
});

test("the pty wrapper passes argv through without a shell in between", () => {
  // Every argument stays its own argv element. Building one shell string
  // instead would make a lease alias containing a quote executable, and the
  // aliases are caller-supplied.
  const cmd = ptyCommand("python3", ["kobe", "attach", "it's mine"]);

  expect(cmd.slice(0, 2)).toEqual(["python3", "-c"]);
  expect(cmd.slice(3)).toEqual(["kobe", "attach", "it's mine"]);
});

test("the pty wrapper exits with the attached command's own status", () => {
  // --expect-exit asserts kobe's 125-on-abnormal-end contract. A wrapper that
  // reported its own success would make that assertion meaningless.
  expect(ptyCommand("python3", ["kobe"])[2]).toContain("waitstatus_to_exitcode");
});

test("the resizable pty uses a terminal ioctl rather than stdin bytes", () => {
  const source = resizablePtyCommand("python3", ["kobe"])[2];

  expect(source).toContain("TIOCSWINSZ");
  expect(source).toContain("SIGUSR1");
  expect(source).not.toContain("os.system");
});
