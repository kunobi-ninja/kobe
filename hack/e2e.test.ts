import { expect, test } from "bun:test";

import {
  decodeKeystrokes,
  guestImagesForBackend,
  LEASE_STAGES,
  leaseStageReached,
  parseArgs,
  ptyCommand,
  revokeVerb,
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

test("every stage is backed by a signal the operator actually writes", () => {
  // Guards the mistake the stage list exists to avoid: a stage nobody reaches
  // reads as covered while the restart it names never happens. `provisioning`
  // is the concrete case — no production path writes that phase.
  expect(Object.keys(LEASE_STAGES)).not.toContain("provisioning");
  expect(Object.keys(LEASE_STAGES)).not.toContain("bootstrap");
});

test("a stage is reached by its own marker and by nothing else", () => {
  const bound = { status: { target: { namespace: "kobe-system", childClusterLease: { uid: "u" } } } };

  expect(leaseStageReached("provenance", bound)).toBe(true);
  expect(leaseStageReached("bind", bound)).toBe(true);
  expect(leaseStageReached("claim", bound)).toBe(false);
  expect(leaseStageReached("ready", bound)).toBe(false);
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
  const cmd = ptyCommand("python3", ["kobe", "sandbox", "attach", "it's mine"]);

  expect(cmd.slice(0, 2)).toEqual(["python3", "-c"]);
  expect(cmd.slice(3)).toEqual(["kobe", "sandbox", "attach", "it's mine"]);
});

test("the pty wrapper exits with the attached command's own status", () => {
  // --expect-exit asserts kobe's 125-on-abnormal-end contract. A wrapper that
  // reported its own success would make that assertion meaningless.
  expect(ptyCommand("python3", ["kobe"])[2]).toContain("waitstatus_to_exitcode");
});
