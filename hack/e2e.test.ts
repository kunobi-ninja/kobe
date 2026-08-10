import { expect, test } from "bun:test";

import { guestImagesForBackend, parseArgs } from "./e2e";

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
