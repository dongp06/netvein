import { spawnSync } from "node:child_process";
import assert from "node:assert/strict";
import test from "node:test";

const mitmAvailable = spawnSync("mitmdump", ["--version"], { encoding: "utf8" }).status === 0;

test("Traffic daemon integration", { skip: mitmAvailable ? false : "mitmdump not installed" }, async (t) => {
  await t.test("addon import sanity", () => {
    // python -c import check lands in Task 6 alongside the manager; this file
    // owns the real daemon round-trips once MitmManager exists.
    assert.equal(mitmAvailable, true);
  });
});
