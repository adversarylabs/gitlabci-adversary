import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { parseAdversaryManifest } from "@adversarylabs/sdk";

test("declares deterministic automatic detection", async () => {
  const source = await readFile(new URL("../adversary.yaml", import.meta.url), "utf8");
  const manifest = parseAdversaryManifest(source);
  assert.ok(manifest.detection?.files?.some((f) => f.includes("gitlab-ci")));
  assert.match(source, /"\.gitlab\/ci\/\*\*\/\*\.yml"/);
  assert.match(source, /"\.gitlab\/ci\/\*\*\/\*\.yaml"/);
  assert.equal(manifest.detection?.entrypoint, undefined);
});
