import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import { createAdversaryRunEnvelope } from "@adversarylabs/sdk";
import { createApp } from "../src/index.ts";

const execute = promisify(execFile);

const fixture = (name: string) => new URL(`../fixtures/${name}`, import.meta.url).pathname;
const review = (name: string, raw = false) => createApp().run({ input: { source: { path: fixture(name) } }, includeRawObservations: raw });
const ruleCases = [{"key": "privileged", "id": "gitlab-ci.privileged"}, {"key": "secret-in-script-echo", "id": "gitlab-ci.secret-in-script-echo"}, {"key": "mutable-image", "id": "gitlab-ci.mutable-image"}, {"key": "dind-socket-mount", "id": "gitlab-ci.dind-socket-mount"}, {"key": "curl-pipe-bash", "id": "gitlab-ci.curl-pipe-bash"}, {"key": "include-remote-unpinned", "id": "gitlab-ci.include-remote-unpinned"}, {"key": "allow-failure", "id": "gitlab-ci.allow-failure"}, {"key": "script-yaml-injection-ci-commit", "id": "gitlab-ci.script-yaml-injection-ci-commit"}, {"key": "interruptible-release", "id": "gitlab-ci.interruptible-release"}];

test("reports the release job and inherited interruptible default", async () => {
  const output = await review("rules/interruptible-release/vulnerable", true);
  const observation = output.rawObservations?.find((item) => item.ruleId === "gitlab-ci.interruptible-release");
  assert.equal(observation?.location?.file, ".gitlab-ci.yml");
  assert.equal(observation?.evidence?.job, "publish-packages");
  assert.equal(observation?.evidence?.interruptibleSource, "default");
});

test("applies the root default to a locally included release job", async () => {
  const output = await review("rules/interruptible-release/vulnerable-included", true);
  const observation = output.rawObservations?.find((item) => item.ruleId === "gitlab-ci.interruptible-release");
  assert.equal(observation?.location?.file, "scripts/ci/gitlab/pipeline/publish.yml");
  assert.equal(observation?.evidence?.job, "publish-crates");
  assert.equal(observation?.evidence?.interruptibleSource, "default");
  assert.equal(observation?.evidence?.defaultFile, ".gitlab-ci.yml");
  assert.equal(observation?.evidence?.configurationRoot, ".gitlab-ci.yml");
});

test("handles explicit job-level interruptibility", async () => {
  const explicit = await review("rules/interruptible-release/vulnerable-job", true);
  const observation = explicit.rawObservations?.find((item) => item.ruleId === "gitlab-ci.interruptible-release");
  assert.equal(observation?.evidence?.job, "deploy-production");
  assert.equal(observation?.evidence?.interruptibleSource, "job");
});

test("applies the root auto-cancel opt-out to locally included jobs", async () => {
  const disabled = await review("rules/interruptible-release/clean-auto-cancel");
  assert.equal(disabled.findings.some((finding) => finding.ruleId === "gitlab-ci.interruptible-release"), false);
});

test("does not infer external include content", async () => {
  const external = await review("rules/interruptible-release/clean-external");
  assert.equal(external.findings.some((finding) => finding.ruleId === "gitlab-ci.interruptible-release"), false);
});

test("every shipped rule has focused vulnerable and clean coverage", async () => {
  for (const rule of ruleCases) {
    const vulnerable = await review(`rules/${rule.key}/vulnerable`, true);
    assert.equal(vulnerable.findings.some((finding) => finding.ruleId === rule.id), true, `${rule.id} did not detect its vulnerable fixture`);
    assert.equal(vulnerable.rawObservations?.every((item) => item.location?.file !== undefined), true);
    const clean = await review(`rules/${rule.key}/clean`);
    assert.equal(clean.findings.some((finding) => finding.ruleId === rule.id), false, `${rule.id} flagged its clean fixture`);
  }
});

test("accepts a repository without applicable configuration", async () => {
  const output = await review("clean");
  assert.deepEqual(output.findings, []);
  assert.equal(output.assessment?.risk, "none");
  assert.equal(output.opinion?.ship, true);
});

test("an unrelated edit does not surface a legacy local finding", async () => {
  const legacy = "build:\n  privileged: true\n  script: echo build\n";
  const root = await gitRepository({ ".gitlab-ci.yml": legacy });
  try {
    await writeFile(join(root, ".gitlab-ci.yml"), `${legacy}\n# unrelated documentation update\n`);
    const output = await changedReview(root, [".gitlab-ci.yml"]);
    assert.equal(output.findings.some((finding) => finding.ruleId === "gitlab-ci.privileged"), false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a direct finding on a changed line remains eligible", async () => {
  const root = await gitRepository({
    ".gitlab-ci.yml": "build:\n  privileged: false\n  script: echo build\n",
  });
  try {
    await writeFile(
      join(root, ".gitlab-ci.yml"),
      "build:\n  privileged: true\n  script: echo build\n",
    );
    const output = await changedReview(root, [".gitlab-ci.yml"]);
    assert.equal(output.findings.some((finding) => finding.ruleId === "gitlab-ci.privileged"), true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("an unchanged first match does not hide a later changed match", async () => {
  const root = await gitRepository({
    ".gitlab-ci.yml": [
      "legacy:",
      "  privileged: true",
      "  script: echo legacy",
      "",
      "changed:",
      "  privileged: false",
      "  script: echo changed",
      "",
    ].join("\n"),
  });
  try {
    await writeFile(
      join(root, ".gitlab-ci.yml"),
      [
        "legacy:",
        "  privileged: true",
        "  script: echo legacy",
        "",
        "changed:",
        "  privileged: true",
        "  script: echo changed",
        "",
      ].join("\n"),
    );
    const output = await changedReview(root, [".gitlab-ci.yml"]);
    const observation = output.rawObservations?.find(
      (item) => item.ruleId === "gitlab-ci.privileged",
    );
    assert.equal(observation?.location?.line, 6);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a newly added configuration remains fully eligible", async () => {
  const root = await gitRepository({ "README.md": "# service\n" });
  try {
    await writeFile(
      join(root, ".gitlab-ci.yml"),
      "build:\n  privileged: true\n  script: echo build\n",
    );
    const output = await changedReview(root, [".gitlab-ci.yml"]);
    assert.equal(output.findings.some((finding) => finding.ruleId === "gitlab-ci.privileged"), true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("changed root defaults retain locally included jobs as configuration context", async () => {
  const root = await gitRepository({
    ".gitlab-ci.yml": [
      "include:",
      "  - local: ci/publish.yml",
      "",
      "default:",
      "  interruptible: false",
      "",
    ].join("\n"),
    "ci/publish.yml": [
      "publish-packages:",
      "  stage: publish",
      "  script: npm publish",
      "",
    ].join("\n"),
  });
  try {
    await writeFile(
      join(root, ".gitlab-ci.yml"),
      [
        "include:",
        "  - local: ci/publish.yml",
        "",
        "default:",
        "  interruptible: true",
        "",
      ].join("\n"),
    );
    const output = await changedReview(root, [".gitlab-ci.yml"]);
    const observation = output.rawObservations?.find(
      (item) => item.ruleId === "gitlab-ci.interruptible-release",
    );
    assert.equal(observation?.location?.file, "ci/publish.yml");
    assert.equal(observation?.evidence?.interruptibleSource, "default");
    assert.equal(observation?.evidence?.defaultFile, ".gitlab-ci.yml");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("output ordering and protocol envelope are deterministic", async () => {
  const first = await review(`rules/${ruleCases[0]?.key}/vulnerable`, true);
  const second = await review(`rules/${ruleCases[0]?.key}/vulnerable`, true);
  assert.deepEqual(second, first);
  const envelope = JSON.parse(JSON.stringify(createAdversaryRunEnvelope(first)));
  assert.equal(envelope.protocolVersion, 1);
  assert.equal(envelope.result.adversary.name, "gitlab-ci");
});

async function changedReview(root: string, changedFiles: string[]) {
  return createApp().run({
    input: {
      source: { path: root },
      change: {
        type: "diff",
        base_ref: "HEAD",
        head_ref: "WORKTREE",
        scan_mode: "changed",
        changed_files: changedFiles,
      },
    },
    includeRawObservations: true,
  });
}

async function gitRepository(files: Record<string, string>): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "gitlab-ci-git-"));
  await execute("git", ["init", "--quiet", root]);
  await execute("git", ["-C", root, "config", "user.email", "tests@example.com"]);
  await execute("git", ["-C", root, "config", "user.name", "Tests"]);
  for (const [path, content] of Object.entries(files)) {
    await mkdir(dirname(join(root, path)), { recursive: true });
    await writeFile(join(root, path), content);
  }
  await execute("git", ["-C", root, "add", "."]);
  await execute("git", ["-C", root, "commit", "--quiet", "-m", "baseline"]);
  return root;
}
