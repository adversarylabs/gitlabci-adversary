import { readFile, readdir } from "node:fs/promises";
import { join, sep } from "node:path";
import { type RuleContext } from "@adversarylabs/sdk";
import { observationFor } from "./rules.js";
import { spec, type MatchExpression, type RuleSpec } from "./spec.js";

const SKIPPED = new Set([".adversary", ".git", ".hg", ".next", ".svn", "coverage", "dist", "node_modules", "target", "vendor"]);
const MAX_FILES = 5000;

interface SourceFile { path: string; source: string }
interface Detection { rule: RuleSpec; file: string; line: number; snippet: string; label: string; data: Record<string, unknown> }
interface YamlBlock { key: string; line: number; lines: string[] }

const RESERVED_TOP_LEVEL_KEYS = new Set([
  "after_script", "before_script", "cache", "default", "image", "include", "pages", "services", "stages", "variables", "workflow",
]);
const RELEASE_JOB = /(?:^|[-_.])(deploy(?:ment)?|publish(?:ing)?|release)(?:$|[-_.])/i;

export async function analyzeRepository(ctx: RuleContext): Promise<void> {
  // Full tree for existence/context checks; content uses CLI/SDK review scope.
  const allPaths = await walk(ctx.repoPath);
  const scoped = await ctx.loadInScopeSources({
    include: (path) =>
      !path.split("/").some((segment) => SKIPPED.has(segment)) &&
      spec.files.some((glob) => matchesGlob(path, glob)),
    limit: MAX_FILES,
  });
  const sources: SourceFile[] = scoped.map((file) => ({ path: file.path, source: file.content }));
  ctx.summary.files_scanned = sources.length;

  const detections = spec.rules.flatMap((rule) => evaluate(rule, sources, allPaths));
  detections.sort((a, b) => a.rule.id.localeCompare(b.rule.id) || a.file.localeCompare(b.file) || a.line - b.line || a.label.localeCompare(b.label));
  for (const detection of detections) ctx.observe(observationFor(detection));

  if (sources.length > 0 && detections.length === 0) {
    ctx.review.positive({
      key: `${spec.id}.reviewed`,
      summary: `Reviewed ${sources.length} ${spec.displayName} configuration file${sources.length === 1 ? "" : "s"} without finding a material issue.`,
      evidence: sources.slice(0, 5).map((file) => ({ file: file.path, line: 1 })),
    });
  }
}

function evaluate(rule: RuleSpec, sources: SourceFile[], allPaths: string[]): Detection[] {
  const match = rule.match;
  if (match.kind === "missing-file") {
    const triggers = allPaths.filter((path) => match.triggerFiles.some((glob) => matchesGlob(path, glob))).sort();
    const required = allPaths.some((path) => match.requiredFiles.some((glob) => matchesGlob(path, glob)));
    if (triggers.length === 0 || required) return [];
    return [{ rule, file: triggers[0] ?? ".", line: 1, snippet: triggers[0] ?? "", label: rule.title, data: { triggerFiles: triggers.slice(0, 10), requiredFiles: match.requiredFiles } }];
  }

  if (match.kind === "release-interruptible") {
    return sources
      .filter((file) => match.files.some((glob) => matchesGlob(file.path, glob)))
      .flatMap((file) => detectInterruptibleRelease(rule, file));
  }

  const matchingSources = sources.filter((file) => match.files.some((glob) => matchesGlob(file.path, glob)));
  if (match.kind === "missing-content") {
    return matchingSources.flatMap((file) => {
      if (!test(file.source, match.trigger) || test(file.source, match.required)) return [];
      const location = locate(file.source, match.trigger);
      if (location === undefined) return [];
      return [{ rule, file: file.path, ...location, label: rule.title, data: { requiredPattern: match.required.pattern } }];
    });
  }

  return matchingSources.flatMap((file) => {
    if (!match.requires.every((pattern) => test(file.source, pattern))) return [];
    const location = locate(file.source, match.pattern);
    if (location === undefined) return [];
    return [{ rule, file: file.path, ...location, label: rule.title, data: { matchedPattern: match.pattern.pattern } }];
  });
}

function detectInterruptibleRelease(rule: RuleSpec, file: SourceFile): Detection[] {
  const blocks = topLevelBlocks(file.source);
  if (hasAutoCancelDisabled(blocks)) return [];
  const defaultBlock = blocks.find((block) => block.key === "default");
  const defaultInterruptible = defaultBlock === undefined ? undefined : booleanProperty(defaultBlock, "interruptible");

  return blocks.flatMap((block) => {
    if (RESERVED_TOP_LEVEL_KEYS.has(block.key) || block.key.startsWith(".")) return [];
    const stage = scalarProperty(block, "stage");
    if (!RELEASE_JOB.test(block.key) && (stage === undefined || !RELEASE_JOB.test(stage))) return [];
    if (isTagOnly(block)) return [];

    const jobInterruptible = booleanProperty(block, "interruptible");
    if (jobInterruptible === false) return [];
    const inherited = jobInterruptible === undefined && defaultInterruptible === true;
    if (jobInterruptible !== true && !inherited) return [];

    return [{
      rule,
      file: file.path,
      line: block.line,
      snippet: block.lines[0]?.trim().slice(0, 240) ?? `${block.key}:`,
      label: rule.title,
      data: {
        job: block.key,
        stage,
        interruptibleSource: inherited ? "default" : "job",
        defaultLine: inherited ? defaultBlock?.line : undefined,
      },
    }];
  });
}

function hasAutoCancelDisabled(blocks: YamlBlock[]): boolean {
  const workflow = blocks.find((block) => block.key === "workflow");
  if (workflow === undefined) return false;
  const autoCancel = nestedPropertyLines(workflow, "auto_cancel");
  if (autoCancel === undefined) return false;
  const indentation = directChildIndentation({ ...workflow, lines: autoCancel });
  if (indentation === undefined) return false;
  return autoCancel.slice(1).some((line) => new RegExp(`^\\s{${indentation}}on_new_commit:\\s*["']?none["']?\\s*(?:#.*)?$`, "i").test(line));
}

function topLevelBlocks(source: string): YamlBlock[] {
  const lines = source.split(/\r?\n/);
  const starts: Array<{ key: string; index: number }> = [];
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? "";
    const match = /^([^\s#][^:]*):(?:\s*(?:&\S+)?\s*(?:#.*)?)$/.exec(line);
    if (match?.[1] === undefined) continue;
    starts.push({ key: stripQuotes(match[1].trim()), index });
  }
  return starts.map((start, index) => {
    const end = starts[index + 1]?.index ?? lines.length;
    return { key: start.key, line: start.index + 1, lines: lines.slice(start.index, end) };
  });
}

function stripQuotes(value: string): string {
  if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) return value.slice(1, -1);
  return value;
}

function booleanProperty(block: YamlBlock, property: string): boolean | undefined {
  const indentation = directChildIndentation(block);
  if (indentation === undefined) return undefined;
  const pattern = new RegExp(`^\\s{${indentation}}${property}:\\s*(true|false)\\s*(?:#.*)?$`, "i");
  for (const line of block.lines.slice(1)) {
    const value = pattern.exec(line)?.[1]?.toLowerCase();
    if (value === "true") return true;
    if (value === "false") return false;
  }
  return undefined;
}

function scalarProperty(block: YamlBlock, property: string): string | undefined {
  const indentation = directChildIndentation(block);
  if (indentation === undefined) return undefined;
  const pattern = new RegExp(`^\\s{${indentation}}${property}:\\s*["']?([^"'#\\s]+)["']?\\s*(?:#.*)?$`, "i");
  for (const line of block.lines.slice(1)) {
    const value = pattern.exec(line)?.[1];
    if (value !== undefined) return value;
  }
  return undefined;
}

function isTagOnly(block: YamlBlock): boolean {
  const only = nestedPropertyLines(block, "only");
  if (only !== undefined) {
    const inline = only[0]?.replace(/^\s*only:\s*/, "").trim() ?? "";
    if (/^(?:tags|\[\s*tags\s*\])\s*(?:#.*)?$/i.test(inline)) return true;
    const entries = only.slice(1).map((line) => /^\s*-\s*([^#\s]+)\s*(?:#.*)?$/.exec(line)?.[1]).filter((entry): entry is string => entry !== undefined);
    if (entries.length > 0 && entries.every((entry) => entry.toLowerCase() === "tags")) return true;
  }

  const rules = nestedPropertyLines(block, "rules");
  if (rules === undefined) return false;
  const items = rules.slice(1).filter((line) => /^\s*-\s+/.test(line));
  return items.length > 0 && items.every((line) => /-\s+if:\s*.*\$CI_COMMIT_TAG\b/.test(line) && !/\$CI_(?:COMMIT_BRANCH|DEFAULT_BRANCH|PIPELINE_SOURCE)\b/.test(line));
}

function nestedPropertyLines(block: YamlBlock, property: string): string[] | undefined {
  const indentation = directChildIndentation(block);
  if (indentation === undefined) return undefined;
  const start = block.lines.findIndex((line, index) => index > 0 && new RegExp(`^\\s{${indentation}}${property}:`).test(line));
  if (start < 0) return undefined;
  let end = block.lines.length;
  for (let index = start + 1; index < block.lines.length; index += 1) {
    const line = block.lines[index] ?? "";
    if (line.trim() === "" || line.trimStart().startsWith("#")) continue;
    if (line.search(/\S/) <= indentation) { end = index; break; }
  }
  return block.lines.slice(start, end);
}

function directChildIndentation(block: YamlBlock): number | undefined {
  const indentations = block.lines.slice(1)
    .filter((line) => line.trim() !== "" && !line.trimStart().startsWith("#"))
    .map((line) => line.search(/\S/))
    .filter((indentation) => indentation > 0);
  return indentations.length === 0 ? undefined : Math.min(...indentations);
}

function test(source: string, expression: MatchExpression): boolean {
  return new RegExp(expression.pattern, expression.flags).test(source);
}

function locate(source: string, expression: MatchExpression): { line: number; snippet: string } | undefined {
  const match = new RegExp(expression.pattern, expression.flags).exec(source);
  if (match?.index === undefined) return undefined;
  const line = source.slice(0, match.index).split(/\r?\n/).length;
  return { line, snippet: source.split(/\r?\n/)[line - 1]?.trim().slice(0, 240) ?? "" };
}

async function walk(root: string): Promise<string[]> {
  const files: string[] = [];
  async function visit(relative: string): Promise<void> {
    if (files.length >= MAX_FILES) return;
    const entries = await readdir(join(root, relative), { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (files.length >= MAX_FILES) return;
      const path = relative ? join(relative, entry.name) : entry.name;
      if (entry.isDirectory() && !SKIPPED.has(entry.name)) await visit(path);
      else if (entry.isFile()) files.push(path.split(sep).join("/"));
    }
  }
  await visit("");
  return files.sort();
}

function matchesGlob(path: string, glob: string): boolean {
  let pattern = "^";
  for (let index = 0; index < glob.length; index += 1) {
    const character = glob[index];
    if (character === "*" && glob[index + 1] === "*") {
      if (glob[index + 2] === "/") { pattern += "(?:.*/)?"; index += 2; }
      else { pattern += ".*"; index += 1; }
    } else if (character === "*") pattern += "[^/]*";
    else if (character === "?") pattern += "[^/]";
    else pattern += character !== undefined && "^$+?.()|{}[]".includes(character) ? "\\" + character : character;
  }
  return new RegExp(`${pattern}$`, "i").test(path);
}
