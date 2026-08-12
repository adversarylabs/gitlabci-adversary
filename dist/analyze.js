import { execFile } from "node:child_process";
import { readFile, readdir } from "node:fs/promises";
import { join, sep } from "node:path";
import { promisify } from "node:util";
import { observationFor } from "./rules.js";
import { spec } from "./spec.js";
const SKIPPED = new Set([".adversary", ".git", ".hg", ".next", ".svn", "coverage", "dist", "node_modules", "target", "vendor"]);
const MAX_FILES = 5000;
const MAX_SOURCE_BYTES = 750_000;
const execute = promisify(execFile);
const RESERVED_TOP_LEVEL_KEYS = new Set([
    "after_script", "before_script", "cache", "default", "image", "include", "pages", "services", "stages", "variables", "workflow",
]);
const RELEASE_JOB = /(?:^|[-_.])(deploy(?:ment)?|publish(?:ing)?|release)(?:$|[-_.])/i;
export async function analyzeRepository(ctx) {
    // Full tree for existence/context checks; content uses CLI/SDK review scope.
    const allPaths = await walk(ctx.repoPath);
    const scoped = await ctx.loadInScopeSources({
        include: (path) => !path.split("/").some((segment) => SKIPPED.has(segment)) &&
            isYamlPath(path),
        limit: MAX_FILES,
    });
    const wholeTarget = ctx.change === null || ctx.change.scanMode === "all";
    const sources = [];
    for (const file of scoped) {
        const change = wholeTarget || file.status === "repository"
            ? { changedLines: new Set(), status: "repository" }
            : await changedSource(ctx, file.path);
        sources.push({
            path: file.path,
            source: file.content,
            inScope: true,
            changedLines: change.changedLines,
            status: change.status,
        });
    }
    const configuration = await discoverGitlabConfiguration(ctx.repoPath, allPaths, sources);
    const configurationPaths = new Set(configuration?.sources.map((file) => file.path) ?? []);
    const reviewedByPath = new Map(sources.filter((file) => configurationPaths.has(file.path) || spec.files.some((glob) => matchesGlob(file.path, glob))).map((file) => [file.path, file]));
    if (configuration?.root.inScope === true) {
        for (const file of configuration.sources)
            reviewedByPath.set(file.path, file);
    }
    const reviewedSources = [...reviewedByPath.values()].sort((left, right) => left.path.localeCompare(right.path));
    ctx.summary.files_scanned = reviewedSources.length;
    const detections = spec.rules.flatMap((rule) => evaluate(rule, sources, allPaths, configuration));
    detections.sort((a, b) => a.rule.id.localeCompare(b.rule.id) || a.file.localeCompare(b.file) || a.line - b.line || a.label.localeCompare(b.label));
    for (const detection of detections)
        ctx.observe(observationFor(detection));
    if (reviewedSources.length > 0 && detections.length === 0) {
        ctx.review.positive({
            key: `${spec.id}.reviewed`,
            summary: `Reviewed ${reviewedSources.length} ${spec.displayName} configuration file${reviewedSources.length === 1 ? "" : "s"} without finding a material issue.`,
            evidence: reviewedSources.slice(0, 5).map((file) => ({ file: file.path, line: 1 })),
        });
    }
}
function evaluate(rule, sources, allPaths, configuration) {
    const match = rule.match;
    if (match.kind === "missing-file") {
        const triggers = allPaths.filter((path) => match.triggerFiles.some((glob) => matchesGlob(path, glob))).sort();
        const required = allPaths.some((path) => match.requiredFiles.some((glob) => matchesGlob(path, glob)));
        if (triggers.length === 0 || required)
            return [];
        return [{ rule, file: triggers[0] ?? ".", line: 1, snippet: triggers[0] ?? "", label: rule.title, data: { triggerFiles: triggers.slice(0, 10), requiredFiles: match.requiredFiles } }];
    }
    if (match.kind === "release-interruptible") {
        return detectInterruptibleReleases(rule, sources, configuration, match.files);
    }
    const matchingSources = sources.filter((file) => match.files.some((glob) => matchesGlob(file.path, glob)));
    if (match.kind === "missing-content") {
        return matchingSources.flatMap((file) => {
            if (!test(file.source, match.trigger) || test(file.source, match.required))
                return [];
            const location = locateEligible(file, match.trigger);
            if (location === undefined)
                return [];
            return [{ rule, file: file.path, ...location, label: rule.title, data: { requiredPattern: match.required.pattern } }];
        });
    }
    return matchingSources.flatMap((file) => {
        if (!match.requires.every((pattern) => test(file.source, pattern)))
            return [];
        const location = locateEligible(file, match.pattern);
        if (location === undefined)
            return [];
        return [{ rule, file: file.path, ...location, label: rule.title, data: { matchedPattern: match.pattern.pattern } }];
    });
}
function detectInterruptibleReleases(rule, sources, configuration, conventionalFiles) {
    const configuredPaths = new Set(configuration?.sources.map((file) => file.path) ?? []);
    const configured = configuration === undefined
        ? []
        : configuration.sources.filter((file) => file.inScope || configuration.root.inScope)
            .flatMap((file) => detectInterruptibleRelease(rule, file, configuration.root));
    const standalone = sources
        .filter((file) => !configuredPaths.has(file.path) && conventionalFiles.some((glob) => matchesGlob(file.path, glob)))
        .flatMap((file) => detectInterruptibleRelease(rule, file, file));
    return [...configured, ...standalone];
}
function detectInterruptibleRelease(rule, file, root) {
    const blocks = topLevelBlocks(file.source);
    const rootBlocks = file.path === root.path ? blocks : topLevelBlocks(root.source);
    if (hasAutoCancelDisabled(rootBlocks) || (file.path !== root.path && hasAutoCancelDisabled(blocks)))
        return [];
    const rootDefaultBlock = rootBlocks.find((block) => block.key === "default");
    const fileDefaultBlock = blocks.find((block) => block.key === "default");
    const rootDefaultInterruptible = rootDefaultBlock === undefined ? undefined : booleanProperty(rootDefaultBlock, "interruptible");
    const fileDefaultInterruptible = fileDefaultBlock === undefined ? undefined : booleanProperty(fileDefaultBlock, "interruptible");
    const defaultInterruptible = rootDefaultInterruptible ?? fileDefaultInterruptible;
    const defaultBlock = rootDefaultInterruptible === undefined ? fileDefaultBlock : rootDefaultBlock;
    const defaultFile = rootDefaultInterruptible === undefined ? file.path : root.path;
    return blocks.flatMap((block) => {
        if (RESERVED_TOP_LEVEL_KEYS.has(block.key) || block.key.startsWith("."))
            return [];
        const stage = scalarProperty(block, "stage");
        if (!RELEASE_JOB.test(block.key) && (stage === undefined || !RELEASE_JOB.test(stage)))
            return [];
        if (isTagOnly(block))
            return [];
        const jobInterruptible = booleanProperty(block, "interruptible");
        if (jobInterruptible === false)
            return [];
        const inherited = jobInterruptible === undefined && defaultInterruptible === true;
        if (jobInterruptible !== true && !inherited)
            return [];
        if (!directFindingEligible(file, block.line))
            return [];
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
                    defaultFile: inherited ? defaultFile : undefined,
                    configurationRoot: root.path,
                },
            }];
    });
}
async function discoverGitlabConfiguration(repoPath, allPaths, inScopeSources) {
    const rootPath = [".gitlab-ci.yml", ".gitlab-ci.yaml"].find((path) => allPaths.includes(path));
    if (rootPath === undefined)
        return undefined;
    const byPath = new Map(inScopeSources.map((file) => [file.path, file]));
    const ensureSource = async (path) => {
        const existing = byPath.get(path);
        if (existing !== undefined)
            return existing;
        try {
            const content = await readFile(join(repoPath, path));
            if (content.byteLength > MAX_SOURCE_BYTES || content.includes(0))
                return undefined;
            const source = {
                path,
                source: content.toString("utf8"),
                inScope: false,
                changedLines: new Set(),
                status: "context",
            };
            byPath.set(path, source);
            return source;
        }
        catch {
            return undefined;
        }
    };
    const root = await ensureSource(rootPath);
    if (root === undefined)
        return undefined;
    const discovered = new Map([[root.path, root]]);
    const queue = [root];
    while (queue.length > 0) {
        const current = queue.shift();
        if (current === undefined)
            break;
        const patterns = localIncludePatterns(current.source);
        const includedPaths = allPaths.filter((path) => isYamlPath(path) && patterns.some((pattern) => matchesGlob(path, pattern)));
        for (const path of includedPaths) {
            if (discovered.has(path))
                continue;
            const source = await ensureSource(path);
            if (source === undefined)
                continue;
            discovered.set(path, source);
            queue.push(source);
        }
    }
    return { root, sources: [...discovered.values()].sort((left, right) => left.path.localeCompare(right.path)) };
}
function directFindingEligible(file, line) {
    return file.status !== "modified" || file.changedLines.has(line);
}
async function changedSource(ctx, path) {
    const base = ctx.change?.baseRef;
    if (base === undefined || !(await existsAtRevision(ctx.repoPath, base, path))) {
        return { changedLines: new Set(), status: "added" };
    }
    const args = ["diff", "--unified=0", base];
    const head = ctx.change?.headRef;
    if (head !== undefined && !ctx.change?.worktree)
        args.push(head);
    args.push("--", path);
    const patch = await gitOutput(ctx.repoPath, args);
    return { changedLines: changedLineNumbers(patch), status: "modified" };
}
async function existsAtRevision(repoPath, revision, path) {
    try {
        await execute("git", ["-C", repoPath, "cat-file", "-e", `${revision}:${path}`], {
            maxBuffer: 1024 * 1024,
        });
        return true;
    }
    catch {
        return false;
    }
}
async function gitOutput(repoPath, args) {
    const result = await execute("git", ["-C", repoPath, ...args], {
        encoding: "utf8",
        maxBuffer: 8 * 1024 * 1024,
    });
    return result.stdout;
}
function changedLineNumbers(patch) {
    const lines = new Set();
    for (const match of patch.matchAll(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/gm)) {
        const start = Number(match[1]);
        const count = match[2] === undefined ? 1 : Number(match[2]);
        for (let line = start; line < start + count; line += 1)
            lines.add(line);
    }
    return lines;
}
function localIncludePatterns(source) {
    const patterns = [];
    const inline = source.split(/\r?\n/).find((line) => /^include:\s*\S/.test(line));
    if (inline !== undefined) {
        const value = inline.replace(/^include:\s*/, "");
        const localObject = /^\{\s*local:\s*(.*?)\s*\}\s*(?:#.*)?$/.exec(value)?.[1];
        patterns.push(...parseIncludeValues(localObject ?? value));
    }
    const include = topLevelBlocks(source).find((block) => block.key === "include");
    if (include === undefined)
        return uniqueLocalPatterns(patterns);
    const directIndentation = directChildIndentation(include);
    if (directIndentation === undefined)
        return uniqueLocalPatterns(patterns);
    let localListIndentation;
    for (const line of include.lines.slice(1)) {
        if (line.trim() === "" || line.trimStart().startsWith("#"))
            continue;
        const indentation = line.search(/\S/);
        if (localListIndentation !== undefined && indentation <= localListIndentation)
            localListIndentation = undefined;
        const local = /^(\s*)(?:-\s*)?local:\s*(.*?)\s*(?:#.*)?$/.exec(line);
        if (local !== null && indentation === directIndentation) {
            const value = local[2]?.trim() ?? "";
            if (value === "")
                localListIndentation = local[1]?.length ?? indentation;
            else
                patterns.push(...parseIncludeValues(value));
            continue;
        }
        if (localListIndentation !== undefined && indentation > localListIndentation) {
            const item = /^\s*-\s*(.*?)\s*(?:#.*)?$/.exec(line)?.[1];
            if (item !== undefined)
                patterns.push(...parseIncludeValues(item));
            continue;
        }
        const shorthand = /^\s*-\s*(.*?)\s*(?:#.*)?$/.exec(line)?.[1];
        if (shorthand !== undefined && indentation === directIndentation)
            patterns.push(...parseIncludeValues(shorthand));
    }
    return uniqueLocalPatterns(patterns);
}
function parseIncludeValues(value) {
    const trimmed = value.trim();
    const values = trimmed.startsWith("[") && trimmed.endsWith("]")
        ? trimmed.slice(1, -1).split(",")
        : [trimmed];
    return values.map((entry) => normalizeLocalPattern(entry)).filter((entry) => entry !== undefined);
}
function normalizeLocalPattern(value) {
    let normalized = value.trim();
    if (normalized.startsWith('"') || normalized.startsWith("'")) {
        const quote = normalized[0];
        const end = normalized.indexOf(quote, 1);
        if (end < 0)
            return undefined;
        normalized = normalized.slice(1, end);
    }
    else
        normalized = normalized.replace(/\s+#.*$/, "");
    normalized = normalized.replace(/^\.\//, "").replace(/^\//, "");
    if (normalized === "" || normalized.includes("$") || normalized.includes(":") ||
        /(?:^|\/)\.\.(?:\/|$)/.test(normalized) || !/\.ya?ml$/i.test(normalized))
        return undefined;
    return normalized;
}
function uniqueLocalPatterns(patterns) {
    return [...new Set(patterns)].sort();
}
function isYamlPath(path) {
    return /\.ya?ml$/i.test(path);
}
function hasAutoCancelDisabled(blocks) {
    const workflow = blocks.find((block) => block.key === "workflow");
    if (workflow === undefined)
        return false;
    const autoCancel = nestedPropertyLines(workflow, "auto_cancel");
    if (autoCancel === undefined)
        return false;
    const indentation = directChildIndentation({ ...workflow, lines: autoCancel });
    if (indentation === undefined)
        return false;
    return autoCancel.slice(1).some((line) => new RegExp(`^\\s{${indentation}}on_new_commit:\\s*["']?none["']?\\s*(?:#.*)?$`, "i").test(line));
}
function topLevelBlocks(source) {
    const lines = source.split(/\r?\n/);
    const starts = [];
    for (let index = 0; index < lines.length; index += 1) {
        const line = lines[index] ?? "";
        const match = /^([^\s#][^:]*):(?:\s*(?:&\S+)?\s*(?:#.*)?)$/.exec(line);
        if (match?.[1] === undefined)
            continue;
        starts.push({ key: stripQuotes(match[1].trim()), index });
    }
    return starts.map((start, index) => {
        const end = starts[index + 1]?.index ?? lines.length;
        return { key: start.key, line: start.index + 1, lines: lines.slice(start.index, end) };
    });
}
function stripQuotes(value) {
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'")))
        return value.slice(1, -1);
    return value;
}
function booleanProperty(block, property) {
    const indentation = directChildIndentation(block);
    if (indentation === undefined)
        return undefined;
    const pattern = new RegExp(`^\\s{${indentation}}${property}:\\s*(true|false)\\s*(?:#.*)?$`, "i");
    for (const line of block.lines.slice(1)) {
        const value = pattern.exec(line)?.[1]?.toLowerCase();
        if (value === "true")
            return true;
        if (value === "false")
            return false;
    }
    return undefined;
}
function scalarProperty(block, property) {
    const indentation = directChildIndentation(block);
    if (indentation === undefined)
        return undefined;
    const pattern = new RegExp(`^\\s{${indentation}}${property}:\\s*["']?([^"'#\\s]+)["']?\\s*(?:#.*)?$`, "i");
    for (const line of block.lines.slice(1)) {
        const value = pattern.exec(line)?.[1];
        if (value !== undefined)
            return value;
    }
    return undefined;
}
function isTagOnly(block) {
    const only = nestedPropertyLines(block, "only");
    if (only !== undefined) {
        const inline = only[0]?.replace(/^\s*only:\s*/, "").trim() ?? "";
        if (/^(?:tags|\[\s*tags\s*\])\s*(?:#.*)?$/i.test(inline))
            return true;
        const entries = only.slice(1).map((line) => /^\s*-\s*([^#\s]+)\s*(?:#.*)?$/.exec(line)?.[1]).filter((entry) => entry !== undefined);
        if (entries.length > 0 && entries.every((entry) => entry.toLowerCase() === "tags"))
            return true;
    }
    const rules = nestedPropertyLines(block, "rules");
    if (rules === undefined)
        return false;
    const items = rules.slice(1).filter((line) => /^\s*-\s+/.test(line));
    return items.length > 0 && items.every((line) => /-\s+if:\s*.*\$CI_COMMIT_TAG\b/.test(line) && !/\$CI_(?:COMMIT_BRANCH|DEFAULT_BRANCH|PIPELINE_SOURCE)\b/.test(line));
}
function nestedPropertyLines(block, property) {
    const indentation = directChildIndentation(block);
    if (indentation === undefined)
        return undefined;
    const start = block.lines.findIndex((line, index) => index > 0 && new RegExp(`^\\s{${indentation}}${property}:`).test(line));
    if (start < 0)
        return undefined;
    let end = block.lines.length;
    for (let index = start + 1; index < block.lines.length; index += 1) {
        const line = block.lines[index] ?? "";
        if (line.trim() === "" || line.trimStart().startsWith("#"))
            continue;
        if (line.search(/\S/) <= indentation) {
            end = index;
            break;
        }
    }
    return block.lines.slice(start, end);
}
function directChildIndentation(block) {
    const indentations = block.lines.slice(1)
        .filter((line) => line.trim() !== "" && !line.trimStart().startsWith("#"))
        .map((line) => line.search(/\S/))
        .filter((indentation) => indentation > 0);
    return indentations.length === 0 ? undefined : Math.min(...indentations);
}
function test(source, expression) {
    return new RegExp(expression.pattern, expression.flags).test(source);
}
function locate(source, expression) {
    const match = new RegExp(expression.pattern, expression.flags).exec(source);
    if (match?.index === undefined)
        return undefined;
    const line = source.slice(0, match.index).split(/\r?\n/).length;
    return { line, snippet: source.split(/\r?\n/)[line - 1]?.trim().slice(0, 240) ?? "" };
}
function locateEligible(file, expression) {
    const flags = expression.flags.includes("g") ? expression.flags : `${expression.flags}g`;
    const matcher = new RegExp(expression.pattern, flags);
    for (const match of file.source.matchAll(matcher)) {
        if (match.index === undefined)
            continue;
        const line = file.source.slice(0, match.index).split(/\r?\n/).length;
        if (!directFindingEligible(file, line))
            continue;
        return { line, snippet: file.source.split(/\r?\n/)[line - 1]?.trim().slice(0, 240) ?? "" };
    }
    return undefined;
}
async function walk(root) {
    const files = [];
    async function visit(relative) {
        if (files.length >= MAX_FILES)
            return;
        const entries = await readdir(join(root, relative), { withFileTypes: true });
        entries.sort((a, b) => a.name.localeCompare(b.name));
        for (const entry of entries) {
            if (files.length >= MAX_FILES)
                return;
            const path = relative ? join(relative, entry.name) : entry.name;
            if (entry.isDirectory() && !SKIPPED.has(entry.name))
                await visit(path);
            else if (entry.isFile())
                files.push(path.split(sep).join("/"));
        }
    }
    await visit("");
    return files.sort();
}
function matchesGlob(path, glob) {
    let pattern = "^";
    for (let index = 0; index < glob.length; index += 1) {
        const character = glob[index];
        if (character === "*" && glob[index + 1] === "*") {
            if (glob[index + 2] === "/") {
                pattern += "(?:.*/)?";
                index += 2;
            }
            else {
                pattern += ".*";
                index += 1;
            }
        }
        else if (character === "*")
            pattern += "[^/]*";
        else if (character === "?")
            pattern += "[^/]";
        else
            pattern += character !== undefined && "^$+?.()|{}[]".includes(character) ? "\\" + character : character;
    }
    return new RegExp(`${pattern}$`, "i").test(path);
}
