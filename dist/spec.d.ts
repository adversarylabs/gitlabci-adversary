import { type Confidence, type Severity } from "@adversarylabs/sdk";
export interface MatchExpression {
    pattern: string;
    flags: string;
}
interface ContentMatch {
    kind: "content";
    files: string[];
    pattern: MatchExpression;
    requires: MatchExpression[];
}
interface MissingContentMatch {
    kind: "missing-content";
    files: string[];
    trigger: MatchExpression;
    required: MatchExpression;
}
interface MissingFileMatch {
    kind: "missing-file";
    triggerFiles: string[];
    requiredFiles: string[];
}
interface ReleaseInterruptibleMatch {
    kind: "release-interruptible";
    files: string[];
}
export interface RuleSpec {
    id: string;
    title: string;
    summary: string;
    category: string;
    severity: Severity;
    confidence: Confidence;
    whyItMatters: string;
    impact: string;
    recommendation: string;
    complexity: "trivial" | "small" | "medium" | "large";
    tags: string[];
    match: ContentMatch | MissingContentMatch | MissingFileMatch | ReleaseInterruptibleMatch;
}
export interface AdversarySpec {
    id: string;
    displayName: string;
    description: string;
    files: string[];
    rules: RuleSpec[];
}
export declare const spec: {
    readonly id: "gitlab-ci";
    readonly displayName: "GitLab CI";
    readonly description: "Reviews GitLab CI for privileged runners, secret leakage, mutable images, and unpinned includes.";
    readonly files: [".gitlab-ci.yml", ".gitlab-ci.yaml", ".gitlab/ci/*.yml", ".gitlab/ci/*.yaml", ".gitlab/ci/**/*.yml", ".gitlab/ci/**/*.yaml"];
    readonly rules: [{
        readonly id: "gitlab-ci.privileged";
        readonly title: "Job requests privileged container execution";
        readonly summary: "Job requests privileged container execution";
        readonly category: "security";
        readonly severity: "critical";
        readonly confidence: "high";
        readonly whyItMatters: "Privileged jobs can take over the runner host.";
        readonly impact: "Full root access to the runner machine.";
        readonly recommendation: "Use rootless builders or protected dedicated runners.";
        readonly complexity: "small";
        readonly tags: ["security", "privileged"];
        readonly match: {
            readonly kind: "content";
            readonly files: [".gitlab-ci.yml", ".gitlab-ci.yaml", ".gitlab/ci/*.yml", ".gitlab/ci/*.yaml", ".gitlab/ci/**/*.yml", ".gitlab/ci/**/*.yaml"];
            readonly pattern: {
                readonly pattern: "privileged:\\s*true";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "gitlab-ci.secret-in-script-echo";
        readonly title: "Script echoes secret-like CI variables";
        readonly summary: "Script echoes secret-like CI variables";
        readonly category: "security";
        readonly severity: "critical";
        readonly confidence: "high";
        readonly whyItMatters: "Job logs retain secrets; pipelines can exfiltrate variables.";
        readonly impact: "Credential leakage via CI logs.";
        readonly recommendation: "Never echo secrets; use masked protected variables.";
        readonly complexity: "small";
        readonly tags: ["security", "secrets"];
        readonly match: {
            readonly kind: "content";
            readonly files: [".gitlab-ci.yml", ".gitlab-ci.yaml", ".gitlab/ci/*.yml", ".gitlab/ci/*.yaml", ".gitlab/ci/**/*.yml", ".gitlab/ci/**/*.yaml"];
            readonly pattern: {
                readonly pattern: "(?:echo|printenv|env)\\s+[^#\\n]*(?:\\$CI_JOB_TOKEN|\\$CI_REGISTRY_PASSWORD|\\$(?:[A-Z0-9_]*(?:PASSWORD|TOKEN|SECRET|PRIVATE_KEY)[A-Z0-9_]*))";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "gitlab-ci.mutable-image";
        readonly title: "CI image uses a mutable tag";
        readonly summary: "CI image uses a mutable tag";
        readonly category: "supply-chain";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "Floating tags make CI non-reproducible.";
        readonly impact: "Unexpected image content on rebuild.";
        readonly recommendation: "Pin job and service images to digests or exact versions.";
        readonly complexity: "small";
        readonly tags: ["supply-chain", "image"];
        readonly match: {
            readonly kind: "content";
            readonly files: [".gitlab-ci.yml", ".gitlab-ci.yaml", ".gitlab/ci/*.yml", ".gitlab/ci/*.yaml", ".gitlab/ci/**/*.yml", ".gitlab/ci/**/*.yaml"];
            readonly pattern: {
                readonly pattern: "image:\\s*(?:name:\\s*)?[^\\s]+:(?:latest|main|edge)\\b";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "gitlab-ci.dind-socket-mount";
        readonly title: "Pipeline references the Docker socket";
        readonly summary: "Pipeline references the Docker socket";
        readonly category: "security";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "Docker socket access is host-root equivalent.";
        readonly impact: "Container escape via Docker API.";
        readonly recommendation: "Use isolated builders without host socket.";
        readonly complexity: "small";
        readonly tags: ["security", "docker-sock"];
        readonly match: {
            readonly kind: "content";
            readonly files: [".gitlab-ci.yml", ".gitlab-ci.yaml", ".gitlab/ci/*.yml", ".gitlab/ci/*.yaml", ".gitlab/ci/**/*.yml", ".gitlab/ci/**/*.yaml"];
            readonly pattern: {
                readonly pattern: "/var/run/docker\\.sock|DOCKER_HOST\\s*[:=]\\s*unix:///var/run/docker\\.sock";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "gitlab-ci.curl-pipe-bash";
        readonly title: "Script pipes remote content to a shell";
        readonly summary: "Script pipes remote content to a shell";
        readonly category: "security";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "Remote code execution in privileged CI identity.";
        readonly impact: "Attacker-controlled install script runs as the job.";
        readonly recommendation: "Download, verify checksum, then execute.";
        readonly complexity: "small";
        readonly tags: ["security", "curl-pipe"];
        readonly match: {
            readonly kind: "content";
            readonly files: [".gitlab-ci.yml", ".gitlab-ci.yaml", ".gitlab/ci/*.yml", ".gitlab/ci/*.yaml", ".gitlab/ci/**/*.yml", ".gitlab/ci/**/*.yaml"];
            readonly pattern: {
                readonly pattern: "(?:curl|wget)[^\\n|]*\\|\\s*(?:ba)?sh";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "gitlab-ci.include-remote-unpinned";
        readonly title: "include pulls CI config from a mutable remote";
        readonly summary: "include pulls CI config from a mutable remote";
        readonly category: "supply-chain";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "Pipeline definition becomes mutable third-party code.";
        readonly impact: "Compromised shared CI can run as your project.";
        readonly recommendation: "Pin include project ref to a SHA or protected tag; vendor remotes.";
        readonly complexity: "small";
        readonly tags: ["supply-chain", "include"];
        readonly match: {
            readonly kind: "content";
            readonly files: [".gitlab-ci.yml", ".gitlab-ci.yaml", ".gitlab/ci/*.yml", ".gitlab/ci/*.yaml", ".gitlab/ci/**/*.yml", ".gitlab/ci/**/*.yaml"];
            readonly pattern: {
                readonly pattern: "remote:\\s*['\\\"]?https?://";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "gitlab-ci.allow-failure";
        readonly title: "Critical job allows failure";
        readonly summary: "Critical job allows failure";
        readonly category: "correctness";
        readonly severity: "medium";
        readonly confidence: "high";
        readonly whyItMatters: "Security and test gates become cosmetic.";
        readonly impact: "Broken main looks green.";
        readonly recommendation: "Keep tests and security scans hard-failing.";
        readonly complexity: "small";
        readonly tags: ["correctness", "gates"];
        readonly match: {
            readonly kind: "content";
            readonly files: [".gitlab-ci.yml", ".gitlab-ci.yaml", ".gitlab/ci/*.yml", ".gitlab/ci/*.yaml", ".gitlab/ci/**/*.yml", ".gitlab/ci/**/*.yaml"];
            readonly pattern: {
                readonly pattern: "(?:^|\\n)test\\s*:(?:[^\\n]*\\n)+?[^\\n]*allow_failure:\\s*true";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "gitlab-ci.script-yaml-injection-ci-commit";
        readonly title: "Untrusted CI variable used in eval or sh -c";
        readonly summary: "Untrusted CI variable used in eval or sh -c";
        readonly category: "security";
        readonly severity: "medium";
        readonly confidence: "high";
        readonly whyItMatters: "eval/sh -c over commit/MR fields enables code execution.";
        readonly impact: "Branch names or messages inject shell.";
        readonly recommendation: "Quote expansions; avoid eval; use structured args.";
        readonly complexity: "small";
        readonly tags: ["security", "injection"];
        readonly match: {
            readonly kind: "content";
            readonly files: [".gitlab-ci.yml", ".gitlab-ci.yaml", ".gitlab/ci/*.yml", ".gitlab/ci/*.yaml", ".gitlab/ci/**/*.yml", ".gitlab/ci/**/*.yaml"];
            readonly pattern: {
                readonly pattern: "(?:eval|sh\\s+-c|bash\\s+-c)\\s+[\\\"']?[^\\\"'\\n]*\\$(?:CI_COMMIT_REF_NAME|CI_COMMIT_MESSAGE|CI_MERGE_REQUEST_TITLE)";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "gitlab-ci.interruptible-release";
        readonly title: "Release job can be canceled by a newer pipeline";
        readonly summary: "Release job can be canceled by a newer pipeline";
        readonly category: "correctness";
        readonly severity: "medium";
        readonly confidence: "high";
        readonly whyItMatters: "GitLab's redundant-pipeline cancellation can stop branch or scheduled release work before publication completes.";
        readonly impact: "A newer pipeline can leave a publish or deployment incomplete.";
        readonly recommendation: "Make the release job and its required path non-interruptible, or isolate release pipelines under non-interruptible defaults.";
        readonly complexity: "small";
        readonly tags: ["correctness", "release", "interruptible"];
        readonly match: {
            readonly kind: "release-interruptible";
            readonly files: [".gitlab-ci.yml", ".gitlab-ci.yaml", ".gitlab/ci/*.yml", ".gitlab/ci/*.yaml", ".gitlab/ci/**/*.yml", ".gitlab/ci/**/*.yaml"];
        };
    }];
};
export {};
