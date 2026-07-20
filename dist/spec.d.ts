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
    match: ContentMatch | MissingContentMatch | MissingFileMatch;
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
    readonly description: "Reviews GitLab CI for privileged runners, mutable images, and ineffective gates.";
    readonly files: [".gitlab-ci.yml", ".gitlab-ci.yaml", ".gitlab/ci/*.yml", ".gitlab/ci/*.yaml"];
    readonly rules: [{
        readonly id: "gitlab-ci.mutable-image";
        readonly title: "CI image uses a mutable tag";
        readonly summary: "CI image uses a mutable tag";
        readonly category: "supply-chain";
        readonly severity: "medium";
        readonly confidence: "high";
        readonly whyItMatters: "CI image uses a mutable tag weakens an important supply-chain boundary.";
        readonly impact: "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.";
        readonly recommendation: "Pin job and service images to digests or exact versions.";
        readonly complexity: "small";
        readonly tags: ["supply-chain", "mutable-image"];
        readonly match: {
            readonly kind: "content";
            readonly files: [".gitlab-ci.yml", ".gitlab-ci.yaml", ".gitlab/ci/*.yml", ".gitlab/ci/*.yaml"];
            readonly pattern: {
                readonly pattern: "image:\\s*(?:name:\\s*)?[^\\s]+:(?:latest|main|edge)\\b";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "gitlab-ci.privileged";
        readonly title: "Job requests privileged container execution";
        readonly summary: "Job requests privileged container execution";
        readonly category: "security";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "Job requests privileged container execution weakens an important security boundary.";
        readonly impact: "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.";
        readonly recommendation: "Use rootless builders or protected dedicated runners.";
        readonly complexity: "small";
        readonly tags: ["security", "privileged"];
        readonly match: {
            readonly kind: "content";
            readonly files: [".gitlab-ci.yml", ".gitlab-ci.yaml", ".gitlab/ci/*.yml", ".gitlab/ci/*.yaml"];
            readonly pattern: {
                readonly pattern: "privileged:\\s*true";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "gitlab-ci.allow-failure";
        readonly title: "Required validation is allowed to fail";
        readonly summary: "Required validation is allowed to fail";
        readonly category: "correctness";
        readonly severity: "medium";
        readonly confidence: "high";
        readonly whyItMatters: "Required validation is allowed to fail weakens an important correctness boundary.";
        readonly impact: "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.";
        readonly recommendation: "Keep tests and security scans hard-failing.";
        readonly complexity: "small";
        readonly tags: ["correctness", "allow-failure"];
        readonly match: {
            readonly kind: "content";
            readonly files: [".gitlab-ci.yml", ".gitlab-ci.yaml", ".gitlab/ci/*.yml", ".gitlab/ci/*.yaml"];
            readonly pattern: {
                readonly pattern: "(?:test|lint|scan|audit):[\\s\\S]{0,220}allow_failure:\\s*true";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }];
};
export {};
