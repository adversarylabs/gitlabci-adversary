import { type Confidence, type Severity } from "@adversarylabs/sdk";

export interface MatchExpression { pattern: string; flags: string }
interface ContentMatch { kind: "content"; files: string[]; pattern: MatchExpression; requires: MatchExpression[] }
interface MissingContentMatch { kind: "missing-content"; files: string[]; trigger: MatchExpression; required: MatchExpression }
interface MissingFileMatch { kind: "missing-file"; triggerFiles: string[]; requiredFiles: string[] }
export interface RuleSpec {
  id: string; title: string; summary: string; category: string; severity: Severity; confidence: Confidence;
  whyItMatters: string; impact: string; recommendation: string; complexity: "trivial" | "small" | "medium" | "large"; tags: string[];
  match: ContentMatch | MissingContentMatch | MissingFileMatch;
}
export interface AdversarySpec { id: string; displayName: string; description: string; files: string[]; rules: RuleSpec[] }

export const spec = {
  "id": "gitlab-ci",
  "displayName": "GitLab CI",
  "description": "Reviews GitLab CI for privileged runners, secret leakage, mutable images, and unpinned includes.",
  "files": [
    ".gitlab-ci.yml",
    ".gitlab-ci.yaml",
    ".gitlab/ci/*.yml",
    ".gitlab/ci/*.yaml",
    ".gitlab/ci/**/*.yml",
    ".gitlab/ci/**/*.yaml"
  ],
  "rules": [
    {
      "id": "gitlab-ci.privileged",
      "title": "Job requests privileged container execution",
      "summary": "Job requests privileged container execution",
      "category": "security",
      "severity": "critical",
      "confidence": "high",
      "whyItMatters": "Privileged jobs can take over the runner host.",
      "impact": "Full root access to the runner machine.",
      "recommendation": "Use rootless builders or protected dedicated runners.",
      "complexity": "small",
      "tags": [
        "security",
        "privileged"
      ],
      "match": {
        "kind": "content",
        "files": [
          ".gitlab-ci.yml",
          ".gitlab-ci.yaml",
          ".gitlab/ci/*.yml",
          ".gitlab/ci/*.yaml",
          ".gitlab/ci/**/*.yml",
          ".gitlab/ci/**/*.yaml"
        ],
        "pattern": {
          "pattern": "privileged:\\s*true",
          "flags": "i"
        },
        "requires": []
      }
    },
    {
      "id": "gitlab-ci.secret-in-script-echo",
      "title": "Script echoes secret-like CI variables",
      "summary": "Script echoes secret-like CI variables",
      "category": "security",
      "severity": "critical",
      "confidence": "high",
      "whyItMatters": "Job logs retain secrets; pipelines can exfiltrate variables.",
      "impact": "Credential leakage via CI logs.",
      "recommendation": "Never echo secrets; use masked protected variables.",
      "complexity": "small",
      "tags": [
        "security",
        "secrets"
      ],
      "match": {
        "kind": "content",
        "files": [
          ".gitlab-ci.yml",
          ".gitlab-ci.yaml",
          ".gitlab/ci/*.yml",
          ".gitlab/ci/*.yaml",
          ".gitlab/ci/**/*.yml",
          ".gitlab/ci/**/*.yaml"
        ],
        "pattern": {
          "pattern": "(?:echo|printenv|env)\\s+[^#\\n]*(?:\\$CI_JOB_TOKEN|\\$CI_REGISTRY_PASSWORD|\\$(?:[A-Z0-9_]*(?:PASSWORD|TOKEN|SECRET|PRIVATE_KEY)[A-Z0-9_]*))",
          "flags": "i"
        },
        "requires": []
      }
    },
    {
      "id": "gitlab-ci.mutable-image",
      "title": "CI image uses a mutable tag",
      "summary": "CI image uses a mutable tag",
      "category": "supply-chain",
      "severity": "high",
      "confidence": "high",
      "whyItMatters": "Floating tags make CI non-reproducible.",
      "impact": "Unexpected image content on rebuild.",
      "recommendation": "Pin job and service images to digests or exact versions.",
      "complexity": "small",
      "tags": [
        "supply-chain",
        "image"
      ],
      "match": {
        "kind": "content",
        "files": [
          ".gitlab-ci.yml",
          ".gitlab-ci.yaml",
          ".gitlab/ci/*.yml",
          ".gitlab/ci/*.yaml",
          ".gitlab/ci/**/*.yml",
          ".gitlab/ci/**/*.yaml"
        ],
        "pattern": {
          "pattern": "image:\\s*(?:name:\\s*)?[^\\s]+:(?:latest|main|edge)\\b",
          "flags": "i"
        },
        "requires": []
      }
    },
    {
      "id": "gitlab-ci.dind-socket-mount",
      "title": "Pipeline references the Docker socket",
      "summary": "Pipeline references the Docker socket",
      "category": "security",
      "severity": "high",
      "confidence": "high",
      "whyItMatters": "Docker socket access is host-root equivalent.",
      "impact": "Container escape via Docker API.",
      "recommendation": "Use isolated builders without host socket.",
      "complexity": "small",
      "tags": [
        "security",
        "docker-sock"
      ],
      "match": {
        "kind": "content",
        "files": [
          ".gitlab-ci.yml",
          ".gitlab-ci.yaml",
          ".gitlab/ci/*.yml",
          ".gitlab/ci/*.yaml",
          ".gitlab/ci/**/*.yml",
          ".gitlab/ci/**/*.yaml"
        ],
        "pattern": {
          "pattern": "/var/run/docker\\.sock|DOCKER_HOST\\s*[:=]\\s*unix:///var/run/docker\\.sock",
          "flags": "i"
        },
        "requires": []
      }
    },
    {
      "id": "gitlab-ci.curl-pipe-bash",
      "title": "Script pipes remote content to a shell",
      "summary": "Script pipes remote content to a shell",
      "category": "security",
      "severity": "high",
      "confidence": "high",
      "whyItMatters": "Remote code execution in privileged CI identity.",
      "impact": "Attacker-controlled install script runs as the job.",
      "recommendation": "Download, verify checksum, then execute.",
      "complexity": "small",
      "tags": [
        "security",
        "curl-pipe"
      ],
      "match": {
        "kind": "content",
        "files": [
          ".gitlab-ci.yml",
          ".gitlab-ci.yaml",
          ".gitlab/ci/*.yml",
          ".gitlab/ci/*.yaml",
          ".gitlab/ci/**/*.yml",
          ".gitlab/ci/**/*.yaml"
        ],
        "pattern": {
          "pattern": "(?:curl|wget)[^\\n|]*\\|\\s*(?:ba)?sh",
          "flags": "i"
        },
        "requires": []
      }
    },
    {
      "id": "gitlab-ci.include-remote-unpinned",
      "title": "include pulls CI config from a mutable remote",
      "summary": "include pulls CI config from a mutable remote",
      "category": "supply-chain",
      "severity": "high",
      "confidence": "high",
      "whyItMatters": "Pipeline definition becomes mutable third-party code.",
      "impact": "Compromised shared CI can run as your project.",
      "recommendation": "Pin include project ref to a SHA or protected tag; vendor remotes.",
      "complexity": "small",
      "tags": [
        "supply-chain",
        "include"
      ],
      "match": {
        "kind": "content",
        "files": [
          ".gitlab-ci.yml",
          ".gitlab-ci.yaml",
          ".gitlab/ci/*.yml",
          ".gitlab/ci/*.yaml",
          ".gitlab/ci/**/*.yml",
          ".gitlab/ci/**/*.yaml"
        ],
        "pattern": {
          "pattern": "remote:\\s*['\\\"]?https?://",
          "flags": "i"
        },
        "requires": []
      }
    },
    {
      "id": "gitlab-ci.allow-failure",
      "title": "Critical job allows failure",
      "summary": "Critical job allows failure",
      "category": "correctness",
      "severity": "medium",
      "confidence": "high",
      "whyItMatters": "Security and test gates become cosmetic.",
      "impact": "Broken main looks green.",
      "recommendation": "Keep tests and security scans hard-failing.",
      "complexity": "small",
      "tags": [
        "correctness",
        "gates"
      ],
      "match": {
        "kind": "content",
        "files": [
          ".gitlab-ci.yml",
          ".gitlab-ci.yaml",
          ".gitlab/ci/*.yml",
          ".gitlab/ci/*.yaml",
          ".gitlab/ci/**/*.yml",
          ".gitlab/ci/**/*.yaml"
        ],
        "pattern": {
          "pattern": "(?:^|\\n)test\\s*:(?:[^\\n]*\\n)+?[^\\n]*allow_failure:\\s*true",
          "flags": "i"
        },
        "requires": []
      }
    },
    {
      "id": "gitlab-ci.script-yaml-injection-ci-commit",
      "title": "Untrusted CI variable used in eval or sh -c",
      "summary": "Untrusted CI variable used in eval or sh -c",
      "category": "security",
      "severity": "medium",
      "confidence": "high",
      "whyItMatters": "eval/sh -c over commit/MR fields enables code execution.",
      "impact": "Branch names or messages inject shell.",
      "recommendation": "Quote expansions; avoid eval; use structured args.",
      "complexity": "small",
      "tags": [
        "security",
        "injection"
      ],
      "match": {
        "kind": "content",
        "files": [
          ".gitlab-ci.yml",
          ".gitlab-ci.yaml",
          ".gitlab/ci/*.yml",
          ".gitlab/ci/*.yaml",
          ".gitlab/ci/**/*.yml",
          ".gitlab/ci/**/*.yaml"
        ],
        "pattern": {
          "pattern": "(?:eval|sh\\s+-c|bash\\s+-c)\\s+[\\\"']?[^\\\"'\\n]*\\$(?:CI_COMMIT_REF_NAME|CI_COMMIT_MESSAGE|CI_MERGE_REQUEST_TITLE)",
          "flags": "i"
        },
        "requires": []
      }
    }
  ]
} as const satisfies AdversarySpec;
