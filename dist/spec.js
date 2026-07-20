export const spec = {
    "id": "gitlab-ci",
    "displayName": "GitLab CI",
    "description": "Reviews GitLab CI for privileged runners, mutable images, and ineffective gates.",
    "files": [
        ".gitlab-ci.yml",
        ".gitlab-ci.yaml",
        ".gitlab/ci/*.yml",
        ".gitlab/ci/*.yaml"
    ],
    "rules": [
        {
            "id": "gitlab-ci.mutable-image",
            "title": "CI image uses a mutable tag",
            "summary": "CI image uses a mutable tag",
            "category": "supply-chain",
            "severity": "medium",
            "confidence": "high",
            "whyItMatters": "CI image uses a mutable tag weakens an important supply-chain boundary.",
            "impact": "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.",
            "recommendation": "Pin job and service images to digests or exact versions.",
            "complexity": "small",
            "tags": [
                "supply-chain",
                "mutable-image"
            ],
            "match": {
                "kind": "content",
                "files": [
                    ".gitlab-ci.yml",
                    ".gitlab-ci.yaml",
                    ".gitlab/ci/*.yml",
                    ".gitlab/ci/*.yaml"
                ],
                "pattern": {
                    "pattern": "image:\\s*(?:name:\\s*)?[^\\s]+:(?:latest|main|edge)\\b",
                    "flags": "i"
                },
                "requires": []
            }
        },
        {
            "id": "gitlab-ci.privileged",
            "title": "Job requests privileged container execution",
            "summary": "Job requests privileged container execution",
            "category": "security",
            "severity": "high",
            "confidence": "high",
            "whyItMatters": "Job requests privileged container execution weakens an important security boundary.",
            "impact": "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.",
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
                    ".gitlab/ci/*.yaml"
                ],
                "pattern": {
                    "pattern": "privileged:\\s*true",
                    "flags": "i"
                },
                "requires": []
            }
        },
        {
            "id": "gitlab-ci.allow-failure",
            "title": "Required validation is allowed to fail",
            "summary": "Required validation is allowed to fail",
            "category": "correctness",
            "severity": "medium",
            "confidence": "high",
            "whyItMatters": "Required validation is allowed to fail weakens an important correctness boundary.",
            "impact": "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.",
            "recommendation": "Keep tests and security scans hard-failing.",
            "complexity": "small",
            "tags": [
                "correctness",
                "allow-failure"
            ],
            "match": {
                "kind": "content",
                "files": [
                    ".gitlab-ci.yml",
                    ".gitlab-ci.yaml",
                    ".gitlab/ci/*.yml",
                    ".gitlab/ci/*.yaml"
                ],
                "pattern": {
                    "pattern": "(?:test|lint|scan|audit):[\\s\\S]{0,220}allow_failure:\\s*true",
                    "flags": "i"
                },
                "requires": []
            }
        }
    ]
};
