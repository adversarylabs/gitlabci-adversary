# Initial checks

## gitlab-ci.mutable-image

- Severity: medium
- Category: supply-chain
- Recommendation: Pin job and service images to digests or exact versions.

## gitlab-ci.privileged

- Severity: high
- Category: security
- Recommendation: Use rootless builders or protected dedicated runners.

## gitlab-ci.allow-failure

- Severity: medium
- Category: correctness
- Recommendation: Keep tests and security scans hard-failing.

