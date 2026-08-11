> **Shipped in 0.0.4:** , , , , , , , 
>
> Rules documented below that are not in that list are deferred (not yet in `src/spec.ts`).

# Checks — what gitlab-ci detects

This file is the **public audit list** of detectors for the **gitlab-ci** adversary. High-confidence GitLab CI/CD pipeline defects in `.gitlab-ci.yml` and included CI configs—not a general YAML style linter.

Runtime source of truth: [`src/spec.ts`](src/spec.ts) / [`src/rules.ts`](src/rules.ts).

**Scope:** `.gitlab-ci.yml`, `.gitlab-ci.yaml`, and files referenced via `include:` when present in-repo. Understand job keys, `script`, `image`, `services`, `tags`, `rules`, `only/except`, `allow_failure`.

**Precision stance:** Privileged Docker and secret-echo patterns fire. Benign `allow_failure` on clearly non-gating jobs stays quieter than on `test`/`security` job names.

Public grounding: [GitLab Runner security docs](https://docs.gitlab.com/runner/security/) (privileged mode host access), [GitLab CI variable security](https://docs.gitlab.com/ci/variables/) (malicious `.gitlab-ci.yml` exfiltrating variables), and protected-variable model.

---

## Critical

### `gitlab-ci.privileged`

| | |
| --- | --- |
| **What** | Job or runner config enables Docker privileged mode |
| **Why** | Privileged jobs can take over the runner host ([GitLab Runner security](https://docs.gitlab.com/runner/security/)) |
| **Looks for** | `privileged: true` under job, service, or default; `docker:dind` service **with** privileged true (dind often requires it—still fire with remediation pointing to rootless/Kaniko) |
| **Stays quiet when** | Privileged absent/false |
| **Public examples** | GitLab docs: privileged disables container security boundaries; CI escape writeups |
| **Remediation** | Prefer rootless builders (Kaniko, buildah rootless), protected dedicated runners, never shared privileged runners for untrusted branches |

### `gitlab-ci.secret-in-script-echo`

| | |
| --- | --- |
| **What** | Job script echoes or prints CI variables that look like secrets |
| **Why** | Job logs retain secrets; GitLab warns that pipeline YAML can exfiltrate variables |
| **Looks for** | `script`/`before_script` lines with `echo`/`printenv`/`env` referencing `$CI_JOB_TOKEN`, `$CI_REGISTRY_PASSWORD`, or variables matching `PASSWORD|TOKEN|SECRET|KEY|PRIVATE` |
| **Stays quiet when** | Masked variable usage without echo; `echo` of non-secret `$CI_COMMIT_SHA` etc. |
| **Public examples** | [GitLab CI variable security](https://docs.gitlab.com/ci/variables/) malicious job curling secrets out |
| **Remediation** | Never echo secrets; use masked+protected variables; avoid printing env |

### `gitlab-ci.untrusted-mr-with-secrets`

| | |
| --- | --- |
| **What** | Pipelines on merge requests from forks can run with high-privilege variables |
| **Why** | Contributor-controlled pipeline YAML + secrets = theft |
| **Looks for** | Jobs that run on `merge_request_event` / `only: merge_requests` without `rules` limiting to protected branches, **and** script uses deploy/secret-looking variables |
| **Stays quiet when** | MR jobs are read-only (lint/test without secrets); secrets restricted via protected variables + protected branches |
| **Public examples** | GitLab protected variables docs; analogous to GitHub `pull_request_target` class of bugs |
| **Remediation** | Protected variables only on protected branches; separate untrusted MR pipelines |

---

## High

### `gitlab-ci.mutable-image`

| | |
| --- | --- |
| **What** | Job or service image uses floating tags (`latest` or unpinned) |
| **Why** | Non-reproducible CI; supply-chain tag moves |
| **Looks for** | `image: foo:latest`, `image: foo` without tag/digest, services likewise |
| **Stays quiet when** | Any explicit version tag or `@sha256:` digest (recommend digests, but do not flag versioned tags — that hits most real pipelines); fire on `:latest` / missing tag |
| **Public examples** | Supply-chain CI guidance; same class as GHA unpinned actions |
| **Remediation** | Pin job and service images to digests or exact versions |

### `gitlab-ci.dind-socket-mount`

| | |
| --- | --- |
| **What** | Mounts Docker socket into job |
| **Why** | Equivalent to host root via Docker API |
| **Looks for** | `/var/run/docker.sock` referenced in `script` / `variables` (`docker run -v /var/run/docker.sock:…`, `DOCKER_HOST=unix:///var/run/docker.sock`) or in a committed runner `config.toml` volumes list — job YAML itself cannot mount volumes; the socket arrives via these paths |
| **Stays quiet when** | No docker.sock mounts |
| **Public examples** | Classic CI docker.sock escapes |
| **Remediation** | Use isolated builders without host socket |

### `gitlab-ci.curl-pipe-bash`

| | |
| --- | --- |
| **What** | Script pipes remote content to shell |
| **Why** | Remote code execution in privileged CI identity |
| **Looks for** | `curl … | bash`, `wget … | sh` in script arrays |
| **Stays quiet when** | No pipe-to-shell |
| **Public examples** | Same pattern as npm/GHA script injection classes |
| **Remediation** | Download, verify checksum, then execute |

### `gitlab-ci.rules-always-on-main-secrets`

| | |
| --- | --- |
| **What** | Deploy job with secrets has `rules: - when: always` or wide branch match |
| **Why** | Secrets run on unexpected refs |
| **Looks for** | Jobs named deploy/release/publish with broad rules and environment credentials |
| **Stays quiet when** | Rules restrict to protected branches/tags |
| **Public examples** | GitLab environments + protected branches model |
| **Remediation** | Gate deploys on protected refs and manual approval where needed |

### `gitlab-ci.include-remote-unpinned`

| | |
| --- | --- |
| **What** | `include:` pulls CI config from mutable sources |
| **Why** | The pipeline definition itself becomes mutable third-party code — same class as unpinned GitHub Actions |
| **Looks for** | `include: remote:` http(s) URLs; `include: project:` without `ref:` (tracks the other project’s default branch) |
| **Stays quiet when** | `include: local`; project includes pinned with `ref:` to a SHA or protected tag; GitLab-maintained templates (note, don’t fire) |
| **Public examples** | GitLab `include:` docs; CI supply-chain guidance on pinning shared pipeline definitions |
| **Remediation** | Pin `ref:` to a commit SHA or protected tag; vendor remote includes into the repo |

---

## Medium

### `gitlab-ci.interruptible-release`

| | |
| --- | --- |
| **What** | A branch or scheduled publish/deploy/release job is explicitly interruptible or inherits `default: interruptible: true` |
| **Why** | With redundant-pipeline cancellation enabled, a newer pipeline on the same ref can stop release work before publication completes |
| **Looks for** | Release-like job names or stages with job-level `interruptible: true`, or the same-file top-level default set to true |
| **Stays quiet when** | The job is explicitly non-interruptible; the release is tag-only; auto-cancel on new commits is disabled; or no interruptible setting applies |
| **Public example** | [GitLab `interruptible` documentation](https://docs.gitlab.com/ci/yaml/#interruptible); [Substrate PR 13088](https://github.com/paritytech/substrate/pull/13088), merged after an observed scheduled publishing pipeline cancellation |
| **Remediation** | Make the release job and its required path non-interruptible, or isolate release pipelines under non-interruptible defaults |

---

### `gitlab-ci.allow-failure`

| | |
| --- | --- |
| **What** | Critical jobs set `allow_failure: true` |
| **Why** | Security/test gates become cosmetic |
| **Looks for** | `allow_failure: true` on jobs whose name/stage matches `test`, `lint`, `security`, `sast`, `secret`, `build` (required path) |
| **Stays quiet when** | allow_failure on clearly optional jobs (`notify`, `coverage-report`, experimental) |
| **Public examples** | CI hygiene; “green main” while tests fail |
| **Remediation** | Keep tests and security scans hard-failing |

### `gitlab-ci.script-yaml-injection-ci-commit`

| | |
| --- | --- |
| **What** | Untrusted CI variables reach code-execution or argument positions |
| **Why** | In `script`, `$VAR` is shell parameter expansion — data, not code — so echoing a branch name is *not* command injection (do not overclaim; this differs from GHA template interpolation). Real risk: `eval`, `sh -c "$VAR"`, command substitution over variables, or unquoted expansion in argument position (a branch named `--force` becomes a flag) |
| **Looks for** | `eval` / `sh -c` / backtick or `$( )` substitution over `$CI_COMMIT_REF_NAME`, `$CI_COMMIT_MESSAGE`, `$CI_MERGE_REQUEST_TITLE`; unquoted expansions of those vars in command argument position |
| **Stays quiet when** | Quoted expansions used as plain data (`echo "$CI_COMMIT_REF_NAME"`); no eval / `sh -c` |
| **Public examples** | CI script injection literature; GitLab variable expansion footguns |
| **Remediation** | Quote expansions; avoid eval; prefer structured args |

### `gitlab-ci.cache-key-too-broad`

| | |
| --- | --- |
| **What** | Cache key ignores lockfiles (constant key) for dependency caches |
| **Why** | Stale, non-hermetic dependency caches. GitLab separates caches between protected and unprotected refs by default, so cross-trust poisoning is limited — frame as staleness/reproducibility, poisoning only within the same protection tier |
| **Looks for** | `cache:key:` static string while caching `node_modules`/`vendor`/`.cache` |
| **Stays quiet when** | Key includes lockfile checksum files |
| **Public examples** | CI cache poisoning discussions |
| **Remediation** | Include lockfile hashes in cache keys |

---

## Out of scope

| Concern | Owner |
| --- | --- |
| GitHub Actions workflows | `ci/github-actions` |
| Depot workflows | `ci/depot` |
| Dockerfile content | `container/dockerfile` |
| Generic secret literals in repo | `security/secrets` |
