# gitlab-ci

**gitlab-ci** reviews GitLab CI/CD configs for **privileged runners, secret leakage in scripts, mutable images, Docker socket use, and unpinned includes**.

It is a **CI security reviewer** for `.gitlab-ci.yml`, not a general YAML linter. When it reports, pipelines can take over runners or exfiltrate variables.

## What it does

1. **Discovers** GitLab CI config files.
2. **Runs deterministic detectors** for privileged mode, secrets in scripts, images, and includes.
3. **Synthesizes a review** with file:line evidence.
4. Optionally **enhances** with a model when provided.

It never executes the scanned project as the product under review, never installs dependencies into it, and never needs network access to the target repository.

## What it detects

Every **shipped rule id**, severity, and short description lives in **[CHECKS.md](CHECKS.md)**.

Highlights:

| Area | Examples |
| --- | --- |
| Runner | privileged: true; docker.sock references |
| Secrets | echo of $CI_JOB_TOKEN / *PASSWORD* vars |
| Supply chain | image:*:latest; remote includes |
| Gates | allow_failure on test jobs |

### Ownership boundaries

| Concern | Owned by |
| --- | --- |
| GitHub Actions | [`ci/github-actions`](https://github.com/adversarylabs/githubactions-adversary) |
| Depot CI | [`ci/depot`](https://github.com/adversarylabs/depotci-adversary) |
| Dockerfile content | [`container/dockerfile`](https://github.com/adversarylabs/dockerfile-adversary) |

## Precision stance

- **High confidence** only for deterministic, evidence-backed patterns.
- Clean fixtures must stay quiet; vulnerable fixtures must fire.
- Prefer missing a weak signal over a false positive on normal production code.
