# GitLab CI adversary

Reviews GitLab CI for privileged runners, secret leakage, mutable images, release safety, and unpinned includes.

## Goals

The adversary is designed to produce a small number of high-confidence,
actionable findings grounded in concrete repository evidence. Its review should
be deterministic where possible, explicit about impact, and quiet when the
available evidence does not justify a finding.

## Scope

It evaluates GitLab CI configuration, includes, jobs, scripts, runner privilege, secret exposure, caches, and release behavior.

The complete detector or review inventory is maintained in
[CHECKS.md](CHECKS.md).

## Boundaries

It owns CI configuration in this platform domain. Application code, container definitions, and infrastructure resources remain with their specialist adversaries.
