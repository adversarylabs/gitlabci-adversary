# Checks

| Rule | Severity | Scans for |
| --- | --- | --- |
| `gitlab-ci.allow-failure` | Medium | Critical jobs set `allow_failure: true` |
| `gitlab-ci.curl-pipe-bash` | High | Script pipes remote content to shell |
| `gitlab-ci.dind-socket-mount` | High | Mounts Docker socket into job |
| `gitlab-ci.include-remote-unpinned` | High | `include:` pulls CI config from mutable sources |
| `gitlab-ci.interruptible-release` | Medium | A branch or scheduled publish/deploy/release job is explicitly interruptible or inherits `default: interruptible: true` from its GitLab configuration |
| `gitlab-ci.mutable-image` | High | Job or service image uses floating tags (`latest` or unpinned) |
| `gitlab-ci.privileged` | Critical | Job or runner config enables Docker privileged mode |
| `gitlab-ci.script-yaml-injection-ci-commit` | Medium | Untrusted CI variables reach code-execution or argument positions |
| `gitlab-ci.secret-in-script-echo` | Critical | Job script echoes or prints CI variables that look like secrets |
