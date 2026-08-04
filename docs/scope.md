# ci/gitlab-ci — mission and scope

Source of truth for what this adversary is *for*.

- **Package:** `gitlabci`
- **Factory routing:** human PR comments are attributed to this adversary only when they match **In scope**.
- **Languages / surfaces:** GitLab CI

## Mission

Review GitLab CI for privileged runners, secret leakage, mutable images, and unpinned includes.

## In scope (fair miss if humans raised it and we did not)

- Privileged runners
- Secret leakage in CI
- Mutable images / unpinned includes

## Out of scope (not a miss for this adversary)

- GitHub Actions (other package)
- App code logic

## Factory grading rule

- **In scope + human raised it + this adversary did not surface it** → real miss → suggested issue for **this** package
- **Out of scope** → do not grade as a miss for this adversary
- **Better fit for another adversary** → route there; do not double-count as a miss here
- **Unclear** → prefer out-of-scope for grading
