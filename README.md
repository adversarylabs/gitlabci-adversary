# GitLab CI adversary

Reviews GitLab CI for privileged runners, mutable images, and ineffective gates.

## Checks

- **CI image uses a mutable tag:** Pin job and service images to digests or exact versions.
- **Job requests privileged container execution:** Use rootless builders or protected dedicated runners.
- **Required validation is allowed to fail:** Keep tests and security scans hard-failing.

## Development

```sh
npm ci
npm test
adversary validate .
adversary pack --check .
```
