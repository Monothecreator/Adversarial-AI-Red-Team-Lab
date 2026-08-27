# Security Policy

This project is a controlled AI security testing lab. It intentionally evaluates adversarial prompts and safety controls in a sandboxed environment.

## Scope

- Only simulated or synthetic secrets and mock tools are used.
- No production credentials, personal data, or privileged environments should be connected.
- Do not run adversarial tests against external systems without explicit authorization.

## Responsible use

- Keep all testing in isolated local or Dockerized environments.
- Use synthetic secrets such as `TEST_SECRET_12345`.
- Restrict tool access and output publication in the lab environment.

## Reporting a vulnerability

If you identify a real issue in the project infrastructure or a security control implementation, please report it privately via GitHub Security Advisories or by contacting the repository maintainer.
