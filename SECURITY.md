# Security Policy

## Supported versions

Security fixes are applied to the current `main` branch and the latest `1.0.x` release.

## Reporting a vulnerability

Report suspected vulnerabilities privately through the repository host's private vulnerability-reporting or security-advisory feature. If that feature is unavailable, contact the repository maintainers through an established private organizational channel.

Do not include access tokens, credentials, customer data, signed URLs, platform thread IDs, or unredacted investigation findings in a report. Provide reproduction steps using synthetic data where possible.

Maintainers will acknowledge a report, assess severity and scope, coordinate remediation, and publish disclosure details after affected deployments can be updated. Response timing depends on severity and operational impact.

## Security boundary

The service accepts only same-tenant application identities with the `EscalationCaller` app role and an enabled operator-managed caller policy. The proxy is investigation-only and must not expose direct Platform SRE Agent administration or cross-caller investigation access.
