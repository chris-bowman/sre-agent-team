# Contributing

Thank you for improving the Platform Escalation Service.

## Development workflow

1. Create a focused branch from `main`.
2. Keep public MCP and HTTP behavior compatible with `docs/service-contract-v1.md`.
3. Add or update tests for behavioral changes.
4. Run the local validation commands below.
5. Open a pull request describing the behavior, security impact, and validation evidence.

## Local validation

From `escalation-proxy/app`:

```powershell
python -m pytest -q
python -m ruff check .
python -m ruff format --check .
python -m mypy
```

From the repository root, compile every tracked Bicep and Bicep parameter file and parse every tracked PowerShell script. The same checks run in `.github/workflows/proxy-validation.yml`.

## Change expectations

- Preserve least-privilege identity and authorization boundaries.
- Never commit credentials, access tokens, signed URLs, caller-policy data, or deployment state.
- Pin runtime dependencies and deploy immutable image digests.
- Keep changes narrow; document operator-visible behavior and migration steps.
- Do not weaken private networking, tenant validation, app-role checks, caller policy, ownership checks, quotas, or output redaction.

## Reporting security issues

Do not open public issues for suspected vulnerabilities. Follow `SECURITY.md`.
