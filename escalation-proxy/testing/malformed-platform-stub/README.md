# Malformed platform stub

Disposable test double for the Platform SRE Agent threads API, used only to close the
P13.3 malformed-findings staging gap in [docs/plan.md](../../docs/plan.md).

It implements just `POST /api/v1/threads`, `GET /api/v1/threads/{id}`, and
`GET /api/v1/threads/{id}/messages`, always returning a completed thread whose only
message is a final report missing the required `### Verdict` section. Point a
proxy revision's `PLATFORM_AGENT_ENDPOINT` at a deployed instance of this stub to
prove the proxy returns a safe `502 invalid_platform_response` with no report
content, then revert the endpoint and delete the stub deployment. It does not
validate the `Authorization` header and must never be pointed at by anything
other than a temporary, isolated staging revision.
