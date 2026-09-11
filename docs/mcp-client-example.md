# MCP Consumer Example

This example connects a generic same-tenant agent or service to the Platform Escalation Service using MCP Streamable HTTP. The proxy exposes only three investigation tools:

- `create_platform_investigation`
- `get_investigation_status`
- `get_investigation_summary`

## Prerequisites

1. The caller service principal has the `EscalationCaller` application role.
2. The platform operator has registered the caller and one or more workload-owned `allowed_resource_groups` in Azure App Configuration.
3. The caller can acquire an Entra access token for `api://<proxy-client-id>/.default`.

## Python

```python
import asyncio

from azure.identity import DefaultAzureCredential
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

proxy_url = "https://<proxy-hostname>/mcp"
proxy_application_client_id = "<proxy-application-client-id>"


async def investigate() -> None:
    credential = DefaultAzureCredential()
    token = credential.get_token(f"api://{proxy_application_client_id}/.default")
    headers = {
        "Authorization": f"Bearer {token.token}",
        "Accept": "application/json, text/event-stream",
    }

    async with streamablehttp_client(proxy_url, headers=headers) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            print([tool.name for tool in tools.tools])

            result = await session.call_tool(
                "create_platform_investigation",
                {
                    "description": "The caller cannot resolve the shared API private endpoint.",
                    "caller_label": "example-consumer",
                    "resource_group_id": "/subscriptions/<subscription-id>/resourceGroups/<workload-resource-group>",
                    "severity": "high",
                    "context": "The issue began after a network deployment.",
                },
            )
            print(result.content)


asyncio.run(investigate())
```

The proxy validates the caller token, application identity, and operator-owned resource-group scope on every MCP request. Callers must not depend on Platform SRE Agent thread IDs; the proxy returns opaque investigation IDs only. Platform-owned outcomes contain a handoff notice, not platform investigation detail. Existing v1 integrations may continue to send `workload_name` as a deprecated alias for `caller_label`.