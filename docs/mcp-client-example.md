# MCP Consumer Example

This example connects a generic same-tenant agent or service to the Platform Escalation Service using MCP Streamable HTTP. The proxy exposes only three investigation tools:

- `create_platform_investigation`
- `get_investigation_status`
- `get_investigation_summary`

## Prerequisites

1. The caller service principal has the `EscalationCaller` application role.
2. The caller is registered in `CALLER_POLICIES_JSON` when policy configuration is enabled.
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
                    "workload_name": "example-consumer",
                    "severity": "high",
                    "context": "The issue began after a network deployment.",
                },
            )
            print(result.content)


asyncio.run(investigate())
```

The proxy validates the caller token and application identity on every MCP request. Callers must not depend on Platform SRE Agent thread IDs; the proxy returns opaque investigation IDs only.