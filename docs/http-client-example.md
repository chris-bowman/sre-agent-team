# HTTP Consumer Example

This example uses a same-tenant managed identity to call the Platform Escalation Service over its versioned HTTP API. It is suitable for a generic service or agent consumer; it does not require the workload SRE reference implementation.

## Prerequisites

1. The caller service principal has the `EscalationCaller` app role on the proxy Entra application.
2. The platform operator has registered the caller and one or more workload-owned `allowed_resource_groups` in Azure App Configuration.
3. The caller can reach the proxy HTTPS endpoint.

## Python

```python
import time
import uuid

import requests
from azure.identity import DefaultAzureCredential

proxy_base_url = "https://<proxy-hostname>"
proxy_application_client_id = "<proxy-application-client-id>"

credential = DefaultAzureCredential()
token = credential.get_token(f"api://{proxy_application_client_id}/.default")
headers = {
    "Authorization": f"Bearer {token.token}",
    "Idempotency-Key": str(uuid.uuid4()),
}

creation = requests.post(
    f"{proxy_base_url}/api/v1/investigations",
    headers=headers,
    json={
        "description": "The shared API is unreachable from the caller workload.",
        "caller_label": "example-consumer",
        "resource_group_id": "/subscriptions/<subscription-id>/resourceGroups/<workload-resource-group>",
        "severity": "high",
        "context": "Connection failures began after the latest network deployment.",
    },
    timeout=30,
)
creation.raise_for_status()
investigation = creation.json()

while investigation["status"] not in {"completed", "failed", "expired"}:
    time.sleep(investigation["poll_after_seconds"])
    status = requests.get(
        f"{proxy_base_url}/api/v1/investigations/{investigation['investigation_id']}",
        headers={"Authorization": f"Bearer {token.token}"},
        timeout=120,
    )
    status.raise_for_status()
    investigation = status.json()

if investigation["status"] == "completed":
    findings = requests.get(
        f"{proxy_base_url}/api/v1/investigations/{investigation['investigation_id']}/findings",
        headers={"Authorization": f"Bearer {token.token}"},
        timeout=30,
    )
    findings.raise_for_status()
    print(findings.json()["findings"])
```

## Error Handling

The versioned API returns `application/problem+json` errors. Use the stable `code`, `retryable`, and optional `retry_after_seconds` fields to decide whether to retry. Do not parse internal error text or depend on Platform SRE Agent thread IDs; they are intentionally not exposed.