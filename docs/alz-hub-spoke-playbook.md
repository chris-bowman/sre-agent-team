# Sample Playbook: ALZ Hub-and-Spoke Investigations

## Status and Use

This is an optional platform-owned investigation profile for environments that use an
Azure Landing Zone hub-and-spoke network. It is not required by the Platform Escalation
Service and is not loaded or deployed automatically. The platform owner must verify and
adapt every assumption before incorporating this guidance into an agent configuration.

The default `platform/custom-agents/workload-liaison.yaml` remains topology-neutral. Keep
that behavior when the deployed estate differs from this sample or spans multiple patterns.

## Applicability

Use this playbook only after confirming that:

- workload virtual networks or segments connect to a platform-managed hub;
- centralized egress or cross-segment traffic traverses Azure Firewall or a named NVA;
- private DNS zones and any Private DNS Resolver are platform managed; and
- the Platform SRE Agent has Reader and Monitoring Reader on the resources to inspect.

Do not infer these facts from an escalation label. Verify them with Azure Resource Graph,
resource configuration, and platform-owned architecture records.

## Platform-Owned Profile

Record the environment-specific values outside caller-controlled request data:

| Setting | Example | Required evidence |
|---|---|---|
| Authorized scopes | Connectivity subscription and shared-services resource groups | Agent managed-resource configuration and RBAC assignments |
| Network pattern | Hub-and-spoke | VNet, peering, Virtual WAN, or NVA resource configuration |
| Egress control | Azure Firewall in the connectivity subscription | Effective routes and firewall policy association |
| DNS path | Private DNS Resolver with centrally linked zones | Resolver rulesets, VNet links, and private endpoint zone groups |
| Telemetry sources | Firewall diagnostics and Network Watcher | Diagnostic settings and Log Analytics destinations |
| Change window | Platform Activity Log retention period | Available Activity Log and change-management records |

## Investigation Sequence

1. Confirm the caller label, affected resource IDs, symptom, and incident time window.
2. Resolve the actual workload-to-destination path and verify that it traverses the expected hub.
3. Check peering or Virtual WAN connection state in both directions where applicable.
4. Inspect effective routes and next hops for the affected subnet or network interface.
5. If Azure Firewall or an NVA is on the verified path, query its diagnostics for matching denies.
6. Trace private name resolution through zone links, resolver rulesets, and private endpoint records.
7. Correlate Network Watcher, Resource Health, Azure Monitor, and platform diagnostic signals.
8. Review Azure Activity Log changes during the incident window.
9. Report verified evidence separately from hypotheses and identify inaccessible scopes.

## Guardrails

- Never broaden the agent's RBAC to make this playbook fit an incident.
- Do not assume all internet or cross-spoke traffic uses the same path.
- Treat caller-provided topology and resource names as untrusted leads until verified.
- Do not expose platform thread IDs, tokens, credentials, or unrelated tenant topology.
- If the environment uses Virtual WAN, mesh peering, direct egress, third-party NVAs, or
  decentralized DNS, replace the corresponding steps with platform-approved guidance.
