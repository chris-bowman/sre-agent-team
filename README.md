# Platform Escalation Service for Azure SRE Agents

## Why this exists

Production incidents rarely respect team boundaries. A workload team may own its
application while separate platform, networking, identity, security, and operations
teams own the shared services it depends on. When an issue crosses those boundaries,
engineers can lose critical time finding the right team, transferring context, repeating
diagnostics, and requesting access to systems they should not permanently control.

Giving every team broad access would speed up some investigations, but it would weaken
segregation of duties, least privilege, and centralized governance. Keeping access tightly
separated is safer, but without a defined collaboration path it can make incident response
slow and stressful.

This project addresses that gap with a federated, multi-agent SRE model. Workload teams
retain autonomous, scoped investigation through their own Azure SRE Agents, while the
platform team retains control of its privileged agent and shared infrastructure. When an
incident appears to cross an ownership boundary, an approved agent or external system can
securely escalate the investigation to the platform team without receiving direct platform
access.

## What this project provides

This repository delivers a reusable Platform Escalation Service for Azure SRE Agents.
It exposes a narrow investigation-only MCP and HTTP boundary to approved same-tenant
application identities while the privileged Platform SRE Agent remains platform-admin owned.

The workload SRE Agent included here is a reference consumer that demonstrates the
escalation flow. It is optional: other agents and services can use the public contracts
without deploying the workload example.

For production, the recommended topology is separate platform and workload subscriptions,
with platform read access assigned at management-group scope. For test or lab scenarios,
you can deploy both agents into a single subscription and keep the separation at the
resource-group and RBAC level instead.

## Service Architecture

```
Approved Caller → [Platform Escalation Service] → Platform SRE Agent
                    (MCP + HTTP,                    (platform scope,
                     3 investigation tools,          admin-only)
                     same-tenant Entra auth)

Reference consumer: Workload SRE Agent → Platform Escalation Service
```

See [docs/service-contract-v1.md](docs/service-contract-v1.md) for supported transports,
schemas, and error behavior. See [docs/architecture.md](docs/architecture.md) for full diagrams
and RBAC tables. Production DNS, egress, monitoring, and recovery guidance is in
[docs/operations.md](docs/operations.md). Platform owners using an ALZ hub-and-spoke network
can adapt the optional [sample investigation playbook](docs/alz-hub-spoke-playbook.md).

Contributions are governed by [CONTRIBUTING.md](CONTRIBUTING.md),
[SECURITY.md](SECURITY.md), and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
The project is licensed under the [MIT License](LICENSE), and notable changes are recorded in
[CHANGELOG.md](CHANGELOG.md).

---

## Documentation

Start with the **[deployment guide](docs/deployment.md)** for prerequisites, identity
bootstrap, deployment workflows, caller onboarding, script parameters, and validation.

- [Architecture and RBAC](docs/architecture.md)
- [Service contract](docs/service-contract-v1.md)
- [Operations and recovery](docs/operations.md)
- [Threat model](docs/threat-model.md)
- [Detailed specification](docs/detailed-spec.md)
- [Contribution guide](CONTRIBUTING.md)

## Security and operating model

The platform team owns the privileged Platform SRE Agent and escalation service. Approved
same-tenant callers receive only the `EscalationCaller` app role and an enabled caller
policy; they do not receive direct platform access. Workload agents retain access only to
their approved Azure scopes, and platform investigations remain narrow and read-oriented.

Production deployments should separate platform and workload subscriptions, assign access
through authorized enterprise governance processes, and use the monitoring, private
networking, and recovery guidance in the deployment and operations documents. Lab
deployments may share a subscription while retaining clear resource-group and RBAC
boundaries.

## Repository structure

```
modules/           Reusable Bicep modules
platform/          Platform SRE Agent + custom agents
escalation-proxy/  Python FastMCP proxy + Container App infra
workload/          Workload SRE Agent template + custom agents
scripts/           Deployment PowerShell scripts
docs/              Architecture documentation
```
