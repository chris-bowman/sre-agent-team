# ADR 004: Caller Resource Scope and Platform Disclosure

## Status

Accepted

## Decision

Each caller policy contains one or more canonical workload resource-group IDs. Every investigation names exactly one allowlisted group. The proxy denies an unapproved group before creating or reading a Platform SRE Agent thread.

The Platform SRE Agent retains Reader and Monitoring Reader only on platform-owned scope and normally has no workload-resource assignment. The caller resource group guides ownership and correlation; it does not dynamically change the platform agent's Azure RBAC.

Detailed model-generated findings remain in the platform-owned thread. The proxy validates the final report and verdict, then returns a fixed server-authored response for `PLATFORM ISSUE`, `APPLICATION ISSUE`, or `INCONCLUSIVE`. It never returns model-generated root cause, evidence, resource names, topology, or remediation text to callers.

## Consequences

- Caller evidence cannot select an unregistered workload resource group.
- Platform investigation detail remains available to platform operators without becoming caller-visible.
- A compromised or misclassified model report cannot smuggle platform text through an application verdict.
- Callers receive ownership and handoff guidance rather than detailed diagnostic findings.
- Organizations requiring per-caller platform-tool isolation need separate platform agents or a trusted tool broker; prompt text is not authorization.