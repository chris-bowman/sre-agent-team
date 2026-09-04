# ADR 003: Azure Table Registry Backend

## Status

Accepted with production prerequisites

## Decision

Azure Table Storage is the first production investigation registry. Memory storage is local-development only and is constrained to one replica.

## Consequences

- Table mode must use private networking in policy-restricted environments.
- Table admission must evolve to a distributed atomic counter transaction before multi-replica production use.
- Investigation IDs remain opaque and platform thread IDs remain internal registry data.