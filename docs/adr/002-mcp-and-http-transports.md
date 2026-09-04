# ADR 002: MCP and HTTP Transports

## Status

Accepted

## Decision

The service supports both official MCP Streamable HTTP at `/mcp` and the versioned asynchronous HTTP API under `/api/v1`.

## Consequences

- Agent frameworks can use MCP while service integrations can use HTTP.
- Both transports use the same authorization and investigation implementation.
- Existing HTTP routes and MCP tool names remain compatibility interfaces during v1.