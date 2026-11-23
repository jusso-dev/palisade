# 0005. Agent-server protocol

- Status: accepted
- Date: 2026-11-23
- Deciders: Palisade maintainer

## Context

The agent (#4) talks to the server (#10) to check in, fetch policy and deltas, upload events and
inventory, and receive near-real-time nudges such as "policy available" or "rapid check-in".
Agents often sit behind corporate proxies, some of which break HTTP/2 or inspect TLS. All
agent-server traffic must use mutual TLS with a device certificate (#223). The wire types live in
`palisade-proto` ([ADR 0003](0003-crate-boundaries-and-dependency-direction.md)).

## Decision drivers

1. Mutual TLS with a device key that never leaves its key store (#223).
2. Works through restrictive proxies, including ones that break HTTP/2.
3. Efficient, diff-based policy delivery and batched event upload.
4. Offline queueing and replay, which happen on the agent whatever the transport.
5. Generated, typed clients for the agent, the CLI and the console.
6. A small, auditable dependency set in the privileged agent.

## Considered options

1. **gRPC over HTTP/2 (tonic).** Typed services from protobuf, server streaming for push,
   compact binary framing, and mTLS through rustls. Some proxies break HTTP/2 or gRPC
   trailers. Browsers need a separate API (the console uses REST, #15).
2. **HTTPS with JSON or CBOR, plus long-poll or WebSocket for push.** Works through almost any
   proxy and is easy to debug. But it is hand-written or OpenAPI-generated, has no
   service-level schema shared with the agent, and long-poll adds latency and server load.
3. **MQTT over TLS.** Good for push to many devices, but it needs a broker. Request/response
   and bulk transfer fit it poorly, and topic ACLs become a second authorisation system.

## Decision

Option 1, **gRPC over HTTP/2 with tonic and rustls**, as the primary transport, plus an
**HTTPS + JSON fallback** for check-in:

- `palisade-proto` defines the `AgentService` RPCs listed in #62. The server push channel
  (`StreamPush`) only carries nudges, never payloads. The agent then pulls through the normal
  RPCs.
- The fallback is used after 3 consecutive gRPC handshake failures. It carries the same protobuf
  messages, encoded as JSON (the standard protobuf JSON mapping), over HTTP/1.1. It covers
  check-in, policy fetch and event upload. Push falls back to polling at the check-in interval.
- Both paths use the same mTLS identity, the same server pinning, and the same signed payloads.
  Policy bundles and commands are signed end to end ([ADR 0008](0008-cryptographic-algorithms.md)),
  so their trust never depends on which transport delivered them.
- The console and external integrations use the REST API (#15). That is a separate surface,
  not an agent transport.

## Consequences

### Positive

- One schema (`.proto`) generates the agent, server and CLI types, and schema changes are
  reviewable in one place.
- Server streaming gives near-real-time nudges without a broker.
- The JSON fallback keeps agents manageable behind proxies that break HTTP/2.

### Negative

- Two encodings of the same messages must stay in step. Contract tests are needed for both.
- tonic and hyper add to the agent's dependency tree. That is accepted, but they are reviewed
  under the supply-chain policy (#23).
- TLS-inspecting proxies break mTLS by design. The docs must say the agent endpoints need an
  inspection bypass (#62). Palisade never disables verification to work around this.

## Security impact

mTLS with a non-exportable device key authenticates every agent, and server pinning defeats
interception, including by an inspecting proxy that presents its own CA. The fallback is not a
downgrade: it uses the same TLS and identity requirements, and the selection logic must never
fall back to plaintext or to unauthenticated TLS. Push messages carry no payloads, so a
compromised or spoofed push channel can at worst cause extra check-ins. Message parsers in
`palisade-proto` handle data from the network and are fuzz targets (#230).

## Links

- Issues #20, #62 (check-in and transport), #223 (enrolment and mTLS), #15 (REST API),
  #23 (supply chain), #230 (fuzzing). Epics #4, #10, #18.
