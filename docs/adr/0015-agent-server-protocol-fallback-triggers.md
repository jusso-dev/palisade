# 0015. Agent-server protocol with protocol-failure fallback

- Status: accepted
- Date: 2026-11-23
- Deciders: Palisade maintainer

## Context

This ADR supersedes [ADR 0005](0005-agent-server-protocol.md). It keeps that decision (gRPC as
the primary transport, with an HTTPS + JSON fallback), but changes **when** the fallback is used.

ADR 0005 switched to the fallback only after 3 consecutive gRPC handshake failures. Some
proxies let the TLS and HTTP/2 handshake succeed and then break gRPC itself: they strip the
trailers that carry `grpc-status`, downgrade the response to HTTP/1.1, or reset streams. Every
RPC then fails, but no handshake does, so under ADR 0005 the agent never uses the fallback and
cannot check in at all. This is the case the fallback exists for (decision driver 2).

The rest of the context is unchanged. The agent (#4) talks to the server (#10) to check in,
fetch policy and deltas, upload events and inventory, and receive near-real-time nudges such as
"policy available" or "rapid check-in". Agents often sit behind corporate proxies, some of which
break HTTP/2 or inspect TLS. All agent-server traffic must use mutual TLS with a device
certificate (#223). The wire types live in `palisade-proto`
([ADR 0003](0003-crate-boundaries-and-dependency-direction.md)).

## Decision drivers

1. Mutual TLS with a device key that never leaves its key store (#223).
2. Works through restrictive proxies, including ones that break HTTP/2 or gRPC.
3. Efficient, diff-based policy delivery and batched event upload.
4. Offline queueing and replay, which happen on the agent whatever the transport.
5. Generated, typed clients for the agent, the CLI and the console.
6. A small, auditable dependency set in the privileged agent.

## Considered options

Transport (unchanged from ADR 0005):

1. **gRPC over HTTP/2 (tonic).** Typed services from protobuf, server streaming for push,
   compact binary framing, and mTLS through rustls. Some proxies break HTTP/2 or gRPC
   trailers. Browsers need a separate API (the console uses REST, #15).
2. **HTTPS with JSON or CBOR, plus long-poll or WebSocket for push.** Works through almost any
   proxy and is easy to debug. But it is hand-written or OpenAPI-generated, has no
   service-level schema shared with the agent, and long-poll adds latency and server load.
3. **MQTT over TLS.** Good for push to many devices, but it needs a broker. Request/response
   and bulk transfer fit it poorly, and topic ACLs become a second authorisation system.

Fallback trigger (new):

1. **Handshake failures only** (ADR 0005). Simple, but misses proxies that pass the handshake
   and then break gRPC framing, so the agent stays unmanaged behind them.
2. **Any RPC error.** Catches every proxy fault, but also fires on ordinary server answers such
   as `PERMISSION_DENIED` or `UNAVAILABLE` during a server restart. Agents would then leave gRPC
   for reasons the fallback cannot fix.
3. **Handshake failures plus gRPC protocol failures**, counted separately from errors the server
   itself returns. Catches the proxy case without reacting to valid server replies.

## Decision

Transport option 1, **gRPC over HTTP/2 with tonic and rustls**, as the primary transport, plus an
**HTTPS + JSON fallback** for check-in. Fallback trigger option 3.

- `palisade-proto` defines the `AgentService` RPCs listed in #62. The server push channel
  (`StreamPush`) only carries nudges, never payloads. The agent then pulls through the normal
  RPCs.
- **Fallback triggers.** The agent switches to the fallback after either:
  - 3 consecutive gRPC handshake failures (TCP connect, TLS or HTTP/2 negotiation); or
  - 3 consecutive RPCs that fail with a **gRPC protocol failure** after a successful handshake.
    A protocol failure is a response without a valid `grpc-status` (missing or stripped
    trailers), a response that is not HTTP/2 or not `application/grpc`, or an HTTP/2 stream
    reset or connection close before the call completes.

  A complete gRPC response with a non-OK `grpc-status` from the server (for example
  `PERMISSION_DENIED`, `INVALID_ARGUMENT` or `UNAVAILABLE`) is an application error, not a
  protocol failure. It does not count towards either trigger. Because the handshake and gRPC
  framing worked, it resets both counters, as does a success on either path. So the triggers
  only fire on failures that are truly consecutive.
- **TLS failures never trigger anything weaker.** A certificate, pinning or client-identity
  failure is a handshake failure. It may move the agent to the fallback, but the fallback
  applies the same checks and fails in the same way. No trigger relaxes TLS.
- **The fallback.** It carries the same protobuf messages, encoded as JSON (the standard
  protobuf JSON mapping), over HTTP/1.1. It covers check-in, policy fetch and event upload.
  Push falls back to polling at the check-in interval. While on the fallback, the agent retries
  gRPC at a bounded interval set in #62 and returns to it after one successful call.
- Both paths use the same mTLS identity, the same server pinning, and the same signed payloads.
  Policy bundles and commands are signed end to end ([ADR 0017](0017-cryptographic-algorithms-and-nonces.md)),
  so their trust never depends on which transport delivered them.
- The console and external integrations use the REST API (#15). That is a separate surface,
  not an agent transport.

## Consequences

### Positive

- One schema (`.proto`) generates the agent, server and CLI types, and schema changes are
  reviewable in one place.
- Server streaming gives near-real-time nudges without a broker.
- The JSON fallback keeps agents manageable behind proxies that break HTTP/2, including
  proxies that pass the handshake but break gRPC framing.

### Negative

- Two encodings of the same messages must stay in step. Contract tests are needed for both.
- The agent must classify failures (handshake, protocol, application), and #62 needs tests
  that simulate each kind, including a proxy that strips trailers.
- tonic and hyper add to the agent's dependency tree. That is accepted, but they are reviewed
  under the supply-chain policy (#23).
- TLS-inspecting proxies break mTLS by design. The docs must say the agent endpoints need an
  inspection bypass (#62). Palisade never disables verification to work around this.

## Security impact

mTLS with a non-exportable device key authenticates every agent, and server pinning defeats
interception, including by an inspecting proxy that presents its own CA. The fallback is not a
downgrade: it uses the same TLS and identity requirements, and the selection logic must never
fall back to plaintext or to unauthenticated TLS. An on-path attacker who breaks gRPC framing
can force the fallback. That costs only push latency (polling instead of nudges), because both
paths carry the same authenticated, signed messages. Push messages carry no payloads, so a
compromised or spoofed push channel can at worst cause extra check-ins. Message parsers in
`palisade-proto` handle data from the network and are fuzz targets (#230).

## Links

- Supersedes: 0005
- Issues #20, #62 (check-in and transport), #223 (enrolment and mTLS), #15 (REST API),
  #23 (supply chain), #230 (fuzzing). Epics #4, #10, #18.
- [ADR 0017](0017-cryptographic-algorithms-and-nonces.md) (signatures).
