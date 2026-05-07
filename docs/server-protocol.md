# Denyx server protocol v1

> ← [Back to docs README](README.md)

This document specifies the HTTP protocol that a **Denyx
policy + audit server** must implement so a Denyx client (the
`denyx-mcp` server, the `denyx` CLI, or any embedder of
`denyx-host`) can fetch a policy at startup and POST audit events
on every effecting capability call.

The protocol is deliberately small. There are exactly **two
endpoints** — one for policy fetch, one for audit POST — both over
plain HTTP with optional bearer auth. There is no SDK, no gRPC, no
WebSocket. The simplicity is the point: anyone can stand up a
conforming server in an afternoon, in any language, and the same
deployment can serve hand-rolled, SaaS, and on-prem use cases.

## Status & versioning

This is **v1** of the server protocol. Versioning rules:

- **MAJOR (v1 → v2)** when an incompatible change to the wire
  format ships (a new required header, a renamed audit-event
  field, a different auth scheme).
- **MINOR (v1.0 → v1.1)** when a backwards-compatible extension
  ships (a new optional header, a new optional audit-event field).
- The server protocol is versioned **independently** of the Denyx
  implementation crates and the [agent-policy spec](agent-policy-spec.md).

The current Denyx client implementation (`denyx-mcp` 0.1) speaks
**v1** of this protocol.

## What you're building

A Denyx server has two responsibilities:

1. **Serve a policy file** (the same TOML schema documented in
   [agent-policy-spec.md](agent-policy-spec.md)) on demand to
   authenticated clients.
2. **Receive audit events** describing every gate decision the
   client made, and persist them somewhere durable.

Anything else — a UI, a policy editor, drift detection, anomaly
alerts, role-based-access-control over who can edit policies, an
approval broker — is **out of scope** for this protocol. A
conforming server is just an HTTP server with two endpoints; what
it does behind those endpoints is the server author's choice.

## Client behaviour summary

Before reading the per-endpoint detail, the shape of what the
Denyx client does in production:

```
denyx-mcp startup:
  if DENYX_POLICY_URL is set:
    GET <DENYX_POLICY_URL>  with Authorization: Bearer <DENYX_AUTH_TOKEN>
    expect 2xx with TOML body
    parse, resolve inheritance, validate
    use as the active policy

denyx-mcp every effecting capability call:
  if DENYX_AUDIT_URL is set:
    POST <DENYX_AUDIT_URL>  with Authorization: Bearer <DENYX_AUTH_TOKEN>
                            Content-Type: application/json
                            body = {ts, task_id, step, capability, status, detail}
    expect 2xx (success), 4xx (permanent failure, no retry),
           5xx or transport error (retry once)
    if both attempts fail: log "AUDIT GAP" to stderr, continue
```

Both URLs and the auth token come from environment variables — the
Denyx client never accepts them on the command line, so they
cannot end up in shell history or in MCP-config JSON visible to
the agent. The reserved-env-var invariant in `denyx-policy` makes
`DENYX_AUTH_TOKEN` and the URL variables unreadable by the agent
itself, even when a hostile policy lists them in `allow_vars`.

## Authentication

A single mechanism: **HTTP Bearer auth in the `Authorization`
header**.

```
Authorization: Bearer <token>
```

The token is opaque to Denyx. The server defines its semantics —
it might be:

- A long-lived static API key per machine,
- A short-lived JWT that the operator's identity provider issues,
- A workload-identity token (e.g. SPIFFE SVID) wrapped as a
  bearer string.

**The token must be sent on every request to both endpoints**,
not just the policy fetch. The server is free to reject either
endpoint independently with `401 Unauthorized` (token missing /
malformed) or `403 Forbidden` (token valid but lacks the
permission to fetch this policy / submit audit for this scope).

### Auth is required for any non-trivial deployment

The protocol does not *technically* enforce that the server
validate the token — a server that ignores the `Authorization`
header is still wire-conformant. But in practice, **bearer auth
must be validated** for any deployment where:

- The token is the identity carrier for audit ingest (see
  [Event identity](#event-identity--who-emitted-this-event)) —
  without validation, anyone on the network can forge events
  with any token they choose, and the audit trail becomes
  meaningless.
- The server hosts more than one policy and uses the token to
  decide which one to serve (Pattern 2 in the
  [routing model](#which-policy-to-serve--the-servers-routing-model))
  — without validation, anyone can request any policy by
  guessing its token, exposing tighter or looser rule sets.
- The audit endpoint stores anything that an attacker would care
  about — operational telemetry, filesystem paths, URLs the
  agent visits — which is to say, any audit endpoint that's
  worth querying later.

**The narrow exceptions** where skipping the auth check is
defensible:

- **Localhost-loopback dev fixtures.** A `127.0.0.1` server
  listening on a loopback interface, used only for the local
  developer's own testing.
- **Air-gapped private VPCs** where every potential client is
  already authenticated at the network layer (e.g. mutually-TLS-
  authenticated workload identities at an ingress sidecar that
  unwraps before reaching the Denyx server).

In every other shape — corporate networks, the public internet,
shared dev environments, anything reachable from a co-worker's
laptop — **validating the bearer token is required**, not
optional. Treat the protocol's permissiveness as a backwards-
compatibility hatch for trivial setups, not a license to skip
auth in production.

There is no other auth mechanism in v1. No mTLS-encoded identity
in the cert, no signed-request body, no HMAC. If the deployment
needs those, they belong in front of the Denyx server (a sidecar,
an API gateway, or an envoy filter) — not in this protocol.

## Endpoint 1: policy fetch

### Request

```
GET <DENYX_POLICY_URL>
Authorization: Bearer <token>     (optional)
Accept: */*                        (the client doesn't filter)
User-Agent: ureq/2.x               (or whatever the client library
                                    sends — informational, not
                                    load-bearing)
```

The URL is whatever the operator configured. The client passes no
query parameters, no path parameters, and no request body. **The
URL itself is the identity of "which policy to serve."** If a
server wants to serve different policies to different machines /
projects / teams, it must encode that distinction in either:

- **Different URLs per consumer** (so each agent's
  `DENYX_POLICY_URL` points at a unique endpoint), or
- **Bearer-token scope** (the server maps the token to a policy),
  or
- A combination of both.

The protocol is silent on which approach the server uses; it just
defines the wire format.

### Response — success

```
HTTP/1.1 200 OK
Content-Type: text/plain          (or application/toml — client
                                    does not validate this header)
Content-Length: ...

inherits = "secure-defaults"

[filesystem]
read_allow  = ["src/**", "tests/**"]
...
```

The body **must be a valid Denyx policy TOML document** as defined
in [agent-policy-spec.md](agent-policy-spec.md). The client:

1. Reads the body as a UTF-8 string.
2. Parses it with the Denyx TOML loader.
3. Resolves any `inherits = "..."` preset reference (the
   resolution is client-side; presets are baked into the Denyx
   binary, so the server never needs to know about them).
4. Validates the merged result.
5. Uses the result as the active policy for the lifetime of the
   client process.

Any `200`-class status is treated as success. The client does not
validate the response `Content-Type`; sending `text/plain`,
`application/toml`, or `application/x-toml` are all fine.

**The body must not be empty.** An empty TOML document is a valid
TOML expression (it parses to an empty policy), but a default-deny
policy with no rules is almost never what the operator intended.
The client refuses to start when the body is empty, with the
error: *"policy fetch from `<url>` returned an empty body. An
empty TOML parses to a default-deny policy, which is almost
certainly not what the operator intended. Refusing to start."*

### Which policy to serve — the server's routing model

Mirroring the audit-event identity question: when 50 developers
all run `denyx-mcp` with the same `DENYX_POLICY_URL`, how does the
server decide which TOML to send back?

**v1 protocol: the server decides, using URL + bearer token in
whatever combination it likes.** The Denyx client passes no query
parameters, no path parameters, no body, no agent-id header — just
`GET <url>` with optional `Bearer <token>`. So the server has
exactly two information sources for routing:

1. The URL the client hit (host, path, query string).
2. The bearer token in the `Authorization` header.

Four practical patterns, in rough order of operational simplicity:

#### Pattern 1 — One URL, one policy, one token for everyone

`https://denyx.example.com/policy` returns the same TOML to
every caller. The token (if any) is purely for access control —
"is this request allowed to fetch the org policy at all?" —
not for routing.

**Use when:** one global policy applies to everyone in the org;
the only enforcement-level distinction is "Denyx-gated
or not." Smallest deployments. Maximally simple server.

#### Pattern 2 — One URL, per-consumer token (server-side token-to-policy mapping)

Every client hits the same `https://denyx.example.com/policy`
endpoint, but each developer / machine / project gets a unique
bearer token. The server's database maps `token → policy_id`
and serves the matching TOML.

**Use when:** different consumers need different policies (a
junior dev gets a tighter policy than a senior dev; CI gets
tighter than human; per-team baselines). The token is already
per-consumer for audit-identity reasons (see audit endpoint
above), so reusing it for policy routing is "free" — no new
infrastructure.

This is the natural shape for most production deployments and
the symmetric counterpart to the audit-identity pattern. Same
token database powers both endpoints.

#### Pattern 3 — Per-consumer URL (URL itself is the routing key)

Each developer / machine / project gets its own
`DENYX_POLICY_URL` pointing at a unique endpoint:
`https://denyx.example.com/policies/team-platform/dev-machine-42`.
The server maps URL paths to policies (often as a static file
tree behind a CDN); the token is just for access control.

**Use when:** the server is intentionally dumb (a static-file
webserver, a CDN, an S3 bucket with signed URLs). No
policy-routing logic on the server side; the URL distribution
mechanism is what does the routing.

**Trade-off:** URLs proliferate. If you have 50 developers, you
have 50 `DENYX_POLICY_URL` values to distribute. Combine with
direnv / 1Password Shell plugin / your existing
secret-distribution tool to keep this manageable.

#### Pattern 4 — Hybrid (URL = scope, token = instance)

`https://denyx.example.com/policies/<team>` keeps a per-team
scope at the URL level; the bearer token within that team
identifies the specific developer / machine. Server combines
both signals.

**Use when:** you want clean separation between *what kind of
policy you get* (URL = team) and *who you are* (token =
identity). Audit traces are clearer because the URL alone tells
you the policy version's lineage.

### A note on the symmetry with audit

Both endpoints work the same way: **client passes a URL and an
optional bearer token; server decides what to do with them**. The
audit-identity discussion above maps directly onto policy
routing — the same token database that resolves
`token → user@example.com` for audit can also resolve
`token → policy_for_dev_machines.toml` for policy fetch.

Most production deployments use Pattern 2 for both endpoints with
the same token database backing both. That's the "Denyx for
Teams" sweet spot: one token per consumer, one server, two
endpoints, both routed by the same auth context.

### Response — error

| Status | Client behaviour | When the server should use it |
|--------|------------------|-------------------------------|
| `2xx` | Parse body as policy TOML | Normal success |
| `301`, `302`, `307`, `308` | **Treated as failure** | Don't redirect. The client disables auto-redirect. A redirect from a corp-policy URL is a configuration error, not a feature. If you need to relocate the endpoint, change `DENYX_POLICY_URL` on the client. |
| `400` | Failure with body shown to operator | Malformed request (missing required header, etc.) |
| `401` | Failure with body shown to operator | Bearer token missing or malformed |
| `403` | Failure with body shown to operator | Bearer token valid but unauthorised for this policy |
| `404` | Failure with body shown to operator | No policy assigned to this token / URL combination |
| `5xx` | Failure with body shown to operator | Server error |
| `429` | Failure (no automatic retry) | Rate-limited |
| transport error (DNS, TCP, TLS) | Failure | Network unreachable |

The client emits an actionable error message that includes the
URL, the status code, and the first 200 characters of the response
body. Servers should put a human-readable explanation in the body
(plain text or JSON, whichever — the client just shows it). For
example:

```
HTTP/1.1 403 Forbidden
Content-Type: text/plain

Token is valid but is not authorised to fetch policies for project
'staging'. Contact your Denyx administrator at security@example.com.
```

The client does not retry on policy-fetch failures. A failed
fetch at startup is fatal — the client exits with a non-zero
status and the operator is expected to fix the configuration and
restart.

### Timeout

The client uses a **5-second total timeout** (connect + send +
receive + body read). A server that consistently takes longer
than 5 seconds to serve a small TOML file is misbehaving and
operators will notice.

### Caching

There is no client-side caching of policy responses in v1. Every
client startup performs a fresh fetch. The server may set HTTP
cache headers; the client ignores them.

If the server wants to push policy updates to a long-running
client, that requires a v2 extension (e.g. a streaming endpoint
or a webhook). Not in v1.

## Endpoint 2: audit POST

### Request

```
POST <DENYX_AUDIT_URL>
Authorization: Bearer <token>     (optional, same token as policy)
Content-Type: application/json
Content-Length: ...

{
  "ts":         "2026-05-06T18:31:42.842Z",
  "task_id":    "denyx-mcp-9023",
  "step":       7,
  "capability": "fs.read",
  "status":     "allowed",
  "detail":     {
    "path":  "/home/dev/projects/foo/src/main.rs",
    "error": null
  }
}
```

One event per HTTP request. No batching in v1; every gate decision
fires its own POST.

### Audit-event schema

The body is the JSON serialisation of the `AuditEvent` Rust
struct in `crates/host/src/audit.rs`. Field-by-field:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `ts` | string (RFC 3339 / ISO 8601 with `Z` suffix) | yes | Wall-clock time of the gate decision, in UTC |
| `task_id` | string | yes | Caller-supplied identifier for the agent task. The CLI uses one ID per script run; `denyx-mcp` uses one ID per JSON-RPC `tools/call`. Never empty. |
| `step` | unsigned integer | yes | Monotonic step counter within `task_id`. Starts at 0. The first effecting capability call in a task is `step=0`, the second is `step=1`, etc. |
| `capability` | string | yes | Name of the gated capability. One of: `fs.read`, `fs.write`, `fs.delete`, `subprocess.exec`, `net.http_get`, `net.http_post`, `net.http_put`, `net.http_patch`, `net.http_delete`, `env.read`, plus any additional capabilities a future Denyx version registers. |
| `status` | string enum | yes | One of `"allowed"`, `"denied"`, `"errored"`. Snake-case. Servers should treat any other value as a forward-compat unknown and store it without rejecting the event. |
| `detail` | object | yes | Capability-specific structured detail. Free-form JSON object. The shape depends on `capability` (see below). May be empty `{}` if there's no detail to record. |

**Forward-compatibility note**: future Denyx versions may add new
top-level fields to `AuditEvent`. Servers should accept and store
unknown fields rather than reject the event. The client never
removes a field that's already in v1 without a v2 protocol bump.

### Event identity — who emitted this event?

**v1 protocol: the bearer token is the only identity carrier.**

Look at the audit-event schema above and you'll notice what's
*not* there: no `agent_id`, no `machine_id`, no `user`, no
`hostname`. The Denyx client does not stamp a per-event identity
into the event body. The fields are pure descriptions of *what
the agent tried to do*, not *who was running the agent*.

This is a deliberate design choice with explicit consequences for
server implementers. **The server is responsible for joining the
event to an identity at ingest time**, using the bearer token as
the join key. Practical patterns:

1. **One bearer token per machine** (or per developer / per CI
   project). The server's token database maps each token to a
   structured identity record (`user@example.com`, `host=laptop-42`,
   `team=platform`, etc.). At ingest, the server looks up the
   token's identity and writes a denormalised row to the audit
   table:

   ```
   audit_events: (ts, task_id, step, capability, status, detail,
                  user_email, machine_id, team)
   ```

   Most production deployments will use this pattern. It's the
   simplest, the auth and the identity stay in one place.

2. **JWT bearer token with claims.** The token itself is a signed
   JWT. The server validates the signature, extracts the claims
   (`sub`, `email`, `iss`, custom claims for team / project / etc.),
   and uses those without needing a separate database lookup.
   Cleaner for organisations that already issue JWTs from an IdP.

3. **Workload identity** (SPIFFE SVID, GCP service-account token,
   Kubernetes ServiceAccount JWT). The bearer is whatever the
   workload identity system issues; the server validates against
   the identity provider. Right shape for CI agents and headless
   services where there's no human user.

In all three patterns, the **identity is decided by the server**,
not by the client. The Denyx client is a dumb event emitter; it
cannot lie about its identity even in principle, because it
doesn't know its own identity in the first place — the only
self-description it has is whatever the operator put in
`DENYX_AUTH_TOKEN`.

#### Why no `agent_id` field in the event?

Three reasons the v1 spec doesn't include a per-event identity
field:

1. **Bearer-token identity is already in the request.** Adding a
   field to the body would duplicate information the HTTP layer
   already carries, and create the risk of the two disagreeing
   (a malicious client putting a different `agent_id` than its
   token is bound to).
2. **Server-side enrichment is more flexible.** A client-stamped
   `agent_id` becomes load-bearing for the rest of time. Letting
   the server derive identity from the token means the server
   can change identity scoping (per-machine to per-user,
   per-project to per-team, etc.) without coordinating a wire
   change.
3. **Local audit logs don't need it.** The default deployment
   writes JSONL to disk on the same machine as the agent. There's
   no identity question — the file IS the per-machine record.
   Adding identity fields just to satisfy the centralised case
   is overhead the standalone case doesn't need.

#### v2 candidate: optional client-stamped identity

A future v2 protocol extension could add an optional top-level
`agent_id` (or `client_id`) field that the client populates from
an env var (`DENYX_AGENT_ID` or similar). This would make the
event body self-describing for use cases where the server can't
or doesn't want to do token-to-identity mapping (forensic
ingest, multi-tenant log services, etc.). It is **not in v1**;
servers built today should plan for token-based mapping.

If you need client-stamped identity *today* without waiting for
v2: a simple proxy in front of the audit endpoint can inject the
identity into the event body based on the request's bearer
token. Decorate-then-store is a common ingest pattern and works
with any v1-conforming Denyx client unchanged.

### Capability-specific `detail` shape

The `detail` object is structured per-capability. Current shapes:

#### `fs.read` / `fs.write` / `fs.delete`

```json
{
  "path":  "/absolute/or/relative/path/to/file",
  "error": null     // or a string describing the policy violation
}
```

#### `subprocess.exec`

```json
{
  "argv":  ["git", "status", "--short"],
  "error": null
}
```

#### `net.http_get` / `net.http_post` / `net.http_put` / `net.http_patch` / `net.http_delete`

```json
{
  "url":   "https://api.github.com/repos/owner/name",
  "error": null
}
```

#### `env.read`

```json
{
  "var":   "PATH",
  "error": null
}
```

The `error` field is `null` when `status == "allowed"`, and a
human-readable string explaining the denial when `status ==
"denied"` or `"errored"`. Servers MUST NOT rely on a specific
error-string format; the wording can change between Denyx
versions.

### Response — success

```
HTTP/1.1 204 No Content
```

or

```
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 2

{}
```

Any `2xx` status is treated as success. The response body is
**ignored** by the client. Servers that want to log the event ID
back to the client can return `200 OK` with a JSON body, but the
client throws it away.

### Response — error

| Status | Client behaviour | When the server should use it |
|--------|------------------|-------------------------------|
| `2xx` | Success — done | Event accepted |
| `4xx` (any) | **No retry.** Logs `AUDIT GAP` to stderr and continues. | Permanent client error: missing/invalid token, malformed event, scope/quota exhausted, etc. Retrying won't fix it. |
| `5xx` (any) | Retry once after no delay; if the second attempt also fails, logs `AUDIT GAP` to stderr and continues. | Transient server error (overload, maintenance, downstream outage). |
| Transport error (DNS, TCP, TLS) | Retry once; if the second attempt also fails, logs `AUDIT GAP` to stderr and continues. | Network failure. |

This is the **most important behavioural property of the
protocol**: an audit POST failure does NOT block the underlying
capability call. The capability has already been gated by the
local policy at this point; the audit POST is a record-keeping
side effect. If the audit server is down, the agent continues to
work — but with a documented audit gap that the server can
detect by `task_id` / `step` discontinuities in its database.

If a deployment wants stricter behaviour ("refuse the call when
audit is unavailable"), that's a v2 extension. The current Denyx
client documents the audit-gap behaviour honestly and operators
can set up monitoring on the stderr stream to detect prolonged
outages.

### Timeout

The client uses a **2-second total timeout per attempt** (connect
+ send + receive). With one retry, the worst-case impact on a
single capability call is ~4 seconds plus DNS. The 2-second
budget is intentionally tight: every gated call in the agent's
script blocks waiting for the audit POST, so a slow audit server
adds linear cost to every operation.

### Idempotency

The `(task_id, step)` pair uniquely identifies an audit event.
**Servers should treat duplicate `(task_id, step)` POSTs as
idempotent**: deduplicate them, or accept the duplicate
silently. The client's retry-once policy on 5xx and transport
errors means a server that processes an event but fails to
respond will see the same event again. Idempotency on the server
side prevents double-counting.

### Ordering

Events arrive in `(task_id, step)` order **per task**. Across
tasks, ordering is not guaranteed: events from `task_id=A,
step=0` and `task_id=B, step=0` may arrive in either order,
because tasks run on independent timelines.

Within a task, events are emitted serially in step order. The
client does not buffer or batch events.

### Hash chain (informational)

When the client uses a local `JsonlAuditSink` (writing to a JSONL
file on disk), each event is augmented with two extra fields —
`denyx_seq` (a monotonic counter) and `denyx_prev_hash` (the
SHA-256 of the previous line) — that form a tamper-detectable
chain.

**These fields are NOT sent over the audit POST in v1.** The
local-file chain and the HTTP audit stream are independent
mechanisms; the HTTP audit endpoint receives the bare
`AuditEvent` only. A v2 extension might add chain fields to the
HTTP body for end-to-end tamper detection. Out of scope today.

## TLS / transport

In production deployments, **HTTPS is strongly recommended**:

- The bearer token is exposed in cleartext otherwise.
- Audit events contain operationally sensitive content
  (filesystem paths, URLs, command argvs).
- Policy responses are TOML — readable for everyone on the wire.

The client supports HTTP and HTTPS URLs equivalently (same auth,
same body parsing). Local-development and on-prem-private-network
deployments can use plain HTTP; the protocol does not enforce TLS.

The client uses a stock `ureq` agent with TLS via either rustls
or native-tls (depends on the build feature). System CA roots
are trusted by default; servers presenting a corporate-CA
certificate are accepted as long as the corp CA is in the system
trust store. Self-signed certificates require `webpki-roots` /
custom-CA configuration that's not exposed in the v1 client; for
testing, use HTTP.

## Operator's reference: minimum conforming server

The smallest server that implements this spec, **with bearer-token
validation**, is below. **This code has been run end-to-end
against the v0.1 `denyx-mcp` client** — `denyx-mcp` fetches the
policy from `/policy`, resolves the `secure-defaults` preset,
and initialises successfully; unauthenticated requests are
rejected with `401`; valid audit POSTs return `204`.

```python
#!/usr/bin/env python3
"""Minimal Denyx-conformant policy + audit server, with bearer-auth.

Pseudo-Python; not production-ready. Illustrates the wire protocol
with bearer-auth validation. Real production servers should:
  - replace the in-memory token + policy with a database
  - back the audit handler with durable storage
  - serve over TLS via a reverse proxy (nginx, Caddy, ingress sidecar)
  - add request logging and metrics
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import secrets

# Auth: the single bearer token this server accepts. In production
# this is a database lookup keyed on the token (or on a JWT
# subject); here it's one constant for the simplest possible
# example.
EXPECTED_TOKEN = "dev-laptop-token-abc123"

# The policy this server returns to any successfully-authenticated
# request. In production the server typically returns a different
# policy per token / per team / per project (see the "Which policy
# to serve" section above for the routing patterns); a minimal
# example serves the same policy to anyone who authenticates.
POLICY_TOML = """\
inherits = "secure-defaults"

[filesystem]
read_allow  = ["src/**"]
write_allow = ["/tmp/**"]
"""


def is_authorised(headers):
    """True if the Authorization header carries the expected
    bearer token. Uses constant-time comparison to avoid
    timing-oracle attacks on the equality check."""
    auth = headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return False
    presented = auth[len("Bearer "):].strip()
    return secrets.compare_digest(presented, EXPECTED_TOKEN)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/policy":
            self.send_error(404)
            return
        if not is_authorised(self.headers):
            self.send_error(401, "Bearer token missing or invalid")
            return
        body = POLICY_TOML.encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/toml")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/audit":
            self.send_error(404)
            return
        if not is_authorised(self.headers):
            self.send_error(401, "Bearer token missing or invalid")
            return
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            event = json.loads(body)
        except json.JSONDecodeError:
            self.send_error(400, "audit body must be valid JSON")
            return
        print(f"AUDIT: {event['capability']} {event['status']} "
              f"task={event['task_id']} step={event['step']}")
        self.send_response(204)
        self.end_headers()


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 8765), Handler).serve_forever()
```

Save as `denyx_example_server.py`, run it
(`python3 denyx_example_server.py`), then point a Denyx client at
it:

```sh
DENYX_POLICY_URL=http://127.0.0.1:8765/policy \
DENYX_AUDIT_URL=http://127.0.0.1:8765/audit \
DENYX_AUTH_TOKEN=dev-laptop-token-abc123 \
denyx-mcp --confirm-mode auto
```

Or hit it directly with `curl` to test each path:

```sh
# Should 401 (no auth):
curl -i http://127.0.0.1:8765/policy

# Should 200 + TOML body:
curl -i -H "Authorization: Bearer dev-laptop-token-abc123" \
     http://127.0.0.1:8765/policy

# Should 204:
curl -i -H "Authorization: Bearer dev-laptop-token-abc123" \
        -H "Content-Type: application/json" \
        -d '{"ts":"2026-05-06T18:31:42.842Z","task_id":"t-1",
             "step":0,"capability":"fs.read","status":"allowed",
             "detail":{"path":"src/main.rs","error":null}}' \
     http://127.0.0.1:8765/audit
```

> **Note:** this example serves over plain HTTP and binds to
> `127.0.0.1` (localhost only) for clarity. For any production
> deployment that's reachable beyond localhost, terminate TLS in
> front of this server (nginx / Caddy / an ingress sidecar) — the
> bearer token in the `Authorization` header is sent in cleartext
> on HTTP and anyone on the network path can capture and replay
> it. See the [TLS / transport](#tls--transport) section.

## Conformance test vectors

A v1-conforming server must accept all of the following audit-POST
bodies (capability detail shape is *not* normative — these are
illustrative fixtures showing the field types):

```json
{
  "ts": "2026-05-06T18:31:42.842Z",
  "task_id": "t-1",
  "step": 0,
  "capability": "fs.read",
  "status": "allowed",
  "detail": {"path": "src/main.rs", "error": null}
}
```

```json
{
  "ts": "2026-05-06T18:31:43.001Z",
  "task_id": "t-1",
  "step": 1,
  "capability": "subprocess.exec",
  "status": "denied",
  "detail": {"argv": ["rm", "-rf", "/"], "error": "command 'rm' not in allow_commands"}
}
```

```json
{
  "ts": "2026-05-06T18:31:43.124Z",
  "task_id": "t-1",
  "step": 2,
  "capability": "net.http_get",
  "status": "errored",
  "detail": {"url": "https://malicious.example/", "error": "host not in http_get_allow"}
}
```

A v1-conforming server must serve any valid Denyx-spec TOML in
response to a policy-fetch GET. The simplest valid response body:

```toml
inherits = "secure-defaults"
```

That is one line, parses correctly, resolves the secure-defaults
preset, and produces a working policy.

## Out of scope (v1)

Things this spec deliberately does not cover. Each is a
candidate for a future v2 extension or for parallel
specifications:

- **Streaming policy push.** v1 is fetch-on-startup only. Live
  revocation requires a long-lived connection.
- **Audit batching.** One event per POST. High-volume deployments
  may want a `POST /audit/batch` shape.
- **Event acknowledgement IDs.** The client doesn't surface the
  server's response body; idempotency keys today are
  `(task_id, step)` only.
- **Hash-chain transport.** The local JSONL chain is not
  reflected on the wire.
- **Schema discovery / capability negotiation.** Clients and
  servers commit to v1 by configuration; there is no `OPTIONS`
  endpoint or version handshake.
- **mTLS, signed bodies, HMAC.** Bearer tokens only.
- **Approval brokering.** When a `requires_approval` capability
  fires and there's no human at the agent's terminal, routing
  the elicitation to Slack / email / Teams is not part of the
  policy/audit server protocol. That's a separate service.

## Related documents

- [agent-policy-spec.md](agent-policy-spec.md) — the TOML schema
  the policy-fetch endpoint must serve.
- [03-architecture.md](03-architecture.md) — how the client fits
  the policy and audit responses into its runtime.
- [04-security-threat-model.md](04-security-threat-model.md) — what
  Denyx assumes about the network between the client and the
  server (TL;DR: the network is hostile; HTTPS or a private VPC
  is required for production).
