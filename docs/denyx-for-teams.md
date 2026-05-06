# Denyx for Teams

> ← [Back to docs README](README.md)

Denyx works on a single laptop with a TOML file and zero
infrastructure — that's the default and it's the right shape for
the solo developer running Claude Code or opencode against their
own projects. But once a team has more than one person running
agents against shared codebases, three friction points show up:

1. **The policy file drifts.** Each developer ends up with a
   slightly different `denyx.toml`. Nobody's sure which version is
   "the" policy. New rules ship to one machine and not others.
2. **There's no single audit trail.** Each developer's agent
   writes its own JSONL log to their laptop. If you need to
   answer *"did anyone's agent read /etc/passwd this week?"*,
   you have to walk every machine.
3. **Compliance and security teams can't see what they need.**
   Policy reviews live as untracked TOML edits; audit reviews
   live as `tail -f` on a developer's terminal. Neither scales
   past a single person.

**Denyx for Teams** is the deployment shape that solves these
without abandoning the lightweight per-process model: one
**policy + audit server** that every Denyx-gated agent in the
organisation talks to.

## What changes when you deploy a server

The Denyx client (the `denyx` CLI, the `denyx-mcp` MCP server,
or any embedder of `denyx-host`) gains two configuration knobs:

| Environment variable | Purpose |
|----------------------|---------|
| `DENYX_POLICY_URL`   | URL to fetch the active policy from at startup. Replaces the local TOML file. |
| `DENYX_AUDIT_URL`    | URL to POST every audit event to. Replaces (or supplements) the local JSONL log. |
| `DENYX_AUTH_TOKEN`   | Bearer token sent on every request to either URL. Identifies the agent / machine / project to the server. |

Each is optional and independent. You can run with **only**
`DENYX_AUDIT_URL` set (centralised audit, local policy file), or
**only** `DENYX_POLICY_URL` set (centralised policy, local audit
log), or both, or neither. The default — neither set — is the
fully-local solo-developer shape.

The reserved-env-var invariant in `denyx-policy` makes
`DENYX_AUTH_TOKEN`, `DENYX_POLICY_URL`, and `DENYX_AUDIT_URL`
**unreadable by the agent itself**, even when a hostile policy
explicitly lists them in `allow_vars`. The runtime invariant
fires before allow_vars is consulted, so the bearer token never
ends up in the agent's hands.

## Philosophy

Denyx for Teams keeps the per-process semantics the standalone
shape gives you, and **adds** centralised coordination. It does
not turn Denyx into a multi-agent platform — Denyx still governs
one agent process at a time, and each agent's local
default-deny gate is still the thing that fires when a
capability is denied. The server's job is fleet-wide policy
management and audit aggregation, not real-time enforcement.

The architectural distinction matters because it preserves four
properties:

1. **The agent stays unprivileged.** A network-unreachable Denyx
   client still enforces the last-fetched policy correctly. The
   server going down does not allow the agent to escape.
2. **The policy is the contract, not a runtime decision.** The
   server hands the client a policy file once; the client
   enforces it locally. There is no "ask the server every call"
   round-trip on the hot path.
3. **Centralisation is opt-in per knob.** A team can centralise
   audit-only (lowest-friction adoption) and roll out
   centralised policy later without touching the client config
   beyond setting one env var.
4. **The protocol is small enough to write yourself.** Two HTTP
   endpoints, bearer auth, a TOML body and a JSON event body.
   Anyone can stand up a conforming server in an afternoon.

## What a basic Denyx-capable server has to do

A conforming server implements **two HTTP endpoints**. Both
authenticate the requesting client via a `Bearer` token (optional
in development; strongly recommended in production).

### 1. Serve a policy on demand — `GET /policy` (or whatever URL you choose)

```
GET https://denyx.example.com/policy/team-platform
Authorization: Bearer <token>
```

The server's response body is a Denyx policy TOML document — the
same schema documented in
[agent-policy-spec.md](agent-policy-spec.md). The simplest
possible response body is one line:

```toml
inherits = "secure-defaults"
```

That parses to a working default-deny policy with the
`secure-defaults` preset baked into the Denyx binary. Most
deployments will return something larger that adds project- or
team-specific allowlists on top.

The server defines its identity model: it can decide *which* policy
to serve based on the URL path, the bearer token's claims, the
client's source IP, or any combination. The protocol is silent on
this — pick whatever fits the deployment.

The client fetches once at startup. **Policy changes take effect
on the next client restart**, not live. (Live policy push is a v2
extension; not in v1.)

### 2. Receive audit events — `POST /audit` (or whatever URL you choose)

```
POST https://denyx.example.com/audit
Authorization: Bearer <token>
Content-Type: application/json

{
  "ts":         "2026-05-06T18:31:42.842Z",
  "task_id":    "denyx-mcp-9023",
  "step":       7,
  "capability": "fs.read",
  "status":     "allowed",
  "detail":     {"path": "src/main.rs", "error": null}
}
```

One event per HTTP request. The server stores it durably and
returns any `2xx` status. The body is the JSON serialisation of
Denyx's `AuditEvent` — six fields, schema documented in
[server-protocol.md](server-protocol.md).

The server should treat duplicate `(task_id, step)` POSTs as
idempotent — the client retries once on `5xx` or transport
errors, so duplicates are expected. Idempotency on the server
side prevents double-counting in the database.

If the server is unreachable or returns `5xx` twice in a row, the
Denyx client logs an `AUDIT GAP` to stderr and **continues
running**. The capability call has already been gated by the
local policy at this point; the audit POST is a record-keeping
side effect. This is a deliberate availability trade-off — agents
keep working when the audit server has problems — and operators
should monitor for `AUDIT GAP` lines in client stderr to detect
prolonged outages.

### What's optional, not required

A conforming server **only** needs those two endpoints. Anything
beyond that is optional and not part of v1:

- A web UI to view audit events.
- A policy editor.
- Per-team or per-project policy templates.
- Drift detection / anomaly alerts.
- An approval-broker that handles `requires_approval` elicitations
  out-of-band (Slack, email, Teams).
- Multi-tenant billing.
- Real-time policy push.
- HMAC body signing or mTLS.

These are valuable features for a polished product, but a
deployment can ship Denyx for Teams with **zero** of them and the
core value proposition (one policy across the team, one audit log
across the team) holds.

The full wire protocol — all status codes, all timeouts, all
edge cases — is specified in
[server-protocol.md](server-protocol.md).

## How a team rolls this out

The smoothest adoption path, in order:

### Stage 1: Standalone, per-developer

Each developer runs:

```sh
cargo install denyx-cli denyx-mcp
# ...paste the setup prompt from examples/denyx-setup-prompt.md
# into Claude Code or opencode, generate denyx.toml, wire it up.
```

Commit `denyx.toml` to the project repo. **This step is the entire
adoption gate**: once `denyx.toml` is in the repo, every
contributor who has run `cargo install denyx-mcp` picks up the
policy automatically.

The audit log is local-only at this stage. That's fine — it's
useful for the developer, just not yet aggregated.

### Stage 2: Centralised audit only

Stand up a minimal audit-receiving endpoint. The simplest shape
is an HTTP POST handler that writes events to a database
(Postgres, SQLite, ClickHouse — whatever the team already runs).
Twenty lines of code in any web framework.

Distribute one environment variable to every developer:

```sh
export DENYX_AUDIT_URL=https://denyx-audit.internal.example.com/v1/audit
export DENYX_AUTH_TOKEN=<per-developer-token>
```

(In practice, set these in `.envrc` / direnv / 1Password Shell
plugin / your secret-distribution tool of choice — not in
`.bashrc` checked into git.)

Now every gated capability call from every developer's agent
lands in the team's database. You can run queries like:

- *"Which developers' agents tried to read paths outside the
  project tree last week?"*
- *"How often does our API key get used?"*
- *"Has any agent denied a `subprocess.exec` for `rm -rf`?"*

This stage gives compliance and security teams visibility without
changing the developer experience.

### Stage 3: Centralised policy

Once audit aggregation is working, move the policy file to the
server. The same handler can also serve `GET /policy` returning
the canonical policy for the project / team / organisation.

Switch developers from local TOML to:

```sh
export DENYX_POLICY_URL=https://denyx-audit.internal.example.com/v1/policy
```

(Reuse the same auth token; the server can serve different
policies based on token scope.)

Now policy updates ship via the server, not by chasing every
developer to update their `denyx.toml`. Combine with a CI check
that the server's policy is what the team's review process
approved.

The local `denyx.toml` becomes optional at this stage; some
deployments keep it in the repo as a fallback for when the
server is unreachable, others delete it to force the
centralised-policy path.

### Stage 4: Whatever you want next

Once the audit data is in your database and the policy is
fetched from your server, you own the experience. Reasonable
next steps depending on what your team needs:

- **A simple web UI** — Grafana / Metabase against the audit
  table is enough to start. Custom dashboards come later.
- **Drift detection** — alert when a developer's agent triggers
  a denied capability for the first time.
- **Approval brokering** — when `requires_approval` fires on a
  developer's terminal-less CI agent, route the elicitation to
  a Slack channel where someone is available.
- **Per-project policy templates** — let teams pick from
  `python-web-service.toml`, `rust-cli-tool.toml`, etc., with
  shared baselines.
- **Compliance reporting** — generate "this team's agents touched
  these paths these many times in Q1" rollups for SOC 2 / ISO
  27001 audits.

None of these change the Denyx client. They're all server-side
features built on top of the audit data and policy authority.

## Where this fits in the larger picture

| Tier | Buyer | Setup | What's included |
|------|-------|-------|-----------------|
| **Solo** | Single developer running Claude Code locally | `cargo install`, write `denyx.toml` | Per-process gate, IFC, sandbox, local audit |
| **Team** *(this doc)* | Engineering team with N agents across projects | Same client install + `DENYX_POLICY_URL` / `DENYX_AUDIT_URL` against your server | All standalone features + central policy + aggregated audit + compliance reporting |
| **Multi-agent platform** | Multi-agent system with mesh, identity, SRE | A different platform | Multi-agent mesh, agent identity, inter-agent message gating |

Denyx for Teams covers the middle tier — many independent
single-agent processes, governed by one central policy and one
central audit log. It does **not** cover multi-agent coordination
(agent-to-agent identity, mesh routing, inter-agent message
authentication). For that, see the framework-side platforms;
Denyx is not trying to be one.

## Where to next

- [server-protocol.md](server-protocol.md) — the full HTTP wire
  spec for implementing a Denyx-capable server. Status codes,
  timeouts, error semantics, conformance test vectors.
- [agent-policy-spec.md](agent-policy-spec.md) — the TOML schema
  the policy endpoint must serve.
- [04-policy-file.md](04-policy-file.md) — a tutorial introduction
  to writing a Denyx policy. Read first if you've never seen
  one.
- [security-threat-model.md](security-threat-model.md) — what
  Denyx assumes about the network between client and server.
  Short version: HTTPS or a private VPC for production.
