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

## Policy and audit: how to choose

Denyx supports several deployment shapes, and the right one
depends on the trust model, the size of the team, and how much
infrastructure the team is willing to run. This section lays out
the realistic options for **policy distribution** and **audit
destination** independently — they're orthogonal knobs and you
can mix any combination.

### Policy distribution

Where does the active policy come from?

#### Option A — TOML committed to the project's git repo (default)

Each developer runs Denyx with a `denyx.toml` that lives in the
project's repo. `cargo install denyx-cli denyx-mcp`; clone the
repo; the policy is right there.

| Pros | Cons |
|------|------|
| **Zero infrastructure.** No server, no network dependency at startup, works on a plane. | **Can be modified locally without anyone noticing.** A developer can `vim denyx.toml`, save changes, and run their agent against the modified policy. The repo's `main` is unchanged but the local enforcement is. |
| **Version-controlled and code-reviewed.** Policy changes go through PR. `git blame` shows who changed what and why. | **Drift across machines.** If a contributor doesn't `git pull`, their agent enforces yesterday's policy. Whether that's "good" depends on whether yesterday's policy was tighter or looser. |
| **Transparent.** Anyone reading the codebase sees the policy. New contributors don't need a separate access grant. | **No org-wide policy.** Each project carries its own TOML. If your security team has rules that apply across all projects, they have to be replicated in each repo. |
| **Works offline.** | **No central enforcement that all developers run *the* policy.** A determined developer can delete the file and run with no policy. (The Denyx CLI exits without one; the MCP server exits unless `--policy` resolves.) |

**When to use:** small teams, single-project agents, projects where
the policy author and the agent operator are the same person or
team. The default for OSS projects shipping a `denyx.toml`
alongside their code.

**The honest framing**: committing `denyx.toml` to the repo is
**convention-as-enforcement**. It's the same pattern as
`.editorconfig`, `pyproject.toml`'s `[tool.ruff]` block, or any
other in-repo config — culturally enforced, technically optional.
That's enough for a lot of teams. It is *not* enough for a team
that needs to demonstrate to a compliance reviewer that *every*
agent run was gated by a specific approved policy version.

#### Option B — Centralised policy server (`DENYX_POLICY_URL`)

The Denyx client fetches the policy from an HTTP endpoint at
startup. The TOML in the repo is either deleted or kept as a
fallback / local-dev convenience.

| Pros | Cons |
|------|------|
| **Single source of truth.** Update the server, every agent picks up the new policy on next restart. No chasing developers to `git pull`. | **Requires infrastructure.** A server, an auth token distribution mechanism, monitoring. The server going down means new agents can't start (the client refuses to start without a policy). |
| **Cross-project / cross-team consistency.** The server can decide what policy each token / project / machine gets. Security can enforce one set of baseline rules across the entire org. | **Network dependency at startup.** `cargo install denyx-cli && denyx-mcp` no longer works on a plane. Local-only dev needs a local fallback path or a mocked server. |
| **Per-machine / per-project differentiation.** A senior dev's agent can have a more permissive policy than a junior dev's; CI agents can have a tighter one than human-driven sessions. The server decides. | **Bearer-token management.** Rotating tokens, revoking access on offboarding, scoping permissions — all become operations the team has to run. |
| **Compliance story.** "Every agent run on date X used policy version Y" is a server-side query, not a forensic walk across laptops. | **Latency.** A 5-second startup dependency the standalone shape doesn't have. Usually fine; visible if the server is on another continent. |

**When to use:** organisations with central security/compliance
review of policies; teams where developers shouldn't be able to
self-modify the active policy; deployments at scale where pushing
TOML changes across N developers is a coordination tax.

**The honest framing**: this gives you **mandatory, server-enforced
policy** — at the cost of running a server. The server is
deliberately small (two HTTP endpoints) and you can stand it up in
an afternoon, but it is real infrastructure with real
operational cost.

> **Routing note.** Just like the audit-identity case below, the
> client passes the URL and the bearer token to the server and
> nothing else. **The server decides which policy to return** by
> looking at the URL, the token, or both. Four practical patterns:
> *(1)* one URL + one token = one global policy for everyone;
> *(2)* one URL + per-consumer token, server maps token → policy
> in its database (most production deployments); *(3)* per-consumer
> URL where the path itself is the routing key (good when the
> server is a CDN or static-file host); *(4)* hybrid — URL =
> team scope, token = individual within the team. Most teams
> picking centralised policy *and* centralised audit use the same
> token database to resolve both. Full discussion in
> [server-protocol.md](server-protocol.md#which-policy-to-serve--the-servers-routing-model).

#### Option C — Hybrid: server with in-repo fallback

Both the in-repo TOML *and* a `DENYX_POLICY_URL` are configured.
The Denyx client uses the URL when reachable; if the URL is
unset (or the server is unreachable), it falls back to the local
file.

> **Note:** the current Denyx client (`denyx-mcp` 0.1) does
> **not** auto-fall-back from URL to local on a fetch failure — a
> failed fetch is fatal and the client exits. The hybrid shape is
> achieved by *unsetting* `DENYX_POLICY_URL` (e.g. via a
> direnv-controlled env var that's only set on the corporate
> network), so the client uses the local file when offline. A
> first-class fall-back-on-error mode is on the v2 list for the
> server protocol.

| Pros | Cons |
|------|------|
| **Resilience to server outage.** Developers can keep working when the policy server is down. | **Two policies to maintain.** The in-repo file can drift from what the server serves. |
| **Local-dev experience preserved.** Working offline / on a plane just works. | **Reduced compliance guarantee.** "Every agent run used the canonical policy" is no longer true if developers ran with the local fallback. |
| **Smooth migration path.** Teams adopting the server can keep the in-repo file during the transition. | **More configuration to get right.** Which env vars are set when, and on which machines, matters. |

**When to use:** during migration from in-repo to centralised,
or for teams that want centralised policy as a *default* but
explicitly tolerate the local-fallback case for offline /
emergency work.

### Audit destination

Where do gate decisions get recorded?

#### Option A — Local JSONL file only (default)

Each Denyx-gated agent writes to a JSONL log on the machine where
it runs. The audit file is hash-chained: SHA-256 of each line
embedded in the next one's `denyx_prev_hash` field, so any
tampering is detectable on later verification.

| Pros | Cons |
|------|------|
| **Zero infrastructure.** | **Scattered.** Each developer has their own log. "What did all our agents do this week?" is N separate file-walks. |
| **Tamper-detectable.** The hash chain catches insertions, deletions, and modifications. `denyx audit verify` reports mismatches. | **Local resilience only.** A developer can delete the file. Hash chain detects the deletion; doesn't recover the data. |
| **Full history retained** (subject to disk space). | **Hard to query.** JSONL is a stream, not a database. Filtering across many machines requires shipping the data first. |
| **No network round-trip.** Audit POST never delays a capability call. | **No real-time visibility.** Compliance / security can't see what's happening today without manually pulling the logs. |

**When to use:** solo developer; small team where the audit log is
"useful when something goes wrong" rather than a primary security
control; environments where shipping logs off the machine is
itself a compliance issue.

#### Option B — Centralised HTTP POST (`DENYX_AUDIT_URL`)

Every audit event POSTs to the configured URL. The server stores
events in whatever backend the team runs (Postgres, ClickHouse,
S3-as-JSONL, a SIEM, etc.).

| Pros | Cons |
|------|------|
| **Real-time aggregation.** Compliance / security teams can run "what's happening right now" queries. | **Network dependency on the hot path.** Each gated capability call blocks for up to ~4 seconds (2s timeout + 1 retry) on the audit POST. Slow audit server = slow agent. |
| **Org-wide visibility.** "Has any agent denied a `subprocess.exec` of `rm -rf /` this week?" is one SQL query. | **AUDIT GAP on persistent failure.** Two failed POSTs in a row produce a stderr `AUDIT GAP` line and the client continues without retrying that event. The capability call has already been gated locally; the missing record is a record-keeping gap, not a security bypass. Operators must monitor for AUDIT GAP lines. |
| **Compliance-ready.** Auditable, exportable, retained per the team's data-retention policy. | **Server outage during a long-running session means missing events.** The client doesn't buffer; events that fail to POST are dropped (with the AUDIT GAP log). |
| **Centralised retention policy.** "Keep audit data for 7 years" is configured once on the server, not per machine. | **Bearer-token management** (same auth concerns as the policy server). |

**When to use:** teams that need real-time compliance visibility;
deployments where the audit log feeds an existing SIEM or alerting
pipeline; orgs that need to demonstrate "every agent action was
recorded centrally."

> **Identity note.** The event body itself does not contain
> `user`, `machine_id`, or `agent_id` fields — the bearer token
> in the HTTP `Authorization` header is the only identity carrier
> in v1 of the server protocol. The server is responsible for
> joining the event to an identity at ingest, typically by
> issuing one bearer token per machine / developer / CI project
> and looking up the mapping in its token database. JWTs with
> claims, workload-identity tokens (SPIFFE / GCP / K8s SA), and
> proxy-injected `X-User` headers are all valid implementation
> choices. Full discussion in
> [server-protocol.md](server-protocol.md#event-identity--who-emitted-this-event).

#### Option C — Local JSONL + log shipping (filebeat / vector / fluentd)

Each Denyx-gated agent writes to a local JSONL file (Option A).
A separate log-shipping process (filebeat, vector, fluentd, the
team's existing log pipeline) tails the file and forwards events
to a central system.

| Pros | Cons |
|------|------|
| **Local resilience.** The local hash-chained file survives server outages; the shipper retries when the central system comes back. | **Lag.** Events show up in the central store seconds-to-minutes after the gate decision, not immediately. |
| **Decouples Denyx from the audit transport.** If the team already runs vector / a SIEM agent, no new infrastructure needed — just point the shipper at the JSONL file. | **Two moving parts** instead of one. Shipper failures are silent unless monitored separately. |
| **No hot-path network round-trip.** Capability calls don't wait for any network. | **Hash chain doesn't transit.** The central store gets the bare events; tamper detection lives only on the local file. |
| **Standard tooling.** Most security teams already have a log-shipping story. | **Doesn't catch local-file deletion.** The shipper has whatever the file had at last tail; if the user deletes the file, the shipper just sees EOF. |

**When to use:** teams that already operate a log pipeline;
environments where blocking on a network POST per capability call
is unacceptable (high-frequency agents); deployments that want
centralised audit *eventually* but not synchronously.

#### Option D — Local JSONL + HTTP POST (both)

Both `DENYX_AUDIT_URL` is set *and* the local JSONL file path is
configured (`--audit-log /var/log/denyx/audit.jsonl`). Every event
goes to both places.

| Pros | Cons |
|------|------|
| **Belt-and-braces.** If the central server fails, the local file still has everything. If the user tampers with the local file, the central server still has the canonical record. | **Hot-path latency stacks.** Each capability call blocks for the audit POST AND the local-file write (the latter is fast; the former is the binding cost). |
| **Tamper detection on two sides.** Hash chain on local file + server-side `(task_id, step)` continuity check. | **Two retention policies to manage.** When does the local file get rotated? When does the server's data get aged out? Misalignment causes "we have it on the server but not locally" investigations. |

**When to use:** high-stakes deployments where both local and
central records are required by policy (some regulated
industries); pre-production hardening where you want maximum
forensic data while you tune the system.

### Pick a combination

The two axes are independent. A team might run:

| Policy | Audit | Profile |
|--------|-------|---------|
| In-repo TOML (Option A) | Local JSONL only (Option A) | **Solo / small OSS team.** Zero infra. The default Denyx experience. |
| In-repo TOML | Local JSONL + log shipping (Option C) | **Small org, existing log pipeline.** Convention-enforced policy + centralised audit-eventually. |
| Centralised server (Option B) | Centralised HTTP POST (Option B) | **Compliance-driven org.** Mandatory policy + real-time audit. The "Denyx for Teams" sweet spot. |
| Centralised server | Local JSONL + log shipping | **Compliance-driven org with high-frequency agents.** Mandatory policy + decoupled audit (no hot-path latency). |
| Hybrid (Option C) | Both: local JSONL + HTTP POST (Option D) | **Belt-and-braces.** Resilient policy fallback + dual audit records. Highest operational overhead; highest forensic completeness. |
| Centralised server | Local JSONL only | **Mandatory policy, no central audit yet.** Useful migration intermediate state — get the policy story sorted, then add audit aggregation later. |

The "right" choice is whichever one matches the team's threat
model and operational appetite. Denyx doesn't take a position on
which is best; it tries to make all of them feasible without
forcing infrastructure that some deployments don't need.

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

There are two equivalent ways to wire developers' machines.

**Option A (recommended): bake the URL into the project's MCP
config via `denyx host-config --audit-url`**, so the audit
endpoint is part of the committed `.mcp.json` / `opencode.json`
and contributors don't have to remember to set anything:

```sh
denyx host-config \
    --policy ./denyx.toml \
    --host both \
    --audit-url https://denyx-audit.internal.example.com/v1/audit \
    --existing replace
```

Then distribute only the auth token via direnv / 1Password Shell
plugin / your secret-distribution tool of choice:

```sh
export DENYX_AUTH_TOKEN=<per-developer-token>
```

**Option B: use environment variables for everything.** If the
audit URL changes per-developer or per-deployment and you don't
want it in git, leave the host-config in local-audit mode and
override at runtime:

```sh
export DENYX_AUDIT_URL=https://denyx-audit.internal.example.com/v1/audit
export DENYX_AUTH_TOKEN=<per-developer-token>
```

(The env var wins over the flag, so this works on top of any
host-config output.)

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

Same two-option pattern as Stage 2.

**Option A (recommended): bake the URL into the project config**
so the team endpoint is part of git history and contributors
inherit it on clone:

```sh
denyx host-config \
    --policy ./denyx.toml \
    --host both \
    --policy-url https://denyx-audit.internal.example.com/v1/policy \
    --audit-url https://denyx-audit.internal.example.com/v1/audit \
    --existing replace
```

Note the `--policy ./denyx.toml` flag is still required even
though the runtime fetches the URL — host-config reads the local
file once to derive the OS-sandbox `allowedDomains` / `allowWrite`
stanza in `.claude/settings.json`. Keep the local TOML in sync
with the server policy (or generate it from the server) and
re-run host-config when the policy changes a host or write path.

**Option B: env-var override** for setups where the URL must vary
per developer / per machine:

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
- [06-policy-file.md](06-policy-file.md) — a tutorial introduction
  to writing a Denyx policy. Read first if you've never seen
  one.
- [04-security-threat-model.md](04-security-threat-model.md) — what
  Denyx assumes about the network between client and server.
  Short version: HTTPS or a private VPC for production.
