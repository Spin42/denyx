# Agent Policy Spec

**Status:** Draft v1 — 2026-05-04

A portable, tool-agnostic format for declaring what an autonomous (or
semi-autonomous) coding agent is permitted to do in a given environment.

The spec is implementation-neutral. Aegis (this repository) is a
reference runtime that enforces it for Starlark agent scripts, but the
file format is intended to be consumable by any agentic system —
Claude Code, opencode, Cursor, Continue, Aider, custom CLI agents,
CI-hosted agents, in-house IDE plugins. If your tool already has some
notion of "tool permission" or "approval mode", this spec is an
upgrade path: replace the model-side prompt-and-pray with a declarative
policy file your runtime enforces.

The rest of this document covers:

- [Why a portable spec](#why-a-portable-spec)
- [Core principles](#core-principles)
- [The TOML schema](#the-toml-schema)
- [Enforcement semantics](#enforcement-semantics)
- [Implementer's guide](#implementers-guide-non-aegis-systems)
- [Reference policies](#reference-policies)
- [Compatibility and versioning](#compatibility-and-versioning)
- [Aegis as the reference implementation](#aegis-as-the-reference-implementation)

---

## Why a portable spec

Today's agentic coding tools sit in one of two modes:

1. **"Approve each command"** — the user confirms every shell call,
   network request, file write. Friction-heavy, fatigue-inducing, and
   the *runtime* (Claude Code, Cursor, opencode) decides what to
   surface. The model can construct commands that *look* innocuous but
   aren't, and the user clicks through anyway.
2. **"Auto / YOLO mode"** — everything runs unprompted. No safety. This
   is how production databases get deleted, credentials get exfiltrated,
   and `~/.aws/credentials` ends up rewritten with attacker-controlled
   keys.

Neither is a real authorization system. Both depend on the *agent host's
interpretation* of what the model emitted, which the model can game via
prompt phrasing.

A declarative policy file fixes this:

- The user (or operator, or CI pipeline) writes a policy. The file is
  text, version-controllable, reviewable in PRs.
- The runtime reads the policy at startup and enforces it. Forbidden
  operations fail at the **system layer**, not via a prompt asking the
  model nicely.
- The model literally cannot emit code that bypasses the policy by
  clever phrasing — the rejection happens before the action runs (or
  during, with audit), not in a model-readable wrapper.
- Policies can be selected by environment (dev / staging / prod /
  CI / sandbox) and composed (a CI policy can extend a dev policy
  with stricter `deny_*` lists).
- Different agents running against the same code with different
  policies behave three different ways at the *system* level. No
  re-prompting needed.

The portability angle is what makes the spec valuable beyond any one
runtime. A team using three different agent tools (one in the IDE, one
in CI, one as a deploy bot) writes one policy file and gets consistent
enforcement everywhere.

## Core principles

The spec encodes five rules. Implementations are expected to honor all
five; deviations should be documented as compatibility notes.

1. **Default-deny.** If an action is not explicitly allowed, it is
   denied. Never default-allow.
2. **Deny wins.** Explicit denies always override allows, on the same
   key or any parent. `read_allow = ["~/projects/**"]` plus
   `deny = ["~/projects/**/secrets/**"]` denies the secrets even
   though they're under an allowed prefix.
3. **Pre-execution check + runtime intercept + audit emit.** Three
   lines of defense. Static analysis catches design errors. Runtime
   intercept catches dynamic dispatch and clever workarounds. Audit log
   gives post-hoc accountability even when a determined attacker bypasses
   the first two.
4. **Confirm-per-call is a fallback, not the primary safety.** Most
   actions are pre-authorized by the policy and run silently with audit
   logging. Confirm prompts only fire for explicitly-marked categories
   (typically destructive ones: `fs.delete`, `subprocess.exec`,
   `database.write`). Avoids confirm-fatigue while keeping destructive
   actions human-gated.
5. **Negative space is explicit.** Allowlists alone are insufficient —
   `read_allow = ["~/projects/**"]` doesn't prevent a clever symlink
   attack, a path with `..` segments, or a typo that escapes the
   intended root. Belt-and-suspenders denylists (cloud-metadata IPs,
   SSH config, credentials files, bind-mount escape paths) close the
   enumeration gaps.

## The TOML schema

```toml
# ----- Top-level metadata (optional but recommended) -----
version = "1"                           # spec major version
name = "fastapi_prod_readonly"          # short human label
description = "Diagnose prod; cannot mutate anything"

# Capabilities that prompt the human before firing. Empty by default;
# any capability listed here triggers a synchronous confirm hook.
confirm_per_call = ["fs.delete", "subprocess.exec", "database.write"]

# ----- Filesystem -----
[filesystem]
# Path patterns are gitignore-style: relative patterns match anywhere
# under the policy root, absolute patterns match literal paths,
# `~/...` expands to $HOME.
read_allow   = ["src/**", "tests/**", "/tmp/agent_work/**"]
write_allow  = ["src/**", "/tmp/agent_work/**"]
delete_allow = ["/tmp/agent_work/**"]
deny = [
    "~/.aws/**", "~/.ssh/**", "~/.config/**",
    ".env", ".env.*",
    "**/secrets/**", "**/secrets.*",
    "/etc/passwd", "/etc/shadow",
]

# ----- Network -----
[network]
http_get_allow    = ["api.github.com", "*.npmjs.org"]
http_post_allow   = []
http_put_allow    = []
http_patch_allow  = []
http_delete_allow = []
deny_hosts = ["evil-exfil.example.com"]
deny_ips = [
    "169.254.169.254",   # cloud metadata service (IMDSv1/2)
    "10.0.0.0/8",        # internal CIDRs (when implementer supports CIDR)
]

# ----- Environment -----
[environment]
# Read named env vars only. Default-deny: a script can NOT enumerate.
allow_vars = ["USER", "HOME", "PATH", "GITHUB_REPOSITORY"]
deny_vars  = [
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
    "DATABASE_URL", "DATABASE_PASSWORD",
]

# ----- Subprocess -----
[subprocess]
# argv[0] basename match. Empty allow_commands = no subprocess at all.
allow_commands = ["git", "npm", "pytest", "ruff", "black"]
deny_commands = [
    "rm", "dd", "mkfs", "shred",
    "curl", "wget", "ssh", "scp", "nc",
    "sudo", "doas", "su",
]
# Per-command argument denylist (basename → forbidden patterns,
# substring-match against joined argv).
[subprocess.deny_args]
git = ["push --force", "reset --hard", "clean -fd"]
npm = ["publish"]
rails = ["db:drop", "db:reset"]

# ----- Database -----
[database]
# Globally-denied connection names (raw production handles, etc.)
deny_connections = ["prod_primary", "prod_admin"]
# SQL keywords forbidden everywhere, regardless of connection.
deny_operations = ["DROP", "TRUNCATE", "ALTER", "CREATE USER", "GRANT"]

[[database.connections]]
name = "localdev"
read = true
write = true
schemas_allow = ["public", "app"]
tables_deny = []

[[database.connections]]
name = "prod_replica"
read = true
write = false
schemas_allow = ["public", "analytics"]
tables_deny = ["users", "auth.*", "billing.*"]

# ----- Deployment / infra -----
[deployment]
deny_targets = ["disaster_recovery"]
tools = ["kubectl", "terraform", "aws", "flyctl"]

[[deployment.targets]]
name = "dev"
allow_actions = ["*"]

[[deployment.targets]]
name = "staging"
allow_actions = ["get", "describe", "logs", "rollout"]
deny_actions = ["delete", "scale"]

[[deployment.targets]]
name = "prod"
allow_actions = ["get", "describe", "logs"]
deny_actions = ["*"]                        # belt-and-suspenders
note = "Read-only diagnostic access only"

# ----- Capability allowlist -----
[functions]
# Which capabilities the script may reference at all. Names are dotted
# (`fs.read`, `database.write`, etc.); pre-execution check rejects any
# script that mentions a capability not in this list.
allow = [
    "fs.read", "fs.write",
    "net.http_get",
    "subprocess.exec",
    "env.read",
    "database.read",
]
deny = [
    "fs.delete",          # explicitly off in this environment
    "database.write",     # belt-and-suspenders even though it's not in allow
]
```

### Capability names

The canonical capability names are:

| Capability         | Meaning                                              |
|--------------------|------------------------------------------------------|
| `fs.read`          | Read file contents                                   |
| `fs.write`         | Create / overwrite a file                            |
| `fs.delete`        | Remove a file                                        |
| `net.http_get`     | HTTP GET                                             |
| `net.http_post`    | HTTP POST                                            |
| `net.http_put`     | HTTP PUT (reserved)                                  |
| `net.http_patch`   | HTTP PATCH (reserved)                                |
| `net.http_delete`  | HTTP DELETE (reserved)                               |
| `env.read`         | Read named environment variable                      |
| `subprocess.exec`  | Spawn a child process                                |
| `database.read`    | Issue a read-only SQL query                          |
| `database.write`   | Issue a mutating SQL statement                       |
| `deployment.exec`  | Invoke a deployment tool (kubectl, terraform, etc.)  |

Implementations may extend with their own capabilities (e.g.
`git.commit`, `git.push`, `pkg.install`) but should namespace them and
document the additions.

## Enforcement semantics

### Path matching

Paths follow gitignore conventions:

- `**` matches any number of path components.
- `*` matches anything within a component.
- A pattern with no `/` (e.g. `.env`) matches anywhere in the tree.
- A pattern with `/` is anchored relative to the policy root.
- Absolute paths match literally.
- `~/foo` expands to `$HOME/foo`.

A path access is allowed if:

1. The resolved canonical absolute path does **not** match any `deny`
   pattern, AND
2. The path matches at least one entry in the action-specific allow list
   (`read_allow`, `write_allow`, `delete_allow`).

Implementers are expected to canonicalize paths (resolving `..` and,
where possible, symlinks) before checking, so that
`/tmp/agent/../etc/passwd` is rejected even if `/tmp/agent/**` is
allowed.

### Host matching (network)

- Hosts are matched by glob (`*.npmjs.org` matches `registry.npmjs.org`).
- IP literals are matched as-is. Implementers SHOULD support CIDR
  ranges for `deny_ips` (e.g. `10.0.0.0/8`); compatibility note
  required if not.
- A request to a URL `https://h:p/path` is allowed if the host `h`
  is not in `deny_hosts`/`deny_ips` and IS in the verb-specific allow
  list.

### Subprocess matching

- Match `argv[0]` against `allow_commands` and `deny_commands` by
  basename (`/usr/bin/git` matches `git`). An entry containing `/`
  matches literally too — useful for distinguishing
  `/usr/local/bin/npm` from any old `npm`.
- After the command passes, `subprocess.deny_args` is consulted
  (basename → list of forbidden substrings against the joined argv[1..]).
  First match wins. Substring discipline is deliberate: simple,
  predictable, auditable. Known false-positive case: a pattern like
  `add` matches both `bundle add` *and* `bundle config add` even though
  only the first was intended; mitigation is to write more specific
  patterns (`"add "` with trailing space, or include the gem name).
  Implementers MAY skip the arg-level check in v1; Aegis implements it.

### Database matching

- A SQL statement is rejected if its leading keyword (case-insensitive,
  trimmed) appears in `deny_operations`.
- Connection name must be in some `[[database.connections]]` entry and
  not in `deny_connections`.
- The matching connection's `read`/`write` flag must be true for the
  operation kind. Reads = `SELECT`, `EXPLAIN`, `SHOW`, `WITH` (when
  the wrapped statement is a read). Writes = everything else.
- If `schemas_allow` is non-empty, the table being touched must
  resolve to one of those schemas.
- `tables_deny` is checked last (deny wins).

### Deployment matching

- Target name must appear in some `[[deployment.targets]]` entry and
  not in `deny_targets`.
- Action verb must be in `allow_actions` and not in `deny_actions`.
- Verbs are conventional and tool-specific; the spec doesn't
  prescribe an exhaustive list.

### Confirm-per-call

When a capability fires that's listed in `confirm_per_call`, the
runtime invokes a synchronous human-confirm hook before executing.
The hook receives:

```
{
  task_id:    string,    # opaque per-task identifier
  capability: string,    # e.g. "fs.delete"
  summary:    string,    # human-readable description ("delete /tmp/x")
}
```

The hook returns `Allow` or `Deny`. A `Deny` MUST be audit-logged with
`status="denied"` and `reason="confirm hook denied"`.

### Audit log

Every capability invocation — successful, denied at policy, or denied
at confirm — emits a structured event. Recommended shape:

```json
{
  "ts": "2026-05-04T17:23:00.512Z",
  "task_id": "deploy-2026-05-04",
  "step": 7,
  "capability": "fs.write",
  "status": "allowed | denied | errored",
  "detail": { ... capability-specific fields ... }
}
```

Detail fields by capability:

- `fs.*`: `{ "path": "<resolved>", "error": "<msg>" | null }`
- `net.*`: `{ "url": "<full>", "error": "<msg>" | null }`
- `subprocess.exec`: `{ "argv": [...], "exit": 0, "error": null }`
- `env.read`: `{ "name": "PATH", "error": null }`
- denied: `{ "target": "<what>", "reason": "<why>" }`

JSON Lines is the recommended on-disk format. Tamper-evident options
(signed lines, Merkle chaining) are out of scope for v1 of the spec
but compatible with the wire format.

## Implementer's guide (non-Aegis systems)

To consume this spec from your own agent host:

1. **Parse the file.** Use any TOML library. Make missing sections
   default to empty.
2. **Build matchers.** For each section, build the appropriate matcher
   (gitignore-style globs for paths, host globs for network, exact
   match for env vars).
3. **Decide where to enforce.** Three layers, all recommended:
   - **Pre-execution.** If your agent emits a tool call object before
     execution (`{tool: "fs.write", args: {...}}`), validate the
     arguments against the policy at the dispatch layer. Reject with
     a clear error before the tool runs.
   - **Runtime.** When the tool actually fires, re-check (defense in
     depth — handles dynamic dispatch and any path normalization that
     happened between dispatch and execution).
   - **Audit.** Emit an event for every check, allowed or denied.
     Include task/step/capability/status/detail.
4. **Wire confirm-per-call.** When a capability listed in
   `confirm_per_call` is about to fire, surface a UI prompt
   (modal in IDEs, stderr-prompt in CLIs, MCP roundtrip in MCP-based
   hosts) and wait for the answer synchronously.
5. **Map your tool surface to capability names.** If your agent has a
   `Bash` tool, that's `subprocess.exec` — apply
   `[subprocess].allow_commands` to the leading token. If you have a
   `WebSearch`/`WebFetch` tool, that's `net.http_get`. If you have an
   `Edit` tool, that's `fs.read` followed by `fs.write` (both must
   pass).
6. **Document your extensions.** If your tool needs capabilities not
   in the canonical list (e.g. `git.commit`, `slack.send`), use
   namespaced names and document them in your tool's policy reference.
7. **Honor environment selection.** A common pattern: the host loads
   `policy.dev.toml` by default, switches to `policy.prod_readonly.toml`
   when the working directory or env vars indicate a production-adjacent
   context. Selection MUST be host-driven, not derivable from the
   agent's prompt.

A common mapping for a Claude-Code-style host:

| Tool                       | Capability(ies)                      |
|----------------------------|--------------------------------------|
| `Read`                     | `fs.read`                            |
| `Write` / `Edit`           | `fs.read` + `fs.write`               |
| `Bash`                     | `subprocess.exec` (+ command list)   |
| `WebFetch` / `WebSearch`   | `net.http_get`                       |
| `Task` (subagent)          | inherits parent policy by default    |
| MCP tools                  | per-server, mapped by tool name      |

## Reference policies

The `examples/policies/` directory in this repository ships three
real-world starting points that this spec is intended to support
out of the box:

- `fastapi_dev.toml` — local FastAPI development. Read project tree,
  write only under `app/` and `tests/`, deny `.env*` and
  `**/secrets/**`, allow `pytest`, `uvicorn`, `ruff`, `black`,
  `git`, `pip` (in venv).
- `fastapi_prod_readonly.toml` — production diagnosis only.
  Read-only filesystem, no writes anywhere, no subprocess, only
  HTTP GET, prod database read on a replica connection only.
- `rails_dev.toml` — Rails project. Reads project tree but DENIES
  `config/secrets.yml`, `config/master.key`, `config/credentials/*`.
  Writes allowed under `app/`, `spec/`, `db/migrate/` but DENIED on
  `Gemfile.lock` and `Gemfile`. Allows `rails`, `rake`, `bundle`,
  `rspec`, but denies `rails db:drop`, `rails db:reset`, and
  `bundle add` via subprocess.deny_args.

Cargo'ed copies of all three live alongside this spec. They're
useful as both running-Aegis demos and as portable templates for any
agent host implementing the spec.

## Compatibility and versioning

The spec uses a single `version = "..."` field with semver-major
semantics:

- A v1 file MUST be readable by any v1.x implementation.
- New optional sections may be added in minor revisions; consumers
  encountering unknown sections SHOULD ignore them (forward
  compatibility).
- Removing or restructuring a section requires a major bump.
- Implementations SHOULD declare which version they support; an
  implementation reading a `version = "2"` file when it implements
  only v1 SHOULD reject the file with a clear error.

A compatibility profile in your README or product docs is encouraged:

> `my-agent-host` supports Agent Policy Spec v1, with the following
> notes: (1) `subprocess.deny_args` is parsed but not enforced
> (Slice 2 follow-up). (2) IP literals are matched as-is; CIDR support
> is reserved for v1.1.

## Aegis as the reference implementation

Aegis (this repository) is one runtime that implements this spec:

- Embeds Starlark via `starlark-rust 0.13` and exposes the canonical
  capability set as Starlark builtins (`fs.read`, `net.http_get`,
  `subprocess.exec`, etc.) under a curated namespace.
- Three integration surfaces: standalone CLI (`aegis run --policy
  ... <script>`), embeddable Rust crate (`aegis-host`), and an
  MCP server (planned for Slice 3). All three reuse the same
  `host::Runner` enforcement core.

### Enforcement coverage in Aegis today

Reading a policy file with Aegis does not mean every section is
actively gating the agent — Aegis enforces the surfaces it has
builtins for, and exposes the rest via the policy API for other
tools to consume. The honest picture:

| Section / field                  | Aegis enforcement |
|----------------------------------|-------------------|
| `[filesystem]` (read/write/delete allow + deny) | ✅ enforced |
| `[network]` http_get, http_post  | ✅ enforced |
| `[network]` http_put / patch / delete | ⚠️ schema only (no built-in yet) |
| `[network]` deny_hosts (glob)    | ✅ enforced |
| `[network]` deny_ips (literal)   | ✅ enforced (CIDR not yet) |
| `[environment]` allow_vars / deny_vars | ✅ enforced |
| `[subprocess].allow_commands` / `deny_commands` | ✅ enforced |
| `[subprocess.deny_args]`         | ✅ enforced (substring on joined argv[1..]) |
| `[functions].allow` / `deny`     | ✅ enforced (verifier + runtime) |
| `confirm_per_call`               | ✅ enforced |
| `[database]`                     | ❌ not enforced — schema only. Aegis has no `database.*` builtins; in practice the database policy lines in a real-world file (e.g. `rails_dev.toml`) become load-bearing only via `[subprocess].deny_commands` listing `psql`/`mysql`/`redis-cli`. |
| `[deployment]`                   | ❌ not enforced — schema only. `deny_targets` is descriptive; the actual block on an agent deploying to prod comes from `[subprocess].deny_commands` listing `kubectl`/`terraform`/`aws`/`flyctl`. |

The two unenforced sections are by design: a portable spec lives
above any one runtime. A database tool that wraps SQL queries
should consume `[database]`; a deployment wrapper should consume
`[deployment]`. Aegis specifically says no on those because the
honest cost of doing them well (a real SQL parser, real driver
integration; real kubectl-context handling) is much larger than
the policy-parsing cost. Other implementations are welcome and
encouraged to enforce the sections Aegis doesn't.

Other implementations are welcome more broadly. The spec is
intentionally implementation-neutral; Aegis serves as a reference
that proves the model is enforceable, not as the only correct way to
enforce it.
