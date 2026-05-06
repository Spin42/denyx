# Agent Policy Spec

**Status:** v1.0.0 — 2026-05-06

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
- [Inheritance and presets](#inheritance-and-presets)
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
version = "1.0.0"                       # semver MAJOR.MINOR.PATCH; see "Compatibility and versioning" below
inherits = "secure-defaults"            # opt into a built-in preset
name = "fastapi_prod_readonly"          # short human label
description = "Diagnose prod; cannot mutate anything"

# Capabilities that escalate to the caller for approval before each
# call. Empty by default. The host decides how to present the
# escalation (TTY prompt, MCP elicitation, desktop dialog) — see
# "Approval escalation" below for the protocol-level requirements.
requires_approval = ["fs.delete", "subprocess.exec"]

# ----- Filesystem -----
[filesystem]
# Path patterns are gitignore-style: relative patterns match anywhere
# under the policy root, absolute patterns match literal paths,
# `~/...` expands to $HOME.
read_allow   = ["src/**", "tests/**", "/tmp/agent_work/**"]
write_allow  = ["src/**", "/tmp/agent_work/**"]
delete_allow = ["/tmp/agent_work/**"]
# Local-only reads: the agent may read these paths, but the value
# never bubbles back to the host. See "Visibility classes" below.
local_only_read = ["~/.config/myapp/token"]
# Project-specific denies on top of the inherited preset's universal
# denies (~/.aws, ~/.ssh, **/.env, **/secrets/**, etc.).
deny = ["**/Gemfile.lock"]

# ----- Network -----
[network]
# One allow list per HTTP verb. Empty list = the verb is denied at
# the capability gate (no `net.http_post`, etc.).
http_get_allow    = ["api.github.com", "*.npmjs.org"]
http_post_allow   = ["api.openai.com"]
http_put_allow    = []
http_patch_allow  = []
http_delete_allow = []
# Local-only hosts: the agent may HTTP-call these, but the response
# body is tainted at the runtime boundary and scrubbed before
# crossing back to the host (e.g. an MCP tool result). See
# "Visibility classes" below.
local_only_hosts  = ["api.openai.com"]
deny_hosts = ["evil-exfil.example.com"]
# `secure-defaults` already lists 169.254.169.254 and the RFC1918
# / loopback ranges. Add project-specific IPs/CIDRs here.
deny_ips = []
# Per-call HTTP timeout. Defaults to 30 seconds when unset. Applies
# uniformly to every `net.http_*` verb. Tighten this to keep an
# unhealthy backend from hanging the agent.
timeout_seconds = 30

# ----- Environment -----
[environment]
# Read named env vars only. Default-deny: a script can NOT enumerate.
allow_vars = ["USER", "HOME", "PATH", "GITHUB_REPOSITORY"]
# Local-only vars: the agent may read the value, but it never bubbles
# back. See "Visibility classes" below. secure-defaults already
# denies AWS_*, OPENAI_API_KEY, GITHUB_TOKEN, etc. via deny_vars.
local_only_vars = ["OPENAI_API_KEY"]
# Belt-and-suspenders deny that wins over allow / local-only.
deny_vars = ["AWS_SECRET_ACCESS_KEY"]

# ----- Subprocess -----
[subprocess]
# argv[0] basename match. Empty allow_commands = no subprocess at all.
# secure-defaults' deny_commands already covers rm/sudo/ssh/curl/
# kubectl/etc. — list only project-specific allows here.
allow_commands = ["git", "npm", "pytest", "ruff", "black"]
# Local-only commands: stdout/stderr from these processes is tainted
# at the runtime boundary. See "Visibility classes" below.
local_only_commands = []
# Belt-and-suspenders deny on top of the inherited preset.
deny_commands = []
# Opt-in OS-level isolation backend. "none" (default): subprocesses
# run as regular processes inheriting the (filtered) parent env.
# "bwrap": Linux-only; each call runs in a fresh namespaced
# bind-mount jail derived from the policy. Implementations MAY
# extend with platform-specific backends; the spec only mandates
# that an unknown value is rejected at load.
sandbox = "none"

# Per-command argument denylist (basename → forbidden patterns,
# substring-match against joined argv[1..]).
[subprocess.deny_args]
git = ["push --force", "reset --hard", "clean -fd"]
npm = ["publish"]

# ----- Runtime caps (optional) -----
[runtime]
# Wall-clock cap, in seconds, per script invocation. Checked at
# every effecting capability call: the next call after the deadline
# fails with a typed runtime-limit error before the side effect
# runs. Pure CPU loops are NOT caught (run inside a container if
# you need that).
max_seconds = 30
# Maximum interpreter call-stack depth. Defends against recursion
# bombs. Implementation defaults vary; absent ⇒ implementation
# default.
max_callstack_size = 256

# ----- Host tools (optional) -----
[tools]
# Map external tool names (as exposed by an MCP host or an IDE agent
# runtime) to the dotted Aegis capabilities they require. A consuming
# host that receives a tool call by name (Bash, Read, Edit, WebFetch...)
# looks up the name here, gets back the implied capabilities, and
# verifies each is enabled (i.e. has a populated resource section)
# before invoking the tool. Default-deny: a tool not declared here is
# rejected.
Read      = ["fs.read"]
Edit      = ["fs.read", "fs.write"]
Write     = ["fs.write"]
Bash      = ["subprocess.exec"]
WebFetch  = ["net.http_get"]

# Long-form `[tools.X]` table: capabilities + optional routing
# hints. Bridges (e.g. local-executor harnesses) can read
# `backend_url`/`backend_method` to inject "for WebSearch, GET this
# URL" into the model's system prompt — so the model doesn't have
# to guess. The routing hint is informational; the network
# allowlist is the enforcement.
[tools.WebSearch]
capabilities   = ["net.http_get"]
backend_url    = "https://api.duckduckgo.com/?format=json&no_html=1&skip_disambig=1&q="
backend_method = "GET"
description    = "DuckDuckGo Instant Answer API (public, non-tracking, JSON)."
```

There is no separate `[functions]` allowlist. The set of permitted
capabilities is **derived** from which resource sections are
populated:

- `[filesystem].read_allow` or `local_only_read` non-empty ⇒ `fs.read`
- `[filesystem].write_allow` non-empty ⇒ `fs.write`
- `[filesystem].delete_allow` non-empty ⇒ `fs.delete`
- `[network].http_get_allow` (or any `local_only_hosts` entry) ⇒ `net.http_get`
- `[network].http_post_allow` (or any `local_only_hosts` entry) ⇒ `net.http_post`
- `[network].http_put_allow` / `http_patch_allow` / `http_delete_allow` (or `local_only_hosts`) ⇒ the matching verb
- `[environment].allow_vars` or `local_only_vars` non-empty ⇒ `env.read`
- `[subprocess].allow_commands` or `local_only_commands` non-empty ⇒ `subprocess.exec`

Listing the resource is the declaration of intent; there's no second
allowlist to keep in sync.

### Capability names

The canonical capability names are:

| Capability         | Meaning                                              |
|--------------------|------------------------------------------------------|
| `fs.read`          | Read file contents                                   |
| `fs.write`         | Create / overwrite a file                            |
| `fs.delete`        | Remove a file                                        |
| `net.http_get`     | HTTP GET                                             |
| `net.http_post`    | HTTP POST                                            |
| `net.http_put`     | HTTP PUT                                             |
| `net.http_patch`   | HTTP PATCH                                           |
| `net.http_delete`  | HTTP DELETE                                          |
| `env.read`         | Read named environment variable                      |
| `subprocess.exec`  | Spawn a child process                                |

Implementations may extend with their own capabilities (e.g.
`git.commit`, `git.push`, `pkg.install`) but should namespace them and
document the additions.

### Visibility classes

Every resource (a path, a host, an env var name, a command) is in
exactly one of three classes:

| Class             | Read / use? | Value crosses runtime boundary? | Typical use                                           |
|-------------------|-------------|----------------------------------|-------------------------------------------------------|
| **forbidden**     | no          | (read fails)                     | secrets, prod creds, `~/.aws`, `/etc/passwd`         |
| **local-only**    | yes         | tainted; never bubbles up        | API keys the agent needs to call a service           |
| **public**        | yes         | plain                            | normal source code, dev env vars                     |

The class is determined by which list contains the resource:

- **forbidden** — appears in the action's `deny` / `deny_*` list (deny wins over every allow).
- **local-only** — appears in the action's `local_only_*` list and not in any `deny`.
- **public** — appears in the action's plain allow list (`read_allow`, `http_get_allow`, `allow_vars`, `allow_commands`) and not in any `deny`.
- **forbidden** (the default) — appears in none of the above.

Per resource type, the local-only field name is:

- filesystem: `local_only_read`
- network: `local_only_hosts`
- environment: `local_only_vars`
- subprocess: `local_only_commands` (stdout/stderr of the child are tainted)

Implementations MUST treat `local_only_*` values as tainted at the
runtime output boundary: printed text, audit-event payloads, MCP
tool results, error messages must be scrubbed (or refused outright)
before they cross back to the calling host. See "Information-flow
guarantees and limits" below for the precise contract.

### Information-flow guarantees and limits

The local-only class is a **best-effort** information-flow control
layer. The spec mandates the *enforcement points* (every output
boundary the runtime emits to) but does not mandate a particular
algorithm — different implementations may catch different
transformations.

A v1-conformant implementation MUST, at minimum:

- Scrub the original byte sequence wherever it appears in any
  output the runtime emits.
- Refuse outbound effects (writes, subprocess calls to non-local-
  only commands, HTTP calls to non-local-only hosts) whose string
  arguments carry the original byte sequence.

A v1-conformant implementation SHOULD ALSO catch the common
mechanical transformations: byte-reverse, hex (lower + upper),
single-byte XOR with each key (and its hex form), base64
(standard + url-safe, with and without padding), and ROT-N for
N in 1..25.

A v1-conformant implementation is NOT REQUIRED to catch:

- Cryptographic transforms with a script-generated key (AES, RC4,
  custom invertible permutations) — the runtime doesn't know the
  key.
- Multi-byte XOR keys.
- Pure side channels (`len(secret)`, comparison oracles, substring-
  containment guesses).

These limits MUST be documented in the implementation's user-facing
documentation. The honest framing is: local-only defeats *accidental*
leakage and prompt-injection-grade exfiltration, not a deliberate
adversary running their own crypto.

## Inheritance and presets

To keep policy files focused on what's project-specific, the spec
supports a single field, `inherits = "<preset-name>"`, that pulls in a
known-good baseline.

Merge semantics: the preset is loaded as the base, the user file's
fields are merged on top.

- **List fields** (allow lists, deny lists, `requires_approval`)
  **concatenate with dedup**. A user-file entry of the form `"!X"`
  *removes* `X` from the inherited list (gitignore-style negation);
  this is the supported override path. Negation of an entry that
  isn't in the inherited list is a silent no-op.
- **Map fields** (`subprocess.deny_args`) merge by key; for shared
  keys, the value lists concatenate (with `!`-prefix negation per
  pattern).
- **Scalar fields** (`name`, `description`, `version`): user-file
  value wins if present, otherwise the preset's.
- **`inherits`** does not chain. Presets are not allowed to declare
  their own `inherits`.

#### Overriding preset entries

Sometimes a project legitimately needs to weaken an inherited deny
— a Kubernetes operator agent inside a kind/minikube sandbox where
`kubectl` IS the operator surface, a local-dev policy where the
agent is supposed to talk to `127.0.0.1`, an internal CI where
`pip --user` is the right call. The `!`-prefix syntax handles
these:

```toml
inherits = "secure-defaults"

[subprocess]
allow_commands = ["kubectl"]
deny_commands = ["!kubectl"]    # un-deny kubectl; preset's other denies stand

[network]
http_get_allow = ["localhost"]
deny_ips = ["!127.0.0.0/8"]     # un-block loopback

[filesystem]
deny = ["!~/.kube/config"]      # un-block ~/.kube/config so kubectl can read it
```

Two design choices behind this:

1. **Visibility.** A `!`-prefixed entry is hard to mistake for a
   typo in code review. "Why does this policy have `!kubectl`?" is
   a question that gets asked, where a quietly-shorter inherited
   list would not. Operators who want to weaken security have to
   say so explicitly, in writing, in version control.
2. **Granularity.** The user removes only the entries they need to.
   Other inherited denies (`rm`, `sudo`, `**/.env`, AWS metadata IP)
   stay enforced. The alternative — replace-the-whole-list — gives
   too much footgun room: the operator forgets one entry and
   everything inherited along with it goes silently absent.

Within a single user file, order matters: `["!X", "X"]` ends with
`X` present (the negation removes nothing, then `X` is added);
`["X", "!X"]` ends with `X` absent. In practice, mixing both is a
smell — pick one.

A v1-conformant implementation MUST ship at least the
`secure-defaults` preset, covering universally-bad actions on any
project: well-known credential paths, secret env var names,
destructive shell commands, the cloud metadata IP. The Aegis
runtime's preset is reproduced in
`crates/policy/src/presets.rs`.

Implementations MAY ship additional presets (`web-dev-defaults`,
`prod-readonly`, etc.). The conventions are:

- Preset names are kebab-case.
- Lookup is in-binary, not filesystem-resolved (presets are part of
  the trust boundary; anything resolvable by path or URL could be
  tampered with).
- An unknown preset name is a hard error at policy load — never a
  silent fallback to "no preset".

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
- `deny_ips` entries may be **literal IPs** (`"169.254.169.254"`) or
  **CIDR ranges** (`"10.0.0.0/8"`, `"::1/128"`, `"fc00::/7"`). Both
  v4 and v6 supported. Literal IPs are coerced to host networks
  internally (`/32` or `/128`) so all matching goes through one
  CIDR-containment code path.
- A request to a URL `https://h:p/path` runs through three checks
  in order:
  1. If `h` is an IP literal, it is checked against `deny_ips`.
     Match → reject.
  2. `h` is checked against `deny_hosts` (glob). Match → reject.
  3. `h` is checked against the verb-specific allow list.
     Miss → reject.
- Implementations SHOULD additionally **DNS-resolve hostnames**
  before initiating the request and run each resolved A/AAAA
  through the `deny_ips` check. This catches the case where a
  hostname (which passed the host glob check) resolves to an
  internal IP. Aegis fails open on resolution errors (a temporary
  DNS hiccup shouldn't block legitimate traffic) and matches at
  the IP layer; full defense against DNS rebinding requires
  resolved-IP pinning passed into the HTTP client, which is beyond
  v1.
- `timeout_seconds` (optional) bounds each individual `net.http_*`
  call. Implementations SHOULD apply it as the total request
  timeout (connect + read + write); a request that fails to
  complete within the budget surfaces as a runtime error. Default
  in Aegis is 30 seconds when unset. Keeping the timeout low (5–10s)
  is a defense-in-depth against unhealthy backends hanging the
  agent indefinitely.

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

### Subprocess is a privilege boundary

Listing a binary in `allow_commands` is a *privilege grant*, not just
a permission. Every implementation MUST treat the choice as such.

The runtime gates argv at three levels (Aegis names; ports may rename):

1. **Command gate** — argv[0] must pass `allow_commands` and
   `deny_commands` (above).
2. **Args gate** — `subprocess.deny_args` substring check.
3. **Argv path gate** — every argv element that *looks like a path*
   (absolute, starts with `~/`, contains `/`, or names an existing
   file at the policy root) is checked against the same `[filesystem]`
   rules as `fs.read` / `fs.write`. Aegis rejects
   `subprocess.exec(["cat", "/etc/passwd"])` if `/etc/passwd` is
   outside the read-side allow lists. Implementers SHOULD do the
   same; a port that skips this check has a real bypass for any
   file-touching binary it allows.

What these gates **cannot** see:

- **Paths constructed inside an inline interpreter argument.** A
  shell evaluator (`sh -c "..."`, `bash -c "..."`) or a code
  interpreter (`python -c "..."`, `node -e "..."`,
  `ruby -e "..."`, `perl -e "..."`) takes its content as a single
  string argv element. The runtime sees the string but cannot
  reason about what code inside it will open. `python -c
  "open(chr(47)+'etc'+chr(47)+'passwd').read()"` contains no
  literal `/`, the path is computed at runtime, and the gate is
  blind. **Implementations MUST treat shell evaluators and inline-
  exec interpreters as wholesale-bypass commands** and either
  deny them by default or document the consequence loudly. Aegis's
  `secure-defaults` preset denies them; language templates that
  legitimately need an interpreter (Python, Node, Ruby) negate
  the deny AND add a `deny_args` entry blocking the inline-exec
  flag (`-c`, `-e`, `-p`, etc.).

- **Paths read from environment variables or stdin** by the
  binary. Defense: filter the child env to the declared
  `allow_vars` only (Aegis does this), and don't pipe untrusted
  content into the child's stdin.

- **Children of generic command runners** (`env CMD`, `xargs CMD`,
  `find -exec CMD`, `timeout CMD`, `nohup CMD`, ...). These
  binaries spawn whatever command they're told to spawn, sidestepping
  `allow_commands` for the actual work. Aegis's `secure-defaults`
  denies them and adds `find = ["-exec", "-execdir"]` to
  `deny_args`. Implementers SHOULD do the same.

For total isolation, implementers SHOULD additionally provide an
opt-in OS-level sandbox backend (Aegis: `[subprocess].sandbox =
"bwrap"` on Linux). With sandboxing on, the child's filesystem
view is exactly what the policy bind-mounts in; paths outside the
view do not exist for the child no matter what obfuscation is
used.

### Approval escalation (`requires_approval`)

When a capability fires that's listed in `requires_approval`, the
runtime MUST invoke a synchronous **approval hook** before executing
the side effect. The hook receives:

```
{
  task_id:    string,    # opaque per-task identifier
  capability: string,    # e.g. "fs.delete"
  summary:    string,    # human-readable description ("delete /tmp/x")
}
```

The hook returns `Allow` or `Deny`. A `Deny` MUST be audit-logged
with `status="denied"` and a stable reason string the orchestrator
can match on (the Aegis implementation uses `"confirm hook denied"`
in error messages and tags MCP responses with `aegis_error_kind:
"confirm_denied"`).

How the hook surfaces the escalation depends on the host:

- **Terminal CLI.** Prompt on stdin/stderr; read `y`/`n`. The user
  is in the loop by construction.
- **MCP-based host.** Use the MCP `elicitation/create` primitive
  (protocol version `2025-06-18` and later). The server SHOULD send
  `elicitation/create` upstream when the client advertised
  `capabilities.elicitation` at handshake time, and MUST fall back
  to a structured deny (with a stable error tag the orchestrator
  can branch on) when the client did not advertise it. **Never
  silently auto-allow** an approval-required capability when
  elicitation is unavailable — that turns the field into a no-op.
- **Desktop / IDE host.** Render a modal dialog; await the user's
  click; map to Allow/Deny.
- **Embedded library.** Expose a trait/interface for the embedder
  to plug in.

**Deployment caveat all MCP implementers must document.** When the
end-user has put their MCP client in an auto-permission mode
(Claude Code's `--permission-mode auto`, opencode's unattended
mode, …), the client typically auto-responds to elicitation without
surfacing it to the user. In that configuration the hook still
returns Allow/Deny — but it returns the client's auto-policy, not a
real human decision. Implementations SHOULD make this caveat
explicit in their user-facing documentation.

### Audit log

Every capability invocation — successful, denied at policy, or denied
at the approval hook — emits a structured event. Recommended shape:

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
- `denied`: `{ "target": "<what>", "reason": "<why>" }`

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
4. **Wire approval escalation.** When a capability listed in
   `requires_approval` is about to fire, escalate to the caller and
   wait synchronously for the answer. CLI hosts: prompt on stdin.
   MCP hosts: send `elicitation/create` to the client when it
   advertises the capability, fall back to a structured deny
   (never silent auto-allow) otherwise. Desktop/IDE hosts: render
   a modal. The escalation MUST happen before any side effect, and
   a deny MUST be audit-logged.
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

A common mapping for a Claude-Code-style host (preferably declared
in the policy's `[tools]` block rather than hardcoded in the host):

| Tool                       | Capability(ies)                      |
|----------------------------|--------------------------------------|
| `Read`                     | `fs.read`                            |
| `Write` / `Edit`           | `fs.read` + `fs.write`               |
| `Bash`                     | `subprocess.exec` (+ command list)   |
| `WebFetch` / `WebSearch`   | `net.http_get`                       |
| `Task` (subagent)          | inherits parent policy by default    |
| MCP tools                  | per-server, mapped by tool name      |

When a host receives a tool call by name (e.g. `Bash {command: "ls"}`),
the recommended dispatch is:

1. `Policy::check_tool("Bash")` returns `["subprocess.exec"]` if
   declared and all capabilities are allowed.
2. The host verifies any tool-specific args against the relevant
   capability checks (e.g. `policy.check_subprocess_command(...)`
   for the leading argv token).
3. Tool runs, audit event is emitted with the resolved capability
   names so a reviewer can correlate "Bash ran" to "subprocess.exec
   was used".

## Reference policies

The `examples/policies/` directory in this repository ships three
real-world starting points that this spec is intended to support
out of the box:

- `fastapi_dev.toml` — local FastAPI development. Read project tree,
  write only under `app/` and `tests/`, deny `.env*` (via the
  inherited preset) and lockfile writes, allow `pytest`, `uvicorn`,
  `ruff`, `black`, `git`, `pip` (in venv), and friends.
- `fastapi_prod_readonly.toml` — production diagnosis only.
  Read-only filesystem, no writes anywhere, only HTTP GET, only a
  read-only diagnostic shell (`cat`/`grep`/`ps`/...).
- `rails_dev.toml` — Rails project. Reads project tree but DENIES
  `config/secrets.yml`, `config/master.key`, `config/credentials/**`.
  Writes allowed under `app/`, `spec/`, `db/migrate/` but DENIED on
  `Gemfile.lock` and `Gemfile`. Allows `rails`, `rake`, `bundle`,
  `rspec`, but denies `rails db:drop`, `rails db:reset`, and
  `bundle add` via `[subprocess.deny_args]`.

Cargo'ed copies of all three live alongside this spec. They're
useful as both running-Aegis demos and as portable templates for any
agent host implementing the spec.

## Compatibility and versioning

The spec uses a single `version = "MAJOR.MINOR.PATCH"` field
following [Semantic Versioning 2.0.0](https://semver.org). Each
component has a precise meaning at the schema level:

- **MAJOR** — incompatible schema changes. Removing or restructuring
  a section, renaming a field, changing a field's type, or
  tightening a constraint that an existing v1 file might violate.
  Implementations that support v1 MUST reject a `version = "2.x.y"`
  file with a clear error.
- **MINOR** — additive, backward-compatible changes. New optional
  sections, new optional fields on existing sections, new
  capability names, new preset names. A v1.0 implementation reading
  a v1.1 file MUST accept it: it MUST ignore unknown sections and
  unknown fields, and MUST treat unknown capability names declared
  in `requires_approval` as opaque (escalate to the caller as if
  they were known).
- **PATCH** — clarifications, typo fixes, doc rewrites. No
  observable behavioural change for any conforming implementation.

What this means for implementers:

- Match on MAJOR. `version = "1.0.0"`, `"1.4.7"`, `"1.99.0"` all
  parse and run on a v1 implementation.
- Reject on MAJOR mismatch. A v1 implementation MUST refuse a
  v2.x.y file at load with an actionable error.
- Tolerate the unknown. Encountering a section, field, or capability
  name your implementation doesn't know is NOT a load error if the
  MAJOR matches; it's a silent skip plus, ideally, a one-line
  warning the operator can grep for.

The `version` field itself is OPTIONAL. A file without `version`
parses as if it were the current major's latest minor — useful for
hand-edited dev policies. Production policies SHOULD pin a specific
`MAJOR.MINOR.PATCH`.

A compatibility profile in your README or product docs is encouraged:

> `my-agent-host` supports Agent Policy Spec v1.0, with the
> following notes: (1) `subprocess.deny_args` is parsed but not
> enforced (Slice 2 follow-up). (2) The `bwrap` sandbox backend is
> Linux-only; macOS / Windows fall back to the language-level gate.

## Aegis as the reference implementation

Aegis (this repository) is one runtime that implements this spec:

- Embeds Starlark via `starlark-rust 0.13` and exposes the canonical
  capability set as Starlark builtins (`fs.read`, `net.http_get`,
  `subprocess.exec`, etc.) under a curated namespace.
- Three integration surfaces: standalone CLI (`aegis run --policy
  ... <script>`), embeddable Rust crate (`aegis-host`), and an MCP
  server (`aegis-mcp --policy ... <stdio>`). All three reuse the
  same `host::Runner` enforcement core.
- The MCP server speaks newline-delimited JSON-RPC 2.0 on stdio and
  exposes nine tools: a primary `aegis_run(script)` for full
  Starlark programs, per-capability sugar (`aegis_fs_read`,
  `aegis_fs_write`, `aegis_fs_delete`, `aegis_subprocess_exec`,
  `aegis_net_http_get`, `aegis_net_http_post`, `aegis_env_read`),
  and a read-only oracle `aegis_tool_routing(name?)` that returns
  the `[tools.X]` records (capabilities, backend_url, backend_method,
  description, allowed flag) so a calling host can consult the
  policy's tool surface without re-parsing the TOML.
  Hosts that prefer one MCP call per discrete action use the sugar;
  hosts whose agents naturally compose multi-step Starlark prefer
  `aegis_run`. All surfaces share the same enforcement code path.

### Enforcement coverage in Aegis today

Every section of the v1 schema is actively enforced by the runtime.
The honest picture:

| Section / field                  | Aegis enforcement |
|----------------------------------|-------------------|
| `[filesystem]` (read/write/delete allow + deny) | ✅ enforced |
| `[network]` http_get, http_post  | ✅ enforced |
| `[network]` http_put / patch / delete | ✅ enforced |
| `[network]` deny_hosts (glob)    | ✅ enforced |
| `[network]` deny_ips (literal + CIDR) | ✅ enforced; DNS-resolves hostnames and checks each A/AAAA |
| `[network].timeout_seconds`      | ✅ enforced; per-call HTTP total-time deadline (default 30s) |
| `[environment]` allow_vars / local_only_vars / deny_vars | ✅ enforced; subprocess child env is filtered to declared vars only |
| `[subprocess].allow_commands` / `local_only_commands` / `deny_commands` | ✅ enforced |
| `[subprocess.deny_args]`         | ✅ enforced (substring on joined argv[1..]) |
| `[runtime].max_seconds`          | ✅ enforced at every effecting capability call; pure CPU loops not caught (run inside a container for full isolation) |
| `[runtime].max_callstack_size`   | ✅ enforced via Starlark Evaluator |
| `[filesystem].local_only_read` / `[network].local_only_hosts` | ✅ enforced; values tainted at output boundary (printed, audit, MCP result) |
| Derived capability set            | ✅ enforced (verifier + runtime); auto-derived from populated resource sections, no `[functions]` block |
| `[tools]` short and long form     | ✅ enforced via Policy::check_tool; long form's backend_url / backend_method routing hints exposed via Policy::tool_routing for bridge layers |
| `requires_approval`               | ✅ enforced via ConfirmHook; `aegis-mcp --confirm-mode {auto,elicit,auto-deny,auto-allow}` selects behavior. `auto` (default) sends MCP `elicitation/create` when the client advertises elicitation, otherwise falls back to `auto-deny`. `auto-deny` tags responses with `aegis_error_kind: "confirm_denied"` for orchestrator branching. |
| Self-writable guard              | ✅ enforced at load — refuses any policy whose write_allow / delete_allow matches the policy file itself |
| `inherits` (presets)             | ✅ resolved at load |

If your project needs database-level access control or a
deployment-tool gate, those concerns live above this spec — wrap
your DB driver or your `kubectl` runner with a policy of its own,
or rely on `[subprocess].allow_commands` and
`[subprocess.deny_args]` to keep the agent away from the relevant
binaries.

Other implementations are welcome. The spec is intentionally
implementation-neutral; Aegis serves as a reference that proves the
model is enforceable, not as the only correct way to enforce it.
