# The Policy File

> ← [Back to docs README](README.md) · Implements
> [Agent Policy Spec v1.0.0](agent-policy-spec.md)

The policy file is **the** thing in Denyx. It declares what an agent run
is allowed to do, and the runtime enforces it. This document covers:

- [Quick reference](#quick-reference)
- [The `denyx init` generator](#the-denyx-init-generator)
- [Sections in detail](#sections-in-detail)
  - [`[filesystem]`](#filesystem)
  - [`[network]`](#network)
  - [`[environment]`](#environment)
  - [`[subprocess]`](#subprocess)
  - [`[runtime]`](#runtime)
  - [`[tools]`](#tools)
  - [`requires_approval`](#requires_approval)
- [Capabilities are derived, not declared](#capabilities-are-derived-not-declared)
- [Inheritance and presets](#inheritance-and-presets)
- [The three visibility levels](#the-three-visibility-levels)
- [How the runtime resolves a call](#how-the-runtime-resolves-a-call)
- [Common patterns](#common-patterns)

For the *portable* spec — the implementation-neutral wire format —
see [agent-policy-spec.md](agent-policy-spec.md) (v1.0.0). This document is the
how-to-use guide for the Denyx runtime specifically.

## Quick reference

```toml
# A real policy file, top to bottom.

inherits = "secure-defaults"        # baseline of universal denies
name = "myproject dev"              # human label, free-form
description = "agent profile for local development"

requires_approval = [               # capabilities that escalate to the
    "fs.delete",                    # caller before each call. CLI: TTY
    "subprocess.exec",              # prompt. MCP: elicitation if the
]                                    # client supports it; otherwise
                                     # auto-deny with a structured tag.

[filesystem]
read_allow      = ["src/**", "tests/**", "README.md"]
local_only_read = ["~/.config/myapp/token"]   # read OK, value never bubbles up
write_allow     = ["src/**", "build/**", "/tmp/**"]
delete_allow    = ["build/**", "/tmp/**"]
deny            = ["**/.env*", "~/.aws/**"]   # belt-and-suspenders

[network]
http_get_allow   = ["api.github.com", "*.npmjs.org"]
http_post_allow  = ["api.example.com"]
local_only_hosts = ["api.openai.com"]   # response body tainted, never leaks
deny_hosts       = ["evil.example.com"]
deny_ips         = ["169.254.0.0/16", "10.0.0.0/8"]   # CIDR-aware

[environment]
allow_vars      = ["PATH", "HOME", "USER"]
local_only_vars = ["OPENAI_API_KEY"]   # readable, value never leaves runtime
deny_vars       = ["AWS_SECRET_ACCESS_KEY"]

[subprocess]
allow_commands      = ["git", "make", "python3", "pytest"]
local_only_commands = ["openssl"]      # stdout/stderr tainted
deny_commands       = ["rm", "sudo", "kubectl"]

[subprocess.deny_args]                  # per-command argv blocklist
git    = ["push --force", "reset --hard", "filter-branch"]
rails  = ["db:drop", "db:reset"]
cargo  = ["publish", "yank"]

[tools]                                  # for hosts that consult Denyx as
Read      = ["fs.read"]                  # an authorization oracle, mapping
Edit      = ["fs.read", "fs.write"]      # tool calls (Bash, Read, Edit, ...)
Bash      = ["subprocess.exec"]          # to required Denyx capabilities.
WebFetch  = ["net.http_get"]             # fetch a known URL
WebSearch = ["net.http_get"]             # query a search engine
```

> **There is no `[functions]` block.** The capabilities the script may
> call are derived directly from which resource sections you populated.
> If `read_allow` has entries, `fs.read` is permitted; if
> `allow_commands` has entries, `subprocess.exec` is permitted; and so
> on. See [Capabilities are derived, not declared](#capabilities-are-derived-not-declared)
> below for the full mapping.

## The `denyx init` generator

The fastest way to a working policy is `denyx init`. It emits a starter
policy with:

- `inherits = "secure-defaults"` for the system-protection baseline
- per-language toolchain `allow_commands`
- typical project source layout in `read_allow` / `write_allow`
- `[subprocess.deny_args]` for git destructive operations
  (`push --force`, `reset --hard`, `filter-branch`, `branch -D`, ...)
- explicit `filesystem.deny` for staging / qa / production config files
  (`.env.production`, `secrets.yml`, `production.toml`, ...)
- `[network]` left empty so any HTTP target is an explicit opt-in

Five languages are supported:

```sh
denyx init --lang python    # python3, pip, pytest, ruff, ...
denyx init --lang node      # node, npm, tsc, eslint; npm publish blocked
denyx init --lang ruby      # ruby, bundle, rails, rspec; rails db:drop blocked
denyx init --lang rust      # cargo, rustc; cargo publish/yank blocked
denyx init --lang go        # go, gofmt, golangci-lint
```

Output goes to `denyx.toml` by default; pass `--output PATH` to choose a
different name, or `--output -` to write to stdout. The generator refuses
to overwrite an existing file unless `--force` is passed.

After `denyx init`, **read the file** and trim or extend it for your
project. The templates are conservative starting points, not finished
policies.

## Sections in detail

### `[filesystem]`

| Field             | Effect                                                          |
|-------------------|-----------------------------------------------------------------|
| `read_allow`      | Paths the script may read (`fs.read`)                            |
| `local_only_read` | Paths the script may read, but contents are tainted (see below)  |
| `write_allow`     | Paths the script may write or create (`fs.write`)                |
| `delete_allow`    | Paths the script may delete (`fs.delete`)                        |
| `deny`            | Belt-and-suspenders denylist; **deny wins** over any allow       |

Patterns are gitignore-style globs (powered by the `globset` crate).
The form is **auto-detected** — you can freely mix all three in the
same list:

| Pattern              | Form         | Resolves to                                              |
|----------------------|--------------|----------------------------------------------------------|
| `src/**`             | relative     | `<policy-dir>/src/**`                                    |
| `*.json`             | relative bare| `<policy-dir>/**/*.json` (mirrors gitignore)             |
| `**/secrets/**`      | relative     | any `secrets/` directory under the policy root           |
| `/etc/passwd`        | absolute     | `/etc/passwd`, used as-is                                |
| `/tmp/**`            | absolute     | `/tmp/**`, used as-is                                    |
| `~/.config/myapp/**` | tilde        | `$HOME/.config/myapp/**`                                 |

A typical policy mixes them — relative for the project's own layout,
absolute for shared system paths the agent legitimately needs:

```toml
[filesystem]
read_allow  = ["src/**", "tests/**", "/tmp/**", "~/.cache/myapp/**"]
write_allow = ["src/**", "/tmp/denyx_demo/**"]
```

**The policy root is the directory containing the policy file**, not
the operator's current working directory. This is the portable default:
the same policy file works whether you run denyx from the project root,
from a subdirectory, or in CI — and you don't have to leak your
personal directory structure (`/home/alice/projects/myproject/...`)
into the policy. Override the root explicitly with
`Policy::load_with_root` if you need a different anchor.

### The self-writable guard

A policy that grants `fs.write` or `fs.delete` on its own file is
self-defeating: an agent that can rewrite the policy controlling it
can disable every other rule on the next run. Denyx refuses to load
any policy whose `write_allow` or `delete_allow` matches the policy
file's own path. The error names the offending field and points at
the fix:

```
policy file at "/home/alice/proj/denyx.toml" is itself matched by
[filesystem].write_allow; refusing to load — an agent that can write
its own policy can disable every other rule. Tighten your allow
patterns or add the policy file to [filesystem].deny.
```

You hit this most often with broad globs (`write_allow = ["**"]`).
Two ways out: tighten the allow pattern (e.g. `["src/**"]` instead
of `["**"]`), or keep the broad allow and add an explicit
`deny = ["denyx.toml"]` — deny wins, the runtime sees the file as
unwritable, the guard lets the policy load.

### `[network]`

| Field               | Effect                                                          |
|---------------------|-----------------------------------------------------------------|
| `http_get_allow`    | Hosts permitted for `net.http_get`                              |
| `http_post_allow`   | Hosts permitted for `net.http_post`                             |
| `http_put_allow`    | Hosts permitted for `net.http_put`                              |
| `http_patch_allow`  | Hosts permitted for `net.http_patch`                            |
| `http_delete_allow` | Hosts permitted for `net.http_delete`                           |
| `local_only_hosts`  | Hosts permitted for any verb; response bodies are tainted        |
| `deny_hosts`        | Hosts always denied (deny wins)                                  |
| `deny_ips`          | IP literals or CIDR ranges always denied; checked at DNS resolution |
| `timeout_seconds`   | Per-call HTTP timeout in seconds. Defaults to 30. Applies uniformly to every `net.http_*` builtin. Set low (e.g. 5) to keep an unhealthy backend from hanging the agent. |

Host patterns use the same glob syntax (so `*.npmjs.org` matches
`registry.npmjs.org` and `www.npmjs.org`). `deny_ips` accepts both
literal IPs (`"169.254.169.254"`, coerced to `/32`) and CIDR ranges
(`"10.0.0.0/8"`).

When the script calls `net.http_get("https://example.com/...")`, Denyx:

1. Parses the URL.
2. If the URL's host is itself an IP literal, runs it through `deny_ips`.
3. Resolves the host via DNS.
4. Runs **every resolved IP** through `deny_ips`. (Defends SSRF: if
   `evil.example.com` resolves to `169.254.169.254`, the request is
   rejected.)
5. Checks `deny_hosts`.
6. Checks the verb's `_allow` list (or `local_only_hosts`).

### `[environment]`

| Field             | Effect                                                          |
|-------------------|-----------------------------------------------------------------|
| `allow_vars`      | Env var names the script may read with `env.read`               |
| `local_only_vars` | Names the script may read; values tainted at the boundary       |
| `deny_vars`       | Names always denied (deny wins, even over `allow_vars`)          |

Names match exactly. `env.read("PATH")` succeeds only if `"PATH"` is in
`allow_vars` or `local_only_vars`. There's no glob support — the canonical
name is the single source of truth.

### `[subprocess]`

| Field                 | Effect                                                       |
|-----------------------|--------------------------------------------------------------|
| `allow_commands`      | Commands the script may exec; matched by basename of argv[0] |
| `local_only_commands` | Commands the script may exec; stdout/stderr tainted          |
| `deny_commands`       | Commands always denied (deny wins)                           |
| `deny_args`           | Per-command forbidden argument patterns (table)              |
| `requires_approval_args` | Per-command argv patterns that trigger the confirm hook (table) |

Commands match against the basename of `argv[0]`, so `"git"` matches
both `"git"` and `"/usr/bin/git"`. An absolute-path entry like
`"/usr/local/bin/npm"` matches that exact path only (so a hijacked
`/tmp/npm` won't sneak through).

`deny_args` is a substring match against the joined argv tail. A common
shape:

```toml
[subprocess.deny_args]
git    = ["push --force", "push -f", "reset --hard", "filter-branch"]
bundle = ["publish"]
rails  = ["db:drop", "db:reset"]
```

The substring discipline is deliberately simple. It has known
false-positive cases (the pattern `add` would match `bundle config add`
even though intent was `bundle add`); use more specific patterns
(`"add "` with trailing space, or `"add gem-name"`) when needed.

#### Per-argv confirm-hook prompts (`requires_approval_args`)

The top-level `requires_approval` list (covered in its own section
below) fires the confirm hook for **every** call of a capability —
all `subprocess.exec`s, all `fs.delete`s. That's the right shape
when the capability itself is the boundary you want to gate.

For `subprocess.exec` specifically, operators often want a finer
grain: *"I trust `git` enough to run `git add` / `git commit`
without a prompt, but I want a human-in-the-loop before any
`git push` or `git reset --hard`."* `[subprocess.requires_approval_args]`
expresses exactly this — same map-of-substring-patterns shape as
`deny_args`, but the runtime effect is a prompt, not a deny:

```toml
[subprocess.requires_approval_args]
git   = ["push", "reset --hard", "rebase -i"]
cargo = ["publish"]
gh    = ["release create", "pr merge"]
```

Matching semantics are identical to `deny_args` (substring against
the joined argv tail, basename argv0 lookup with full-path
fallback). When a pattern matches, the confirm hook is called with
a summary that names the matched pattern, so a UI prompt can
render *"`git push --force` matches `push` — approve?"* rather
than a generic *"subprocess.exec — approve?"*.

If `"subprocess.exec"` is **also** in the top-level
`requires_approval` list, the capability-level prompt wins; the
per-argv check is suppressed so the operator never sees two
dialogs for one call.

`!`-negation is supported during inheritance, same as `deny_args`:
a user policy can drop an inherited pattern by writing
`git = ["!push"]` in `[subprocess.requires_approval_args]`.

#### Subprocess is a privilege boundary

Listing a binary in `allow_commands` is a *privilege grant*, not just
a permission. The runtime gates argv at three levels:

1. **`check_subprocess_command`** — argv[0] must be in `allow_commands`
   and not in `deny_commands`.
2. **`check_subprocess_args`** — joined argv[1..] is checked against
   `[subprocess.deny_args]` per-command patterns.
3. **`check_subprocess_argv_paths`** — every argv element that *looks
   like a path* (absolute, tilde, contains `/`, or names an existing
   file at the policy root) is checked against the same `[filesystem]`
   rules the script itself would face. `subprocess.exec(["cat",
   "/etc/passwd"])` is rejected.

What these gates **cannot** see: paths constructed inside a string
argument to a shell evaluator or interpreter. `python3 -c
"open(chr(47)+'etc'+chr(47)+'passwd').read()"` — the inline string
contains no literal `/`, the path is computed at runtime, and Denyx
has no visibility into the Python interpreter's heap. **Any binary
that takes inline code (`sh -c`, `bash -c`, `python -c`, `node -e`,
`perl -e`, `ruby -e`, `lua -e`) is a wholesale bypass for the argv
gate when allowed in `allow_commands`.**

Two layers of defense:

**Layer 1 (always on): tightened `secure-defaults`.** The preset
denies shell evaluators (`sh`, `bash`, `zsh`, `dash`, `fish`),
inline-execution interpreters (`python`, `python3`, `ruby`, `node`,
`perl`, ...), and generic command runners (`env`, `xargs`, `watch`,
`timeout`) by default. Operators who legitimately need them must
`!`-negate AND understand that the language-runtime defense
collapses for those calls. The `denyx init` language templates that
need the relevant interpreter (`python` for Python, `node` for
Node, etc.) negate it AND add a `[subprocess.deny_args]` entry that
blocks the inline-execution flags (`-c`, `-e`, `-p`).

**Layer 2 (opt-in): `[subprocess].sandbox = "bwrap"`.** OS-level
isolation. Every `subprocess.exec` call is wrapped with
[bubblewrap](https://github.com/containers/bubblewrap), which
constructs a fresh Linux namespace + bind-mount jail per call. The
child sees:

- `/usr`, `/lib`, `/lib64`, `/bin`, `/sbin` (read-only) — needed
  to exec at all
- `/etc/ld.so.cache`, `/etc/resolv.conf`, `/etc/hosts`, `/etc/nsswitch.conf` (read-only) — linker + DNS
- `/proc`, `/dev` (special mounts, minimal)
- Each concrete prefix derived from the policy's read/write/delete
  allow lists (read-only or read-write as appropriate)
- *Nothing else.* `/etc/passwd` is not bound. `~/.aws` is not
  bound. The agent's writable directories outside the policy are
  not bound. The child literally cannot reach paths the policy
  didn't permit, **no matter what obfuscation an interpreter uses
  to construct them.**

```toml
[subprocess]
allow_commands = ["python3", "git", "make"]
sandbox        = "bwrap"   # opt in to OS-level isolation
```

Properties:
- Linux-only for v1. Requires `bubblewrap` installed (`apt install
  bubblewrap` on Debian/Ubuntu, `dnf install bubblewrap` on
  Fedora). Denyx refuses to load if `sandbox = "bwrap"` is set but
  the binary isn't on `PATH` — silent fall-through to non-sandboxed
  execution would be the wrong direction.
- Per-call overhead: ~10-50ms for the namespace setup.
- Network: kept (`--share-net`) if any `[network].http_*_allow` is
  populated; otherwise the netns is dropped (`--unshare-net`).
- Process: `--die-with-parent`, `--unshare-pid/uts/ipc`,
  `--new-session`. The child is sandboxed and won't outlive Denyx.
- Env: `--clearenv` then `--setenv` per declared `allow_vars`.
  Mirrors the language-layer env filter; bwrap is also responsible
  for env scoping when this mode is on.

When `sandbox = "bwrap"` is enabled, the argv path-gate (Layer 1)
becomes a fast first-line check; the bwrap layer is the actual
enforcement. Even if the path-gate has a false negative for some
clever argv, the child still can't reach paths outside the
bind-mount layout.

macOS/Windows operators get Layer 1 only today; platform-specific
backends (`sandbox-exec`, Job Objects) are future work.

#### Subprocess env is filtered, not inherited

The child process **does not inherit the parent's full environment**.
Denyx builds the child env from scratch:

- Every name in `[environment].allow_vars` is read from the parent
  and passed through (if set in the parent).
- Every name in `[environment].local_only_vars` is **only** passed
  when the command is in `[subprocess].local_only_commands` — so a
  local-only command can use a tainted secret for an authenticated
  call, and the runtime taints its stdout/stderr at the boundary.
  For a plain (non-local-only) command, the local-only var is NOT
  passed (otherwise the child could echo it into its output and
  defeat the redaction).
- Names in `[environment].deny_vars` are excluded defensively even
  if they appear in an allow list.

**Practical consequence**: if you want the child to find binaries
in `$PATH`, list `"PATH"` in `allow_vars`. Same for `"HOME"`,
`"LANG"`, etc. The `denyx init` templates already include these.
A policy with empty `allow_vars` produces a fully empty child env;
the subprocess must use absolute paths and won't have any standard
shell environment.

### `[runtime]`

Resource caps applied to the Starlark evaluator itself.

| Field                 | Effect                                                                                |
|-----------------------|---------------------------------------------------------------------------------------|
| `max_seconds`         | Wall-time cap (seconds). Checked at the entry of every effecting capability call. Past the deadline, the call returns a typed `RuntimeLimit` error before the action runs (exit code 6 in the CLI). `None` (default) ⇒ unlimited. |
| `max_callstack_size`  | Maximum Starlark call-stack depth. Defends against recursion bombs. Forwarded to `Evaluator::set_max_callstack_size`. `None` (default) ⇒ Starlark's built-in default.                  |

```toml
[runtime]
max_seconds        = 30
max_callstack_size = 200
```

**Limitation worth knowing**: `max_seconds` is checked at
capability-call entry, not on every Starlark statement. A pure
busy-loop with no I/O (`def f(): return f()` is caught by
`max_callstack_size`; a `for _ in range(10**9)` inside a `def`
without any builtin call is NOT caught by either knob and will run
to completion). Starlark has no public per-statement abort hook in
the current upstream API. **For total isolation against malicious
or runaway scripts, run Denyx inside a container.** This is the
deliberate layering the threat model assumes — Denyx is the
language-runtime gate, container/VM is the OS-isolation gate.

### `[tools]`

For hosts that consult Denyx as a *policy oracle* — they receive a tool
call like `Bash {command: "ls"}` and want to ask Denyx "is this allowed?"
— the `[tools]` block maps each tool name to the capabilities it
requires:

```toml
[tools]
Read      = ["fs.read"]
Edit      = ["fs.read", "fs.write"]
Bash      = ["subprocess.exec"]
WebFetch  = ["net.http_get"]   # fetch a known URL
WebSearch = ["net.http_get"]   # run a search query
```

`Policy::check_tool("Edit")` returns `Ok(["fs.read", "fs.write"])`
only if every required capability is enabled (i.e. every required
capability has a populated resource section); otherwise `ToolDenied`.
Tools not declared in `[tools]` are denied by default.

`WebFetch` and `WebSearch` both ultimately make an outbound HTTP
call, so they map to `net.http_get` (or `net.http_post` if your
search backend uses POST). They're listed separately because hosts
distinguish them at the call interface — Claude Code, Cursor, OpenAI
Assistants all expose them as different tools.

**Two TOML forms.** The short form is just a list of capability
names. The long form adds optional `backend_url`, `backend_method`,
and `description` routing hints — a single declaration that tells
the bridge layer (the local-executor harness, an IDE plugin, etc.)
which URL the tool actually targets, without leaving the model to
guess. Both forms work side by side:

```toml
[tools]
# Short form — capabilities only.
Read     = ["fs.read"]
WebFetch = ["net.http_get"]

# Long form — capabilities plus routing hints.
[tools.WebSearch]
capabilities   = ["net.http_get"]
backend_url    = "https://api.duckduckgo.com/?format=json&no_html=1&skip_disambig=1&q="
backend_method = "GET"
description    = "DuckDuckGo Instant Answer API (public, non-tracking, JSON)."

[network]
http_get_allow = ["api.duckduckgo.com"]
```

**Two-layer enforcement, one source of truth.** The routing hint is
informational — it tells callers *where this tool is meant to go*.
The actual HTTP destination is still enforced by
`[network].http_*_allow`. So a script that tries to bypass
`backend_url` and call `net.http_get("https://google.com/...")` fails
at the network layer because `google.com` isn't allowed, regardless
of how the call was framed. Denyx enforces the URL, not the tool
label.

This composes the way you'd want:

- **Hosts surface routing to the model.** A bridge like
  `examples/local_executor/local_mcp.py` reads `backend_url` and
  injects "for WebSearch, GET this URL" into the system prompt. The
  model no longer has to guess.
- **Denyx enforces the URL.** Whatever URL the model ends up calling
  is checked against `[network]`. The routing hint is not load-bearing
  for safety — it's a UX nudge for the model.
- **Operators control both.** Change `backend_url` in the policy and
  the model is told to use a different backend on the next run, with
  no orchestrator-side change. Add the new host to `http_get_allow`
  in the same edit.

A typical Denyx-mediated WebSearch policy looks like the example
above: one tool entry with the URL hint, one network entry allowing
that host. The default DuckDuckGo Instant Answer URL is public,
no-auth, non-tracking, and end-to-end-tested in this repo (see the
[research / web-search agent](#a-research--web-search-agent) common
pattern below). It returns abstracts and definitions for famous-
entity queries, not full web search results — for broader coverage
swap for a self-hosted SearxNG (`docker run -p 8888:8080
searxng/searxng`), Brave Search API, or Tavily.

> **Per-tool URL scoping.** If you want two distinct host sets —
> *"WebSearch may only hit the search API; WebFetch may hit the
> search API + GitHub + MDN"* — you list the superset in `[network]`
> and rely on the bridge layer to route WebSearch to its declared
> `backend_url`. Denyx itself does not scope hosts per-tool yet
> (`net.http_get` is one capability, one allowlist); a future
> enhancement could add `[tools.X].allow_hosts` if there's enough
> demand for strict per-tool URL gating.

### `requires_approval`

Capabilities listed here are *escalated to the caller* before each call.
The list is independent of the resource allow-lists: a capability that's
otherwise permitted by the policy still routes through the approval
hook on every call.

```toml
requires_approval = ["fs.delete", "subprocess.exec"]
```

During policy inheritance the list is merged with the same
`!`-negation discipline as `deny_commands`: a user file can drop
an inherited entry by writing `requires_approval = ["!subprocess.exec"]`.
Used against the `secure-defaults` preset, this lets an operator
opt out of capability-level prompts on specific items while
keeping the rest of the baseline. For finer-grained control on
`subprocess.exec` specifically — *"only prompt on dangerous argv
patterns of allowed binaries"* — see
[`[subprocess.requires_approval_args]`](#per-argv-confirm-hook-prompts-requires_approval_args)
above.

What "escalated to the caller" means depends on the embedder:

- **`denyx run` CLI** — interactive TTY prompt. The user sees a
  one-line summary and types `y` / `n`. This is the only path with a
  guaranteed real-human-in-the-loop today.
- **`denyx-mcp --confirm-mode auto`** (default) — if the connecting
  client advertises the MCP `elicitation` capability at handshake
  time, the server sends a real `elicitation/create` request to the
  client and blocks for the user's reply. If the client doesn't
  advertise elicitation, the server falls back to `auto-deny` (next
  bullet). See "Approval flow under MCP" below for the deployment
  caveat.
- **`denyx-mcp --confirm-mode auto-deny`** — every approval-required
  call returns a tool result with `isError: true` and an
  `denyx_error_kind: "confirm_denied"` tag. The orchestrator can
  surface that to the user via its own UI, edit the policy, and
  re-issue.
- **`denyx-mcp --confirm-mode auto-allow`** — every approval-
  required call passes. Use only for tests and demos. This defeats
  the purpose of `requires_approval`.
- **`denyx-mcp --confirm-mode elicit`** — force elicitation
  regardless of client capability advertisement. If the client
  doesn't actually implement elicitation, the request times out
  (300 s) and the call denies safely.
- **Embedded `denyx-host`** — the host implements the `ConfirmHook`
  trait directly against its UI surface (a desktop app prompt, an
  OAuth-style browser flow, whatever fits).

#### Approval flow under MCP — what actually happens with each client

The server-side primitive is correct: denyx-mcp's bidirectional
dispatch sends `elicitation/create` upstream, blocks on the response,
and maps it to Allow / Deny. **Whether the user actually sees the
prompt is a property of the client, not the server.** Empirical
findings as of 2026-05:

| Client | `--permission-mode` | Advertises elicitation? | What happens |
|--------|----------------------|------------------------|--------------|
| `claude -p` (Sonnet/Opus, Claude Code 2.1.x) | `default` / `auto` / others | **No** | denyx-mcp's `auto` mode falls back to `auto-deny`. Tool returns `isError: true`, `denyx_error_kind: "confirm_denied"`. Agent surfaces the denial in its text response. The runtime correctly enforces the deny — no side effect happens. |
| `claude` (interactive UI) | varies | TBD — verify in your version | If elicitation is advertised, the user gets a real prompt. If not, fallback to `auto-deny` and the orchestrator's own UX. |
| `opencode` | unattended | TBD per version | Same shape. |

**Take-away.** If you want a real per-call human prompt, today's
realistic deployment is one of:

1. **CLI** (`denyx run`) — when the user is at a terminal.
2. **MCP `auto-deny` + orchestrator-handled retry** — the structured
   `confirm_denied` tag gives the orchestrator everything it needs
   to render its own approval UX and either edit the policy or
   re-issue against a non-gated context. This is the most
   broadly-deployed shape today.
3. **MCP `elicit` with a client that supports elicitation** — the
   protocol works end-to-end (Denyx ships integration tests that
   prove this), but you have to verify your specific client
   actually surfaces the prompt instead of auto-responding to it.

Don't assume `requires_approval` plus an MCP server in `auto` mode
gives you human-in-the-loop. **Auto mode is the user's explicit
opt-out from being asked.** If the client doesn't advertise
elicitation (most don't yet, in 2026), the prompt has nowhere to
go, and denyx-mcp falls back to `auto-deny`, which is the safe
behavior — but there is no user prompt anywhere in the loop.

## Capabilities are derived, not declared

Denyx used to require both an `[functions].allow = [...]` block AND
the matching resource section. That was redundant — listing
`read_allow = ["src/**"]` already declares intent to use `fs.read`.
Denyx no longer has a `[functions]` block: capabilities are derived
directly from which resource sections you populate.

The full mapping:

| Resource section field that's non-empty                               | Capability derived  |
|----------------------------------------------------------------------|----------------------|
| `[filesystem].read_allow` or `local_only_read`                       | `fs.read`            |
| `[filesystem].write_allow`                                           | `fs.write`           |
| `[filesystem].delete_allow`                                          | `fs.delete`          |
| `[network].http_get_allow` (or any `local_only_hosts` entry)         | `net.http_get`       |
| `[network].http_post_allow` (or any `local_only_hosts` entry)        | `net.http_post`      |
| `[network].http_put_allow` (or any `local_only_hosts` entry)         | `net.http_put`       |
| `[network].http_patch_allow` (or any `local_only_hosts` entry)       | `net.http_patch`     |
| `[network].http_delete_allow` (or any `local_only_hosts` entry)      | `net.http_delete`    |
| `[environment].allow_vars` or `local_only_vars`                      | `env.read`           |
| `[subprocess].allow_commands` or `local_only_commands`               | `subprocess.exec`    |

What this means in practice:

- **You can't accidentally over-permit.** If you don't list any
  `write_allow` paths, `fs.write` is not callable — the verifier and
  the runtime both reject it. There's no way to "forget" to remove a
  capability declaration.
- **You can't accidentally under-permit.** If you list resource paths
  for a capability, that capability works. No second list to keep in
  sync.
- **The empty default is still safe.** A policy with no resource
  sections (e.g. the bare `secure-defaults` baseline) permits no
  capabilities at all. Pure computation works; every effecting call
  fails.

### Querying the derived set

The Rust API exposes `Policy::effective_functions()` returning the
list of capabilities currently enabled. Useful for diagnostics and
for hosts that want to surface "what can my agent actually do?"
without poking the policy file directly.

## Inheritance and presets

Every Denyx policy can `inherit` a built-in preset. There's currently one:
`secure-defaults`, the universal-deny baseline. Use it as your foundation:

```toml
inherits = "secure-defaults"
```

The preset embeds (see `crates/policy/src/presets.rs` for the full list):

- `[filesystem].deny` — `~/.aws/**`, `~/.ssh/**`, `**/.env*`,
  `**/secrets/**`, `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, ...
- `[network].deny_ips` — `169.254.0.0/16` (cloud metadata),
  `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (RFC1918),
  `127.0.0.0/8`, `::1/128` (loopback), `fc00::/7`, `fe80::/10` (IPv6
  unique-local + link-local).
- `[environment].deny_vars` — `AWS_*`, `OPENAI_API_KEY`, `GITHUB_TOKEN`,
  `STRIPE_SECRET_KEY`, `DATABASE_URL`, ...
- `[subprocess].deny_commands` — `rm`, `dd`, `sudo`, `ssh`, `curl`,
  `wget`, `kubectl`, `helm`, `aws`, `terraform`, `psql`, `mysql`, ...

The user file is merged on top: list fields concatenate with dedup; the
`tools` and `subprocess.deny_args` maps merge per-key.

### Negation: removing inherited entries

Sometimes the preset is too strict for your project. Use the
gitignore-style `!` prefix to remove an inherited entry:

```toml
inherits = "secure-defaults"

[subprocess]
allow_commands = ["kubectl"]
deny_commands  = ["!kubectl"]   # undo the preset's kubectl block
```

Or to allow loopback HTTP for local dev:

```toml
[network]
http_get_allow = ["localhost"]
deny_ips       = ["!127.0.0.0/8"]  # let 127.0.0.0/8 through (cloud metadata still blocked)
```

`!`-prefixed entries are visible in code review (`!~/.aws/**` is hard to
mistake for a typo), and silently no-op if the named entry wasn't in the
preset. They work in every list field, including `subprocess.deny_args`
per-command vectors.

## The three visibility levels

A unifying concept across `[filesystem]`, `[network]`,
`[environment]`, and `[subprocess]`: every readable resource has one of
three visibility levels.

| Level         | Read?       | Returned value          | When to use                                   |
|---------------|-------------|-------------------------|-----------------------------------------------|
| **forbidden** | no          | (read fails)            | secrets, prod creds, `~/.aws`, `/etc/passwd`  |
| **local-only**| yes         | tainted; never bubbles  | API keys the agent needs to call a service    |
| **public**    | yes         | plain                   | normal source code, dev env vars              |

For each resource type, the policy fields are:

- filesystem: `deny` / `local_only_read` / `read_allow`
- network: `deny_hosts` + `deny_ips` / `local_only_hosts` / `http_*_allow`
- environment: `deny_vars` / `local_only_vars` / `allow_vars`
- subprocess: `deny_commands` / `local_only_commands` / `allow_commands`

### How local-only works

The use case: a cloud orchestrator (e.g. Sonnet via Claude Code) delegates
a task to a local executor model. The local model needs to read your
`OPENAI_API_KEY` to call OpenAI's API on your behalf — but the key must
**not** bubble up to the cloud orchestrator (which would log it in
context history, send it back to Anthropic, etc.).

Mark the key local-only:

```toml
[environment]
local_only_vars = ["OPENAI_API_KEY"]

[network]
http_post_allow = ["api.openai.com"]   # outbound — the call we want to make

# env.read and net.http_post are auto-derived from the populated
# resource sections.
```

Now the local script can do this:

```starlark
key = env.read("OPENAI_API_KEY")
body = json.encode({"prompt": "..."})
resp = net.http_post("https://api.openai.com/v1/...", body)
print("response received")    # safe — no secret in the message
```

Even if a script tried to leak the key — `print("key=" + key)` —
the printed line crosses the runtime's output boundary and the
scrub replaces the key with `[REDACTED]` before the orchestrator
sees it.

The enforcement has three layers, all in the runtime:

1. **Output-boundary scrub.** Every `outcome.printed` line, every
   audit-event payload field, every MCP `denyx_run` tool-result
   string, and every error message is scanned. Each scan looks for
   the original tainted bytes AND a documented set of mechanically-
   derived sibling forms — byte-reverse, hex (lower + upper) of
   original and reverse, XOR with each single-byte key, and the hex
   encoding of every XOR result. Any match is replaced with
   `[REDACTED]`.
2. **Subsequence-chunking detection.** A script that prints the
   secret one character at a time interleaved with cover text never
   forms a substring match in any one line. The chunking pass walks
   the joined printed output looking for the secret's characters
   appearing in order with bounded gaps; if found, every line that
   contributed a character is replaced with `[REDACTED]`.
3. **Arg-side denial at outbound effects.** When the destination is
   *not* local-only — `fs.write` to a public path, `fs.delete` to
   any path, `subprocess.exec` of a non-local-only command,
   `net.http_*` to a non-local-only host — every string argument
   is scanned against the same transform set. A match means the
   script is trying to push tainted bytes out through a public
   sink: the call is **refused** with a typed Policy error (not
   scrubbed on the way out). The matched transform label is
   included in the audit-event payload so an operator can see
   exactly how the script tried to disguise the value (e.g.
   `xor_0x5a_hex_lower`).

The taint is **transitively persistent**: read the secret, write it
to a local-only path, read it back, print → still redacted, because
the readback registers as tainted on the new value too.

What this layer does NOT defend against (and the threat-model doc
documents honestly):

- Cryptographic transforms with a script-generated key (AES, RC4,
  custom invertible permutation). The redactor doesn't know the
  key, so the ciphertext doesn't match any pre-computed pattern.
  An adversary determined to bring their own crypto can still
  exfiltrate; closing this would require real value-level taint
  propagation through the Starlark evaluator, which is intrusive
  to the upstream `starlark-rust` crate.
- Pure side channels: `print(len(secret))`,
  `print(secret[0] == "s")`, `print("MNOP" in secret)`. Each
  reveals at most O(log L) bits per query. Defending against
  these would require forbidding `len()` / comparison / `in` on
  tainted values, which would break every legitimate use of a
  secret as a string.

The runtime-enforced rule still holds: a *prompt* alone cannot
bypass the policy, because the policy is enforced in Rust, not by
asking the model nicely.

## How the runtime resolves a call

For any effecting capability, the resolution order is fixed:

1. **Verifier** (pre-execution): is the capability name (e.g. `fs.read`)
   present in the **derived capability set**? Equivalently: is at least
   one resource section that enables this capability populated? If
   not, the whole script is rejected before any line evaluates.
2. **Capability gate** (per-call): re-checks the derived set at
   runtime (defends script-time aliasing).
3. **Resource gate** (per-call): is the specific resource (path, host,
   var name, command) permitted by the matching list?
   - `deny`: reject
   - `local_only_*`: permit, register taint
   - regular allow list: permit, plain
   - none of the above: reject (default-deny)
4. **Approval hook** (per-call): if the capability is in
   `requires_approval`, escalate to the caller. CLI prompts the
   user on stdin; MCP server sends `elicitation/create` (when the
   client supports it) or denies with a structured tag (when not).
   On deny, the call fails.
5. **Action**: do the read / write / fetch / exec.
6. **Audit emit**: log the outcome (`Allowed` / `Errored` / `Denied`).

If any of 1-4 fail, the action does not run.

## Common patterns

### A read-only inspection agent

```toml
inherits = "secure-defaults"

[filesystem]
read_allow = ["src/**", "tests/**", "README*", "**/*.md"]
```

No writes, no network, no subprocess, no env — but the agent can read
the project. Useful for code-review or summary agents. Only `fs.read`
is enabled because only `read_allow` was populated.

### A development agent

```toml
inherits = "secure-defaults"

[filesystem]
read_allow  = ["src/**", "tests/**", "*.toml", "README*"]
write_allow = ["src/**", "tests/**", "/tmp/**"]

[network]
http_get_allow = ["registry.npmjs.org", "deb.debian.org"]

[environment]
allow_vars = ["PATH", "HOME", "USER", "LANG"]

[subprocess]
allow_commands = ["git", "make", "python3", "pytest", "node", "npm"]

[subprocess.deny_args]
git = ["push --force", "reset --hard", "filter-branch"]
npm = ["publish"]
```

Enables `fs.read`, `fs.write`, `net.http_get`, `env.read`,
`subprocess.exec` — all derived from the populated sections. Run
`denyx init --lang <yours>` for a starting point you can trim.

### A CI / production-readonly agent

```toml
inherits = "secure-defaults"

[filesystem]
read_allow = ["**/*"]   # read anything (subject to inherited deny)
```

Inspecting agent for prod-debug. Only `fs.read` is enabled (only
`read_allow` is populated). Cannot write, fetch, exec, or read env.

### A research / web-search agent

```toml
inherits = "secure-defaults"

[filesystem]
read_allow  = ["src/**", "docs/**"]
write_allow = ["/tmp/**"]

[network]
# The hosts the agent's WebSearch / WebFetch tools may actually
# reach. Listing them here is the policy-level constraint; Denyx
# checks every outbound URL against this list, regardless of which
# host-level tool name the call came from.
http_get_allow  = [
    "api.duckduckgo.com",     # default search backend
    "developer.mozilla.org",  # docs the agent may want to fetch
    "doc.rust-lang.org",
]

# Long-form `[tools.X]` entry: capabilities + routing hint. Bridges
# (e.g. examples/local_executor/local_mcp.py) read `backend_url` and
# tell the local model where to make the WebSearch call instead of
# leaving it to guess.
[tools.WebSearch]
capabilities   = ["net.http_get"]
backend_url    = "https://api.duckduckgo.com/?format=json&no_html=1&skip_disambig=1&q="
backend_method = "GET"
description    = "DuckDuckGo Instant Answer API (public, non-tracking, JSON)."

[tools]
WebFetch = ["net.http_get"]
```

Enables `fs.read`, `fs.write`, `net.http_get` — derived from the
populated sections. The agent searches via DuckDuckGo's Instant
Answer API (default; swap for a self-hosted SearxNG, Brave Search,
Tavily, etc. if you need broader coverage) and can fetch MDN /
rust-docs; it cannot reach anywhere else, regardless of what the
orchestrator asked for.

### An agent with a remote-API key, no leak

```toml
inherits = "secure-defaults"

[filesystem]
read_allow  = ["src/**"]
write_allow = ["/tmp/**"]

[network]
http_post_allow = ["api.openai.com"]

[environment]
local_only_vars = ["OPENAI_API_KEY"]
allow_vars      = ["PATH", "USER"]
```

Enables `fs.read`, `fs.write`, `net.http_post`, `env.read`. The local
model reads the key, calls the API, processes the response, writes
results — and the key never appears in any string the cloud
orchestrator sees.

## Where next

- [07-install.md](07-install.md) — install Denyx and dependencies.
- [08-quickstart.md](08-quickstart.md) — generate a policy and run a
  script in 5 minutes.
- [12-local-executor.md](12-local-executor.md) — the full agentic
  setup with a local model + cloud orchestrator.
- [agent-policy-spec.md](agent-policy-spec.md) — the portable spec for
  non-Denyx runtimes that want to consume the same TOML format.
