# `doctor` reference

> ← [Back to docs README](README.md)

Three binaries ship a `doctor` subcommand. **`denyx doctor` is the
canonical entry point** — single command for "is my Denyx setup
right?", with a `--fix` flag for mechanical auto-fixes. The two
binary-specific variants (`denyx-mcp doctor`, `denyx-local-mcp doctor`)
are narrower and exist because those binaries are sometimes the only
ones on `$PATH` — e.g. when Claude Code launches `denyx-mcp` from a
Lima VM or WSL2 distro. None of the three ever modifies anything
without explicit consent (`--fix` is interactive and refuses when
stdin isn't a TTY).

Use `denyx doctor` from a terminal. Use the binary-specific variants
from CI, from inside a host-managed launch context, or when only
that binary is installed.

## Which binary do I run?

| You're running from | Run | Why |
|---|---|---|
| A terminal in the project root | **`denyx doctor`** | Canonical entry. Project-side checks **plus** cross-cutting consistency checks. `--fix` available. |
| A host-managed launch context (Claude Code spawned `denyx-mcp` for you) where only `denyx-mcp` is on PATH | `denyx-mcp doctor` | Same project-side checks; no cross-cutting consistency, no `--fix`. |
| The [local-executor flow](12-local-executor.md) where the small local LLM stack is the relevant unknown | `denyx-local-mcp doctor` | Project-side checks **plus** local-LLM-server probing (scan + targeted). No cross-cutting consistency, no `--fix`. |

If you have all three binaries installed and you're at a terminal,
**default to `denyx doctor`**. Switch to `denyx-local-mcp doctor`
only when you specifically need the local-LLM stack probed.

**Exit codes** (all three binaries): `0` = OK, `1` = warnings, `2` = failures.

**Output language** (all three): `[OK]` / `[INFO]` / `[WARN]` / `[FAIL]`,
followed by a verdict line and copy-pasteable fix instructions.

## `denyx doctor` — canonical

```
Read-only project preflight: combines project_diagnosis (what files
exist, what's wired, lockdown state) with cross-cutting consistency
checks (policy ↔ host-config ↔ launch-flag ↔ project state). Single
entry point for "is my Denyx setup right?". Defaults to the cwd; pass
--project-path <PATH>.
```

### Flags

| Flag | Default | Purpose |
|---|---|---|
| `--project-path <PATH>` | cwd | Project root to inspect. Pass a different path if running doctor from somewhere other than the project root. |
| `--fix` | *off* | Apply mechanical fixes for issues that can be safely re-derived from the policy. **Interactive** — prints the fix plan and prompts for confirmation. **Refuses** when stdin isn't a TTY (CI-safe). See [auto-fix](#what---fix-actually-does). |

### What `denyx doctor` checks

Two layers, run in one pass:

1. **Project diagnosis** — same surface the binary-specific doctors
   inspect:
   - `denyx.toml` presence and validity (missing → INFO; runtime falls
     back to the safe-by-design `secure-defaults` baseline).
   - Per-host config wiring (`.mcp.json`, `.claude/settings.json`,
     `opencode.json`, `.cursor/mcp.json`, `.vscode/settings.json`,
     `.continue/config.json`).
   - Built-in-tool lockdown completeness on each detected host.
   - `./.denyx/` audit dir exists, is writable, and is in `.gitignore`.
   - Self-write protection — `denyx.toml` and host config files are
     not in the policy's `write_allow`.

2. **Cross-cutting consistency** — checks that span layers and
   neither binary-specific doctor can see, because they require both
   the policy and the host-config in one place:
   - **Policy ↔ host-config** — the policy file the host is launched
     with (`--policy <path>` in the MCP entry) is the same file the
     project's checked-in `denyx.toml` is. Catches stale or wrong
     `--policy` flags.
   - **Policy ↔ launch flags** — `--audit-log` in the MCP entry
     points to a path consistent with what the policy expects;
     `--policy-url` (team mode) is paired with the right local
     fallback.
   - **Sandbox stanza ↔ policy** — `.claude/settings.json`'s
     `allowedDomains` and `allowWrite` are derived from the current
     policy (not stale from a previous `host-config` run).
   - **Built-in deny ↔ host version** — Claude Code v2 additions
     (`Agent`, `Task*`, `Cron*`, etc.) are present in the deny list
     when v2 is the active version.

### What `--fix` actually does

`--fix` applies mechanical fixes for issues whose right answer is
derivable from the policy alone. **It never makes policy decisions.**

| Issue | Fix |
|---|---|
| `.denyx/` audit dir missing | `mkdir -p .denyx/` |
| `.gitignore` missing `.denyx/` line | append `.denyx/` |
| Stale sandbox stanza in `.claude/settings.json` | re-emit from the current policy via `host-config --existing replace` |
| Missing or partial built-in deny list in `.claude/settings.json` / `opencode.json` | re-emit the deny list from the current policy |

Issues that require **operator judgment** are **never** auto-fixed:

- Policy decisions: adding a host to `http_get_allow`, granting a new
  capability, expanding `read_allow`.
- Conflicting policy paths (the project has two policy files, or
  `--policy` points somewhere unexpected).
- Manual lockdown gaps (a Cursor session whose UI toggles haven't
  been flipped — Denyx can't write that from CLI).

Those remain in the post-fix report so you have to read and decide.

`--fix` is **interactive**: it prints the fix plan and waits for
`y/N`. If stdin isn't a TTY, it **refuses** and exits with the
diagnosis code unchanged — so CI invocations of `denyx doctor` are
read-only by default even with `--fix` accidentally passed.

### Sample run

```sh
$ denyx doctor
denyx doctor
[OK]   denyx.toml present and valid
[OK]   .denyx/ exists and is in .gitignore
[OK]   .claude/settings.json — permissions.deny covers built-ins
[OK]   .mcp.json wires denyx-mcp with --policy ./denyx.toml
[OK]   policy ↔ host-config consistent (same denyx.toml referenced)
[OK]   sandbox stanza derived from current policy
[INFO] opencode.json not present (skipping opencode checks)
[OK]   policy does not include denyx.toml in write_allow

Setup is ready.
exit 0
```

A degraded run with auto-fixable findings:

```sh
$ denyx doctor
[OK]   denyx.toml present and valid
[WARN] .denyx/ missing (audit log will be created on first call)
[WARN] .gitignore missing `.denyx/` line
[WARN] .claude/settings.json — sandbox stanza stale (allowedDomains
       does not match policy [network].http_get_allow)
[OK]   .mcp.json wires denyx-mcp
[OK]   policy ↔ host-config consistent

NOT ready. Apply the fixes above and re-run `denyx doctor`.
exit 1

$ denyx doctor --fix
[... same diagnosis ...]

Plan:
  [FIX] mkdir .denyx/
  [FIX] append `.denyx/` to .gitignore
  [FIX] re-emit sandbox stanza from policy

Apply the 3 auto-fixes above? [y/N]: y

  [FIX] mkdir .denyx/: created
  [FIX] append .gitignore: added line
  [FIX] re-emit sandbox stanza: rewrote .claude/settings.json#sandbox

Re-running diagnosis...
[OK]   .denyx/ exists and is in .gitignore
[OK]   sandbox stanza derived from current policy

Setup is ready.
exit 0
```

### When to run

- After `denyx host-config` to verify the wiring landed.
- Before opening a Claude Code / opencode session in a project for
  the first time.
- After updating Denyx itself, in case the binary moved or the flag
  surface changed.
- In CI as a project-readiness check (`denyx doctor || exit $?`).
  Don't pass `--fix` in CI — it'll refuse on stdin-not-TTY anyway,
  but explicit is better.

## `denyx-mcp doctor`

```
Read-only project preflight: inspects denyx.toml, host-config files,
audit-dir setup, .gitignore exclusion, and the host's built-in-tool
lockdown. Prints fix instructions for anything that's off; never
auto-fixes.
```

A subset of `denyx doctor`'s project-side checks. **Does not** run
the cross-cutting consistency checks. **Does not** have `--fix`.
Run this when only `denyx-mcp` is on `$PATH` — typically inside a
Lima VM or WSL2 distro that the Claude Code MCP entry uses to launch
the server.

### Flags

| Flag | Default | Purpose |
|---|---|---|
| `--project-path <PATH>` | cwd | Project root to inspect. |

### When to use it instead of `denyx doctor`

- The full `denyx` CLI isn't installed on the launch machine
  (you've only deployed `denyx-mcp` for the runtime).
- You're verifying the project from inside the same VM/distro the
  MCP server runs in, to catch path/visibility mismatches the host
  side can't see.
- A host-side script wants to confirm the gate is wired without
  shelling out to a different binary than the one the host
  launches.

## `denyx-local-mcp doctor`

```
Run a read-only preflight check against the configured endpoint.
Probes the server, verifies models are available, flags Ollama
num_ctx pitfalls. Prints fix instructions on failure; never modifies
anything.
```

Project-side checks **plus** the local-LLM stack: server
fingerprinting, chat + embed model availability, Ollama `num_ctx`
truncation pitfall. **Does not** run cross-cutting consistency.
**Does not** have `--fix`.

### Flags

| Flag | Default | Purpose |
|---|---|---|
| `--endpoint <URL>` | *(none — scan mode)* | OpenAI-compatible API base URL to verify. **Omit** to run in [scan mode](#scan-mode). |
| `--api-key <TOKEN>` | env `DENYX_LOCAL_API_KEY` | Bearer token, if the server requires auth. |
| `--model <ID>` | `qwen2.5-coder:7b` | Chat model id to verify is served. Only used in [targeted mode](#targeted-mode). |
| `--embed-model <ID>` | `nomic-embed-text` | Embed model id to verify is served and can produce a vector. Only used in targeted mode. |
| `--project-path <PATH>` | cwd | Project root to inspect (same as `denyx-mcp doctor`). |
| `--no-project` | *off* | Skip the project-side checks. Useful when running `doctor` purely to verify a remote LLM endpoint. |

### Scan mode

If `--endpoint` is omitted, doctor runs in **scan mode**: it probes
the standard local-LLM ports, lists what's running, and suggests a
copy-pasteable `serve` command.

Probed ports:

| Port | Stack |
|---|---|
| `11434` | [Ollama](https://ollama.ai) |
| `8080` | [llama.cpp server](https://github.com/ggerganov/llama.cpp) |
| `1234` | [LM Studio](https://lmstudio.ai) |
| `8000` | [vLLM](https://github.com/vllm-project/vllm) |
| `5000` | [Text Generation WebUI](https://github.com/oobabooga/text-generation-webui) |

```sh
$ denyx-local-mcp doctor
[OK]   detected Ollama on http://localhost:11434/v1 (version 0.4.2)
[INFO] no other local-LLM servers responding on standard ports
[INFO] re-run with --endpoint http://localhost:11434/v1 for targeted checks
[OK]   denyx.toml present and valid
[OK]   .claude/settings.json — permissions.deny covers built-ins
[WARN] .mcp.json wires denyx-mcp (standalone gate); local-executor
       bridge expected denyx-local-mcp wired via local_mcp.py.
       Re-run host-config with --no-mcp and follow
       docs/12-local-executor.md to wire the bridge.
exit 1
```

### Targeted mode

With `--endpoint` set, doctor verifies that specific server end-to-end:

```sh
denyx-local-mcp doctor \
    --endpoint http://localhost:11434/v1 \
    --model qwen2.5-coder:7b \
    --embed-model nomic-embed-text \
    --project-path /path/to/myproject
```

Targeted-mode checks:

- **Server fingerprint** — Ollama version detected (via
  `/api/version`), or generic OpenAI-compat fallback.
- **Chat model presence** — `--model` is in `/v1/models`.
- **Embed model presence** — `--embed-model` is in `/v1/models`.
- **Round-trip embed call** — POST `/v1/embeddings` returns a vector
  of expected dimension.
- **Ollama `num_ctx`** — for Ollama, reads `/api/show` and **warns
  when `num_ctx` < 8192**. Many setups inherit a 2048 default that
  silently truncates the prompt mid-Starlark, producing parse errors
  whose root cause is the context window, not the model. The fix is
  to set `OLLAMA_CONTEXT_LENGTH=16384` in the environment running
  Ollama, or to declare a model with a larger `num_ctx` parameter.
- **Project-side checks** — same as `denyx-mcp doctor`, with a key
  difference: wiring `denyx-local-mcp` is treated as "good"
  (the local-executor shape) and wiring only `denyx-mcp` is a WARN
  ("local-executor is being bypassed").

### LLM-only mode (`--no-project`)

```sh
denyx-local-mcp doctor --endpoint http://api.openai.com/v1 --no-project
```

Skips every project-state check; just verifies the endpoint /
models / embed round-trip. Useful when:

- Validating a remote OpenAI-compatible endpoint that won't be
  paired with a Denyx-gated project on this machine.
- Running from a non-project directory.
- CI smoke-test of the LLM stack independently of any project.

### When to run

- **Before relying on the local-executor flow.** A 30-second
  preflight beats a 30-minute eval run that fails because Ollama's
  `num_ctx` was 2048.
- **After installing or upgrading Ollama / llama.cpp / etc.**
- **When `delegate_to_local` produces parse errors.** Most likely
  cause is `num_ctx` truncation, which doctor flags directly.
- **When you can't tell whether the bridge is engaged.** The
  warn-vs-OK on the project-side checks distinguishes a wired
  bridge from a bypassed one.

## Startup blocking — the MCP servers refuse to serve when inconsistent

`denyx-mcp` and `denyx-local-mcp` run the same cross-cutting
consistency check on **every startup**, against the freshly-loaded
policy (whether from `--policy <file>` or `--policy-url <url>`). If
any `Critical`-severity issues are found, the MCP server enters
**blocked mode** instead of starting normally.

This catches the team-mode failure pattern the centralised-policy
shape introduces: a developer's machine fetches an updated policy
from the server but the local host-config files (`.claude/settings.json`,
`opencode.json`, …) are stale from the last `denyx host-config` run,
and the gate would silently operate against an inconsistent surface.
It also catches the local-edit equivalent: someone edits `denyx.toml`,
forgets `denyx host-config`, restarts the host.

### What blocked mode looks like

The MCP server stays alive (the host doesn't see a crashed process),
but:

- **`tools/list` advertises only one tool: `denyx_blocked`**, whose
  description tells the agent to surface the inconsistency to the
  user verbatim before doing anything else. Hosts pass tool
  descriptions to the model on every turn, so the model sees the
  message immediately — no tool call required.
- **`tools/call` for any tool name** (`denyx_run`, `denyx_fs_read`,
  `denyx_blocked` itself, `delegate_to_local` on the bridge, …)
  returns a structured payload with `isError: true`,
  `denyx_error_kind: "blocked_startup"`, and the full list of
  Critical issues + their fix instructions.
- **Stderr mirrors the message** prefixed `denyx-mcp: ` per line, so
  `claude --mcp-debug` and host log panels surface it.

The model has **no path to a real capability** until the operator
fixes the inconsistency and restarts the host.

### Resolving a blocked startup

```sh
denyx doctor --fix
# … apply the auto-fixes, fix any operator-judgment issues manually …
# … then restart Claude Code / opencode / Cursor / etc.
```

The fix path is the same as for any other `denyx doctor` finding —
the `--fix` flag handles mechanically re-derivable issues
(re-emitting the sandbox stanza, refreshing the deny list, creating
the audit dir) and prints manual instructions for everything else.

### First-run guard

If the project has **no host-config files at all** (`.mcp.json`,
`opencode.json`, etc. all absent), the consistency check is skipped
— there's nothing to be inconsistent with. This keeps the first
`denyx-mcp` startup before `denyx host-config` has been run from
locking itself out.

### Visibility caveat by host

| Host | Model sees the block | Why |
|---|---|---|
| Claude Code | ✅ strong | Built-in deny list + only Denyx tools available; `denyx_blocked` is the only tool that exists. |
| opencode | ✅ strong | `permission` block whitelists `denyx*`; same effect. |
| Continue | ✅ strong | `tools: []` empty allowlist; same effect. |
| Cursor / Copilot / Cline | ⚠ partial | Built-in tools (Read/Edit/Bash) are still available, so the model could route around `denyx_blocked` and use those instead. The user still sees the message via the tool description if the model lists tools, but enforcement leaks. See [14-other-hosts.md](14-other-hosts.md) for the underlying lockdown gap. |

If your threat model treats the block as load-bearing, use a host
with strong lockdown.

## Decision matrix

| Question | Run |
|---|---|
| **Is my whole Denyx setup right (default question)?** | `denyx doctor` |
| Is the policy I checked in actually the one the MCP entry launches with? | `denyx doctor` (cross-cutting) |
| Is my project gated by Denyx at all? | any of the three |
| Did I wire the local-executor bridge correctly? | `denyx-local-mcp doctor` |
| Is my local LLM stack working? | `denyx-local-mcp doctor` (scan mode) |
| Is `denyx.toml` valid? | any of the three |
| Does my remote OpenAI-compat endpoint serve `qwen2.5-coder:7b`? | `denyx-local-mcp doctor --endpoint <url> --no-project` |
| Is Ollama's `num_ctx` set high enough? | `denyx-local-mcp doctor --endpoint <url>` |
| Apply the mechanical fixes I just got told about | `denyx doctor --fix` (only `denyx` has it) |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | All checks passed. |
| `1` | One or more warnings (WARN-level findings). The gate may still work; some configuration is non-ideal. |
| `2` | One or more failures (ERROR-level findings). The gate is unlikely to work as intended; fix before relying on it. |

The exit code makes doctor scriptable in CI:

```sh
denyx doctor || exit $?
```

`--fix` does not change the exit code semantics — after fixes are
applied, doctor re-runs the diagnosis and the final exit code
reflects the post-fix state.

## Common findings

| Finding | Meaning | Auto-fixable by `denyx doctor --fix`? |
|---|---|---|
| `denyx.toml not present` | INFO — runtime uses `secure-defaults` baseline. | No (operator decision). Run `denyx init` to generate one. |
| `denyx.toml: [filesystem].write_allow includes denyx.toml` | ERROR — agent could rewrite the policy. | No (operator decision). Remove the entry; the runtime refuses to load this policy anyway. |
| `.claude/settings.json: permissions.deny missing Read/Write/Bash` | WARN/ERROR — built-ins not locked down. | **Yes** — re-emits from policy. |
| `.claude/settings.json: sandbox stanza stale` | WARN — `allowedDomains`/`allowWrite` don't match current policy. | **Yes** — re-emits from policy. |
| `.mcp.json wires denyx-mcp without --audit-log` | WARN — events go to stderr. | No (re-run `denyx host-config`). |
| `policy ↔ host-config: --policy points to /tmp/old.toml` | WARN/ERROR — host launches with stale policy. | No (operator decision). Re-run `denyx host-config`. |
| `Ollama num_ctx = 2048 (recommended ≥ 8192)` | WARN — long Starlark programs truncated. | No. `export OLLAMA_CONTEXT_LENGTH=16384 && ollama serve`. |
| `embed model not found in /v1/models` | ERROR — bridge can't compute embeddings. | No. `ollama pull nomic-embed-text`. |
| `wired denyx-mcp but local-executor expected` | WARN — standalone shape wired where the bridge was expected. | No. Re-run `host-config --no-mcp` and follow [12-local-executor.md](12-local-executor.md). |
| `audit-dir not in .gitignore` | WARN — audit logs may end up committed. | **Yes** — appends `.denyx/`. |
| `.denyx/ missing` | WARN — audit dir doesn't exist. | **Yes** — `mkdir`. |
| `local-executor isolation broken` | WARN — a host-config wires `denyx-local-mcp` alongside another MCP server (or `denyx-mcp`), so the cloud model can see that server's tool descriptions directly — defeating the local-executor's tool-poisoning isolation. Added after [Round 3](security-pentest-r3-argv0-and-chunking.md) confirmed this precondition still isn't enforced by `denyx host-config`. | No (operator decision). Remove the other server, split it into its own host-config file, or re-run `denyx host-config --strict-mcp`. |

## See also

- [host-config.md](host-config.md) — what produced the wiring doctor
  inspects.
- [12-local-executor.md](12-local-executor.md) — the local-executor
  flow that `denyx-local-mcp doctor` is calibrated for.
- [09-claude-code.md](09-claude-code.md), [10-opencode.md](10-opencode.md)
  — per-host wiring details.
