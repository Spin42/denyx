# `doctor` reference

> ← [Back to docs README](README.md)

Both `denyx-mcp` and `denyx-local-mcp` ship a `doctor` subcommand —
read-only project preflight that inspects what's wired and prints
copy-pasteable next-steps for anything off. **They never auto-fix.**
Use them after running [`denyx host-config`](host-config.md), before
relying on the gate for non-trivial work, or when something looks off.

## Which binary do I run?

| You're using | Run |
|---|---|
| Standard MCP setup (Claude Code / opencode / Cursor / Copilot / Continue / Cline routed through `denyx-mcp`) | `denyx-mcp doctor` |
| The [local-executor flow](12-local-executor.md) (cloud orchestrator + small local 7B model under the gate) | `denyx-local-mcp doctor` |
| You don't know which | `denyx-mcp doctor` first; it tells you if the project is wired for the local-executor shape instead |

If you have both binaries installed, `denyx-local-mcp doctor` covers
a strict superset of `denyx-mcp doctor`'s project-side checks plus
the local-LLM stack inspection.

Both never modify anything; you can run them as often as you want.
**Exit codes:** `0` = OK, `1` = warnings, `2` = failures.

## `denyx-mcp doctor`

```
Read-only project preflight: inspects denyx.toml, host-config files,
audit-dir setup, .gitignore exclusion, and the host's built-in-tool
lockdown. Prints fix instructions for anything that's off; never
auto-fixes.
```

### Flags

| Flag | Default | Purpose |
|---|---|---|
| `--project-path <PATH>` | cwd | Project root to inspect. Pass a different path if running doctor from somewhere other than the project root. |

### What it checks

1. **`denyx.toml` presence and validity.** Missing is reported as INFO
   (the runtime falls back to the safe-by-design `secure-defaults`
   baseline). A present-but-invalid file is a failure.
2. **Host-config wiring.** For each detected host, whether the MCP
   server entry is present and points at `denyx-mcp` or
   `denyx-local-mcp`.
3. **Built-in-tool lockdown.** For Claude Code: whether
   `permissions.deny` covers `Bash`, `Read`, `Write`, `Edit`, `Glob`,
   `Grep`, `WebFetch`, `WebSearch`, `Monitor`, `NotebookEdit` (and
   `PowerShell` on Windows), plus whether `disableBypassPermissionsMode`
   is set. For opencode: whether `tools` disables built-ins and
   `permission` is deny-by-default with a `denyx*` allow.
4. **Audit-dir setup.** `./.denyx/` exists, is writable, and is in
   `.gitignore` (so audit logs don't end up committed).
5. **Self-write protection.** That neither `denyx.toml` nor the host
   config files are in the policy's `write_allow` (catching a
   misconfigured policy that would let the agent disable the gate).

### Sample run

```sh
$ denyx-mcp doctor
[OK]   denyx.toml present and valid
[OK]   .denyx/ exists and is in .gitignore
[OK]   .claude/settings.json — permissions.deny covers built-ins
[OK]   .mcp.json wires denyx-mcp with --policy ./denyx.toml
[INFO] opencode.json not present (skipping opencode checks)
[OK]   policy does not include denyx.toml in write_allow
exit 0
```

### When to run

- After `denyx host-config` to verify the wiring landed.
- Before opening a Claude Code / opencode session in a project for
  the first time.
- After updating Denyx itself, in case the binary moved or flag
  surface changed.
- In CI as a project-readiness check
  (`denyx-mcp doctor || exit $?`).

## `denyx-local-mcp doctor`

```
Run a read-only preflight check against the configured endpoint.
Probes the server, verifies models are available, flags Ollama
num_ctx pitfalls. Prints fix instructions on failure; never modifies
anything.
```

This binary's `doctor` covers everything `denyx-mcp doctor` does
*plus* the local-LLM stack: server fingerprinting, chat + embed
model availability, and the Ollama `num_ctx` truncation pitfall.

### Flags

| Flag | Default | Purpose |
|---|---|---|
| `--endpoint <URL>` | *(none — scan mode)* | OpenAI-compatible API base URL to verify. **Omit** to run in [scan mode](#scan-mode). |
| `--api-key <TOKEN>` | env `DENYX_LOCAL_API_KEY` | Bearer token, if the server requires auth. |
| `--model <ID>` | `qwen2.5-coder:7b` | Chat model id to verify is served. Only used in [targeted mode](#targeted-mode). |
| `--embed-model <ID>` | `nomic-embed-text` | Embed model id to verify is served and can produce a vector. Only used in targeted mode. |
| `--project-path <PATH>` | cwd | Project root to inspect (same as `denyx-mcp doctor`). |
| `--no-project` | *off* | Skip the project-side checks (policy file, host configs, audit dir, .gitignore). Useful when running `doctor` purely to verify a remote LLM endpoint. |

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
- **When you can't tell whether the gate is engaged.** The
  warn-vs-OK on the project-side checks distinguishes a wired
  bridge from a bypassed one.

## Decision matrix

| Question | Run |
|---|---|
| Is my local LLM stack working? | `denyx-local-mcp doctor` (scan mode) |
| Is my project gated by Denyx at all? | `denyx-mcp doctor` |
| Did I wire the local-executor bridge correctly? | `denyx-local-mcp doctor` (warns when standalone shape is wired instead) |
| Is the host's built-in deny list complete? | either |
| Is `denyx.toml` valid? | either |
| Does my remote OpenAI-compat endpoint serve `qwen2.5-coder:7b`? | `denyx-local-mcp doctor --endpoint <url> --no-project` |
| Is Ollama's `num_ctx` set high enough? | `denyx-local-mcp doctor --endpoint <url>` |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | All checks passed. |
| `1` | One or more warnings (WARN-level findings). The gate may still work; some configuration is non-ideal. |
| `2` | One or more failures (ERROR-level findings). The gate is unlikely to work as intended; fix before relying on it. |

The exit code makes doctor scriptable in CI:

```sh
denyx-mcp doctor || exit $?
```

## Common findings

| Finding | Meaning | Fix |
|---|---|---|
| `denyx.toml not present` | INFO — runtime uses `secure-defaults` baseline. | Run `denyx init` if you want a project-specific policy. |
| `denyx.toml: [filesystem].write_allow includes denyx.toml` | ERROR — agent could rewrite the policy. | Remove the entry; the runtime will refuse to load this policy anyway. |
| `.claude/settings.json: permissions.deny missing Read/Write/Bash` | WARN/ERROR — built-ins are not locked down; gate is bypassable. | Re-run `denyx host-config --host claude`. |
| `.mcp.json wires denyx-mcp without --audit-log` | WARN — events go to stderr where Claude Code buries them. | Re-run `denyx host-config` (always passes `--audit-log` explicitly). |
| `Ollama num_ctx = 2048 (recommended ≥ 8192)` | WARN — long Starlark programs will be silently truncated. | `export OLLAMA_CONTEXT_LENGTH=16384 && ollama serve`. |
| `embed model not found in /v1/models` | ERROR — the local-executor bridge can't compute embeddings. | `ollama pull nomic-embed-text`. |
| `wired denyx-mcp but local-executor expected` | WARN — the standalone shape is wired where the bridge was expected. | Re-run `host-config --no-mcp` and follow [12-local-executor.md](12-local-executor.md). |
| `audit-dir not in .gitignore` | WARN — audit logs may end up committed. | `echo .denyx/ >> .gitignore`. |

## See also

- [host-config.md](host-config.md) — what produced the wiring doctor
  inspects.
- [12-local-executor.md](12-local-executor.md) — the local-executor
  flow that `denyx-local-mcp doctor` is calibrated for.
- [09-claude-code.md](09-claude-code.md), [10-opencode.md](10-opencode.md)
  — per-host wiring details.
