# Quickstart

> ← [Back to docs README](README.md)

Five minutes from "I have an agentic host" to "every effecting tool
call is gated by a TOML policy I control."

Assumes you've already followed [07-install.md](07-install.md) (so
`denyx` and `denyx-mcp` are on `$PATH` — typically via
`cargo install denyx-cli denyx-mcp`).

## 1. The fast path: let your agent set Denyx up for you

If you're already running **Claude Code** or **opencode**, the
fastest way to get Denyx wired into your project is to have the
agent do it. From the project directory you want to gate, paste the
[setup prompt](../examples/denyx-setup-prompt.md) as your first
message of a fresh session.

The agent will:

1. Detect your stack (Python / Node / Rust / Ruby / Go).
2. Run `denyx init --lang <detected>` and show you the generated
   `denyx.toml`.
3. Walk you through five questions about filesystem reads, network
   hosts, env vars, subprocess commands, and approval gates —
   editing `denyx.toml` as you answer.
4. Write a project-local MCP config (`.mcp.json` for Claude Code,
   `opencode.json` for opencode) that wires `denyx-mcp` into your
   project for future sessions.
5. Smoke-test by running an allowed read and a deliberately-denied
   read so you can see the gate fire.
6. Tell you what to commit to git (`denyx.toml`, optionally
   `.mcp.json`) and what not to.

Two-minute setup, project-specific, nothing in `~/.config/`,
nothing system-wide. After it finishes, restart your agent host
and every subsequent tool call goes through the policy gate.

The prompt itself is committed in the repo at
[`examples/denyx-setup-prompt.md`](../examples/denyx-setup-prompt.md);
it's safe to read end-to-end before pasting.

> **What if you're not running Claude Code or opencode?** Skip to
> §2 below for the manual walkthrough. The remaining sections of
> this quickstart (writing a script, running it, watching a denial,
> approval gates, MCP, policy inspection) apply to either path.

## 2. Or, do it manually

If you'd rather drive each step yourself, in the project directory
you want to play with:

```sh
cd ~/myproject
denyx init --lang python
# denyx: wrote denyx.toml (python). Review the file, then run with --policy denyx.toml.
```

The generated `denyx.toml` inherits `secure-defaults`, allows the Python
toolchain (`python3`, `pip`, `pytest`, `ruff`, ...), and explicitly blocks
git destructive operations and staging/qa/prod config files. Open it and
read it — the comments at the top explain what's already covered and
what you may want to extend.

If your project isn't Python, swap in `--lang node`, `ruby`, `rust`, or
`go`.

## 3. Write a tiny Starlark script

Create `count_lines.star`:

```starlark
content = fs.read("README.md")

def count_lines(text):
    n = 0
    for ch in text.elems():
        if ch == "\n":
            n += 1
    return n

print("README has", count_lines(content), "lines")
```

Two things to know about Starlark:

- It's the strict Python subset Bazel and Buck2 use. Loops, conditionals,
  and other control flow only work *inside `def`*.
- No imports, no f-strings. Use string concat or `.format()`.

The full notes are in `examples/local_executor/run_multistep.py`'s
`SYSTEM_PROMPT_TEMPLATE`, which is the same prompt the evaluation harness
gives a 7B model.

## 4. Run it

```sh
denyx run --policy denyx.toml count_lines.star
```

Expected:

```
README has 47 lines
```

The script's printed lines come out on stdout. Audit events go to stderr
by default — you'll see one `Allowed` event for the `fs.read`. To send
audit events to a file:

```sh
denyx run --policy denyx.toml --audit-log /tmp/audit.jsonl count_lines.star
tail -1 /tmp/audit.jsonl
# {"ts":"2026-05-05T07:50:00...","task_id":"count_lines.star","step":1,"capability":"fs.read","status":"allowed","detail":{"path":"...README.md","error":null}}
```

## 5. Watch a denial happen

Edit `count_lines.star` to read something the policy doesn't allow:

```starlark
secrets = fs.read("/etc/passwd")
print(secrets[:50])
```

Run:

```sh
denyx run --policy denyx.toml count_lines.star
echo "exit=$?"
```

You'll get a runtime denial:

```
denyx: policy violation: policy denies read on path "/etc/passwd": matches [filesystem].deny pattern
exit=2
```

`fs.read` itself is enabled (because `read_allow` is populated), so
the verifier lets the script through. The runtime gate then resolves
the path against the inherited `secure-defaults` deny list, sees
`/etc/passwd` matches, and rejects with exit 2.

Try the same script with a path that's not in any deny list but also
not in `read_allow` (e.g. `fs.read("/var/log/syslog")`) — you'll get
a similar runtime denial with the reason "not in
`[filesystem].read_allow`".

The exit codes:

| Code | Meaning                                          |
|------|--------------------------------------------------|
| 0    | Script ran successfully                           |
| 1    | Starlark eval error (parse, name, runtime)        |
| 2    | Policy violation at runtime                       |
| 3    | Pre-execution verifier rejection                  |
| 4    | Confirm hook denied                               |
| 5    | I/O or configuration error                        |
| 6    | Runtime cap exceeded (wall-time / call-stack)     |

## 6. Try a confirm-prompted capability

Edit your `denyx.toml`:

```toml
requires_approval = ["fs.delete"]

[filesystem]
delete_allow = ["/tmp/denyx_quickstart_*"]
```

(`fs.delete` is auto-derived from the populated `delete_allow`; no
separate `[functions]` declaration needed.)

Make a throwaway file and a script:

```sh
touch /tmp/denyx_quickstart_demo
cat > delete_demo.star <<'EOF'
fs.delete("/tmp/denyx_quickstart_demo")
print("deleted")
EOF
denyx run --policy denyx.toml delete_demo.star
```

In a TTY, you'll see:

```
[denyx] confirm fs.delete for task delete_demo.star: delete /tmp/denyx_quickstart_demo
        allow? [y/N]
```

Type `y` and the script proceeds. Type `n` (or just press Enter) and
the script fails with exit code 4.

In CI / non-TTY, the default confirm hook is `DenyAllConfirm` — same
script would fail with exit code 4 unless you pass `--yes` to override.

## 7. Run without a policy file (loud-and-safe fallback)

```sh
denyx run /tmp/random.star
```

Denyx prints a stderr banner explaining that no `--policy` was provided,
so it's using the built-in `secure-defaults` baseline alone — which has
**no allow lists**, so every effecting capability fails. Pure
computation and `print()` still work:

```sh
echo 'print("hello", 1 + 2)' > /tmp/safe.star
denyx run /tmp/safe.star
```

prints `hello 3`. Useful for quick experiments where you want guarantee-
nothing-effecting behavior.

## 8. The MCP server (manual hand-test)

The same enforcement is available over MCP (JSON-RPC 2.0 on stdio).

```sh
mkdir -p ./.denyx
denyx-mcp --policy denyx.toml --audit-log ./.denyx/audit.jsonl
# stays running, reads JSON-RPC requests from stdin
```

> **Why `--audit-log` is mandatory in any non-toy use of
> `denyx-mcp`**: without it, the server defaults to writing audit
> events to *stderr*, which the host (Claude Code / opencode)
> captures into its own MCP-server log directory, mixed in with
> every other MCP server's noise. From the operator's
> perspective, the audit feature looks broken — events are
> "going somewhere" but nowhere greppable. **Always pass
> `--audit-log <path>`** so events go to a file you can `tail
> -f` and `jq` against. `./.denyx/audit.jsonl` (gitignored —
> `echo '.denyx/' >> .gitignore`) is the recommended
> project-local default.

Most agentic hosts (Claude Code, opencode) talk to MCP servers
automatically once configured — see [09-claude-code.md](09-claude-code.md)
and [10-opencode.md](10-opencode.md) for the wiring (both
include `--audit-log` in their example configs).

For a hand test, you can speak the protocol manually:

```sh
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{}}}' | denyx-mcp --policy denyx.toml --audit-log ./.denyx/audit.jsonl
```

You'll get back the server's capability advertisement. The two methods
that matter operationally are `tools/list` and `tools/call`.

## 9. Inspect or validate the policy

Two CLI subcommands let you reason about a policy without running
anything against it:

```sh
denyx policy validate denyx.toml
# OK: denyx.toml parses, resolves, passes self-writable guard. 5 capability(ies) enabled.

denyx policy show denyx.toml
# (prints derived capabilities, every populated section, declared
# tools with routing hints, runtime caps, confirm-gated caps)
```

`policy validate` is a clean fit for CI: exit 0 ⇒ the policy is
loadable and won't trip the self-writable guard at runtime.
`policy show` is the answer to "what is my agent actually allowed
to do?" — it expands the inherited preset, surfaces every rule,
and lists the capability set derived from your resource sections.

## Where next

- [06-policy-file.md](06-policy-file.md) — full policy reference (you'll
  want this open while you trim the generated file).
- [12-local-executor.md](12-local-executor.md) — the agentic setup with a
  local 7B model + cloud orchestrator.
- [09-claude-code.md](09-claude-code.md) — Claude Code integration.
- [10-opencode.md](10-opencode.md) — opencode integration.
