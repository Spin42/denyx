# OWASP Agentic Top 10 — Denyx coverage report

> ← [Back to docs README](README.md)

This is an **empirical** scoring of how Denyx maps to the
[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/)
(ASI-01 through ASI-10), accompanied by concrete tests in
[`crates/host/tests/owasp_agentic.rs`](../crates/host/tests/owasp_agentic.rs)
that demonstrate the position. The report does not claim "10/10
covered" — Denyx is a single-process capability gate, not a
fleet-governance platform, and four of the ten risks are out of
scope by design.

| ASI | Risk | Denyx | Test |
|-----|------|-------|------|
| ASI-01 | Agent Goal Hijacking | **Mitigated** | `asi01_prompt_injection_style_script_is_denied_at_runtime_gate` |
| ASI-02 | Tool Misuse and Exploitation | **Strong** | 3 tests (`asi02_*`) |
| ASI-03 | Identity and Privilege Abuse | **Partial** | 2 tests (`asi03_*`) |
| ASI-04 | Agentic Supply Chain Vulnerabilities | Out of scope | — |
| ASI-05 | Unexpected Code Execution | **Strong** | 2 tests (`asi05_*`) |
| ASI-06 | Context Management and Retrieval Manipulation | Out of scope | — |
| ASI-07 | Insecure Inter-Agent Communication | Out of scope | — |
| ASI-08 | Cascading Failures | Out of scope | — |
| ASI-09 | Human-Agent Trust Exploitation | **Partial** | `asi09_requires_approval_with_deny_decision_blocks_capability` |
| ASI-10 | Rogue Agents | **Partial** | 2 tests (`asi10_*`) |

Tally: **2 strong, 4 mitigated/partial, 4 out of scope.** Denyx is
a tight local gate; the out-of-scope items belong to other layers
(agent mesh, identity, supply chain, SRE) that fleet-governance
platforms address via multi-agent infrastructure Denyx deliberately
doesn't include. Different unit of analysis, different coverage
profile.

---

## ASI-01 — Agent Goal Hijacking

> *"Attacker-controlled inputs (prompts, retrieved content, tool
> outputs, or messages) redirect an agent's goals or plan, causing
> harmful multi-step actions."*

**Denyx position: mitigated, not detected — stronger with local-executor.**
Denyx is a runtime gate, not a prompt firewall. It does not try to detect
when the agent's reasoning has been hijacked. Its claim is the inverse:
**enforcement is independent of intent.** Whether the agent sincerely wants
to read `/etc/passwd` or has been prompt-injected into wanting to, the
policy gate fires the same way.

Test: `asi01_prompt_injection_style_script_is_denied_at_runtime_gate`
runs a Starlark script with prompt-injection-style framing
(*"IGNORE PREVIOUS INSTRUCTIONS"*, *"admin mode"*, *"the user
authorised"*) that calls `fs.read("/etc/passwd")`. The runtime gate
denies the call with a typed `DenyxError::Policy`, regardless of
the framing.

**MCP tool definition poisoning** is a specific form of goal hijacking
where malicious instructions are embedded in a tool's name, description,
or schema so the model's reasoning is manipulated before it takes any
action. Coverage here depends on the deployment mode:

- **`denyx-local-mcp` (local-executor):** structural prevention. The cloud
  orchestrator sees only `delegate_to_local`; it never reads third-party
  MCP tool descriptions. The local executor model receives tool metadata
  only from the operator-controlled policy file. No poisoned description
  from any co-installed MCP server can reach either model's context.
- **`denyx-mcp` (direct):** blast-radius reduction only. The cloud model
  reads all MCP tool descriptions as usual. A poisoned description can
  manipulate reasoning; Denyx's gate still fires on the resulting actions,
  but the reasoning-layer manipulation is not detected.

**Limit:** in both modes, if the prompt injection (or tool poisoning) causes
the agent to choose an *allowed* action that's nonetheless harmful (e.g. a
write within `write_allow` that overwrites a build script), Denyx does not
detect that. The policy is the contract; hijacking can't expand the contract
but can misuse what the contract permits. Tightening `write_allow` is the
answer there.

---

## ASI-02 — Tool Misuse and Exploitation

> *"An agent misapplies legitimate tools (or is induced to do so),
> leading to exfiltration, destructive operations, workflow
> hijacking, or denial-of-wallet."*

**Denyx position: strong on the *action* surface; LLM-side
defenses are best-effort.** Three components carry the load:

1. **Capability gate** at every effecting builtin. Allowlist what
   the agent can use; everything else fails as a typed error.
2. **IFC** with transform-aware redaction (reverse, hex,
   single-byte XOR + hex(XOR), base64 std/url-safe, ROT-1..25,
   chunking detection) and arg-side denial at every outbound
   effect. The static-analysis variant in the verifier refuses
   the shape of "read a local-only value and then output it"
   before the script runs — a literal argument, or one resolvable
   via constant-folding of simple variable assignment/`+`-
   concatenation, with flow-sensitive tracking across the
   top-level statement sequence; the runtime variant scrubs /
   refuses values that flow through reads the static pass cannot
   resolve.
3. **Visibility classes** (`allow` / `local_only_*` / `deny_*`)
   per resource, used by the gates above.

The LLM-side `<task>` wrapping and system-prompt warning in
`denyx-local-mcp` are present but did not measurably reduce
injection obedience on the four local code models tested in
Round 2 (qwen 7B/14B, phi-4 14B, codestral 22B). The honest
framing is that the enforcement is on the script's runtime
behaviour, not on the LLM's reasoning — the model will obey the
injection, and the gates above catch what the obedient code tries
to do.

Tests:

- `asi02_direct_exfil_via_fs_read_is_denied` — forbidden
  `fs.read("/etc/passwd")` denied.
- `asi02_destructive_op_via_subprocess_force_push_is_denied` —
  `git push --force` blocked by `[subprocess.deny_args]` even
  though `git` is in `allow_commands`.
- `asi02_local_only_secret_refused_pre_exec_when_print_present` —
  the verifier's tainted-output-flow refusal.
- `tests/taint.rs` (`fs_local_only_read_redacts_in_printed_output`,
  `env_local_only_var_redacts_in_printed_output`, etc.) — the
  runtime redaction path for variable-arg reads.

**Empirical:** Round 2 (see
[security-pentest-r2-tool-poisoning.md](security-pentest-r2-tool-poisoning.md))
ran 80 step-injection / encoding-bypass / deny-by-default probes
across the four models and observed 0 literal or recovered
leaks. The sample is small and the probe set is hand-crafted; the
useful result from that round is the negative finding about the
LLM-side wrappers, not the positive headline.

**Limits:**

- The IFC transform set is finite by intent. Custom crypto,
  multi-byte XOR, encodings outside the documented set
  (base32, base85, ASCII85, etc.) are residual risk — see the
  Round 1 report and the threat model.
- The pre-exec analysis is bounded: it folds literals and simple
  variable/`+`-concatenation, and traces flow across top-level
  statements, but it does not do full data-flow analysis (no
  string formatting/slicing, no tracing across a `def`/`lambda`
  call boundary under a different name — a coarse whole-script
  fallback catches the latter at the cost of possible false
  positives). Reads it cannot resolve fall through to the runtime
  IFC, which has the same documented residual risk.
- Operator-side: too-broad `**` globs in `read_allow` defeat
  deny-by-default by construction. The narrowest allow-list is
  the operator's responsibility.

---

## ASI-03 — Identity and Privilege Abuse

> *"Agents misuse credentials, tokens, or inherited permissions
> to access systems or data beyond intended limits."*

**Denyx position: partial.**

What Denyx does have:
- **Reserved-env-var invariant** — `DENYX_AUTH_TOKEN`,
  `DENYX_TOKEN`, `DENYX_SERVER_TOKEN`, `DENYX_JWT`,
  `DENYX_API_KEY` are NEVER readable by the agent, even when a
  hostile or careless policy lists them in `allow_vars`. The
  invariant fires before allow_vars is consulted.
- **Per-env-var allow/deny** with deny winning over allow.
- **Subprocess env scrubbing** — child processes inherit a
  filtered env that excludes reserved Denyx names.

What Denyx does NOT have:
- An agent-identity layer. Denyx does not validate or sign
  outbound credentials presented by the agent to upstream
  services.
- Cryptographic agent credentials (an Ed25519- or ML-DSA-style
  identity layer that signs outbound calls). This is what
  fleet-governance platforms typically provide.
- Inherited-permission boundary enforcement on tokens issued
  to the agent — once a credential is in env or filesystem, the
  policy gate is the only thing keeping it from leaking.

Tests:

- `asi03_reserved_env_var_unreadable_even_when_explicitly_allowed`
  — a hostile policy lists `DENYX_AUTH_TOKEN` in `allow_vars`;
  the read is denied anyway.
- `asi03_denylisted_env_var_unreadable_even_when_listed_in_allow`
  — standard `deny_vars` precedence over `allow_vars`.

---

## ASI-04 — Agentic Supply Chain Vulnerabilities

> *"Tools, prompts, agents, models, and registries can be
> compromised or tampered with at build-time or runtime, and
> agentic systems often compose capabilities dynamically."*

**Denyx position: out of scope.**

Denyx gates what the agent's *outputs* can do; it does not gate
the agent itself. A tampered model produces tampered outputs,
which still hit the policy gate. The gate fires on those outputs
the same way it would on outputs from a clean model — so a
compromised model can't expand its own capabilities by tampering
itself, but Denyx does not detect the tampering.

Mitigations users should consider, layered with Denyx:
- Tooling-side: `cargo crev`, `cargo audit`, supply-chain
  scanners.
- Model-side: signed model artefacts, model registry attestation.
- Workflow-side: pin dependencies, review PRs, guard the build
  pipeline.

These belong to other tools. Denyx's contribution is keeping a
compromised agent from doing more than the policy permits — which
is the *blast-radius* property, not the *prevent-compromise*
property.

---

## ASI-05 — Unexpected Code Execution

> *"Agentic systems turn untrusted content or agent-generated
> output into executable behavior (shell commands, scripts,
> deserialization, templates), leading to compromise or sandbox
> escape."*

**Denyx position: strong.** Three layers at the language-runtime
gate, plus interpreter containment in the wasm sandbox.

1. **Command allowlist** — only listed binaries can spawn.
2. **Arg-side denial** — `[subprocess.deny_args]` matches
   substrings against the joined argv (so `git push --force`
   fails even though `git` is allowed).
3. **Path canonicalisation on argv** — paths in argv are resolved
   and checked against `read_allow`/`write_allow` so
   `cat ../../etc/passwd` doesn't slip past the gate via
   relative-path tricks.

**Interpreter containment (default in v0.4.0+; opt out with
`--no-wasm`):** the Starlark interpreter itself runs inside a
`wasmtime` linear-memory sandbox. A miscompilation or
memory-safety bug in `starlark-rust` stays contained at the wasm
boundary instead of corrupting the host address space. Defence-
in-depth, not a primary control. Empirically validated under
adversarial workload in the Round 2 v5 pentest (one `WASM_TRAP`
fire — Opus's quadratic string-concat caused the Starlark
interpreter to `process::abort` inside the wasm guest; the
sandbox contained the abort cleanly). See
[wasm-sandbox](wasm-sandbox.md) for the full parity table and
threat-model deltas.

**Note:** none of these layers isolate the *child process* a
permitted `subprocess.exec` starts. A permitted `python3` runs in
the host kernel — if it constructs paths inside its own heap that
the argv path-gate cannot see (e.g.
`python3 -c "open(chr(47)+'etc'+chr(47)+'passwd').read()"`),
ASI-05 coverage in v0.4.0 depends on `secure-defaults` denying
inline interpreters and the host being run inside a VM or
container. The legacy `[subprocess].sandbox = "bwrap"` field
addressed this on Linux but is deprecated in v0.4.0; see
[06-policy-file.md](06-policy-file.md#subprocess-is-a-privilege-boundary).

Tests:

- `asi05_unlisted_command_denied` — `bash -c id` blocked when only
  `echo` is in `allow_commands`.
- `asi05_path_traversal_in_subprocess_argv_denied` — `cat
  ../../etc/passwd` argv canonicalisation rejects.

**Limit:** the gate is for `subprocess.exec`. Starlark itself
intentionally does not have `eval`, `exec`, dynamic code loading,
or deserialisation — so the language-layer "code-from-content"
attack surface is constrained by language design, not just by
Denyx.

---

## ASI-06 — Context Management and Retrieval Manipulation

> *"Attackers corrupt stored/retrievable context (summaries,
> embeddings, memory) so future reasoning and tool use becomes
> biased or unsafe, including cross-session influence."*

**Denyx position: out of scope.**

Denyx is stateless per-script invocation. There's no embedding
store, no episodic memory, no retrieval layer — so there's
nothing to poison. Frameworks like LangChain, CrewAI, and
custom RAG stacks own this surface.

What Denyx contributes indirectly: if a poisoned context tries
to make the agent leak a secret, the IFC layer at the output
boundary still redacts. So the *blast radius* of a successful
context-poisoning attack is reduced. But Denyx does not detect
or prevent the poisoning itself.

---

## ASI-07 — Insecure Inter-Agent Communication

> *"Spoofing, intercepting, or manipulating agent-to-agent
> messages due to weak authentication or integrity checks."*

**Denyx position: out of scope.** Denyx governs one process. A
multi-agent mesh is a different unit of analysis.

A user running multiple Denyx-gated agents that talk to each
other gets per-agent local enforcement, but the inter-agent
channel itself (a message bus, a shared filesystem, an HTTP
endpoint between the agents) is governed by whatever the
agents are using to talk — not by Denyx.

---

## ASI-08 — Cascading Failures

> *"A single fault propagating across agents, tools, and
> workflows into system-wide impact."*

**Denyx position: out of scope.** Denyx has no SRE plumbing —
no circuit breakers, no SLO enforcement, no inter-agent
back-pressure. The audit log gives a human reviewer
**after-the-fact** visibility into a failure cascade, but does
not stop one in flight.

---

## ASI-09 — Human-Agent Trust Exploitation

> *"Abusing user trust and authority bias to get unsafe
> approvals or extract sensitive information."*

**Denyx position: partial.** The mechanism is `requires_approval`:
listed capabilities fire a `ConfirmHook` before the underlying
operation runs. The host caller decides what the hook does — CLI
prompt, MCP elicitation, or auto-deny.

The hardest-to-honour guarantee here is the **safe default when
no human is in the loop**. The MCP server's `auto` confirm mode
sends an `elicitation/create` request only if the client
advertises elicitation support; most clients (including Claude
Code 2.1.x in `-p` mode) don't yet. In that case, `auto` falls
back to **auto-deny**, NOT auto-allow. The runtime denies
correctly even when there's no UI to ask the human.

Test: `asi09_requires_approval_with_deny_decision_blocks_capability`
pins this. A `requires_approval` capability with a `Deny` hook
yields a typed error and the underlying file deletion does not
happen.

**Limit:** if the human is present and CAN be tricked into
approving (the social-engineering case), Denyx doesn't help.
That's not enforcement; that's UX. The CLI confirmation prompt
is plain-text and shows the capability + summary; users still
have to read it.

---

## ASI-10 — Rogue Agents

> *"Agents drifting or being compromised in ways that cause
> harmful behavior beyond intended scope."*

**Denyx position: partial.**

Two structural guarantees:

1. **Scope cannot be expanded mid-script.** The policy is loaded
   once and is immutable from the script's perspective. A "rogue"
   script that tries every capability hits the gate at each call
   independently — a denied call is not a "now in degraded mode,
   subsequent calls are easier" state.
2. **The audit log records all attempts.** SHA-256 hash-chained,
   tamper-detectable. A human reviewer reading the log sees the
   pattern of denied attempts that characterises a rogue agent.

What Denyx does NOT have:
- Anomaly detection. Denyx doesn't look at the rate or pattern
  of denied calls and trip an alarm.
- Kill switch. There's no out-of-band signal to stop a Denyx-gated
  process; the user kills the process the same way they'd kill
  any other. (For an MCP server, the client can drop the
  connection.)

Tests:

- `asi10_rogue_script_denied_independently_at_each_capability` —
  three forbidden capabilities tried in sequence; each is
  independently denied.
- `asi10_rogue_script_audit_records_attempts` — the JSONL audit
  sink records the denied attempt, so a human reviewer reading
  the log sees the rogue behaviour.

---

## Methodology and honest limits

- This report scores Denyx against the **ten OWASP risks as
  written**, not a paraphrase. The canonical text is at the link
  above; quotations are reproduced inline.
- "Strong" / "Mitigated" / "Partial" / "Out of scope" are author
  judgements with concrete tests behind them. Reasonable readers
  may downgrade some "Strong" to "Partial" on edge cases not
  covered by the test set; the corresponding tests are linked so
  the reader can read them and decide.
- Coverage is measured against a single Denyx-gated agent
  process. A Denyx deployment that includes a centralised policy
  + audit server (the optional server-mode MVP in `denyx-mcp`)
  does NOT change the per-agent coverage; centralisation buys
  consistency across agents, not new capability classes.
- "Out of scope" is a positive choice, not a gap. Denyx is a
  capability gate; it leaves agent-mesh, identity, supply chain,
  context, SRE, and human-UX to other layers. The scoring is
  honest about this rather than claiming coverage that isn't
  there.

## Where to next

- Review [`crates/host/tests/owasp_agentic.rs`](../crates/host/tests/owasp_agentic.rs)
  to see exactly what is and isn't covered.
- For the broader threat model, read
  [docs/04-security-threat-model.md](04-security-threat-model.md).
- For the empirical security toolbox (fuzz, exfil probe, AI
  pentest, mutation testing) that backs these claims, see
  the disclosure block in the [main README](../README.md).
