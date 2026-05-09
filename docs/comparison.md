# Denyx and the agent-safety landscape

> ← [Back to docs README](README.md)

This page exists because evaluating Denyx without knowing the field is
unfair to both sides. Below is an honest survey of adjacent tools —
open-source and commercial — grouped by *what kind of thing they are*,
followed by where Denyx actually sits and when **not** to use it.

The tools below are inventoried as of May 2026; the field moves fast,
so check release notes before betting on any specific feature claim.
This doc focuses on **what each tool's enforcement model is** and
**which Denyx properties it does or doesn't share**, not on feature
checklists. The five Denyx properties used as comparison axes:

1. **Per-value capability tier** with a "use but don't leak" level
   (`local_only_*` in Denyx's policy).
2. **Output-boundary redaction beyond regex** — scrubbing tainted
   values *and their encoded forms* (hex, base64, XOR, ROT-N,
   subsequence chunks) from stdout / audit / tool results.
3. **Cross-host policy translation** — one source-of-truth file
   produces the right config for Claude Code, opencode, Cursor,
   Copilot, Continue, Cline.
4. **Tamper-evident audit** — hash-chained or signed per-action log
   verifiable post-hoc, not just append-only trace storage.
5. **MCP-layer enforcement** — gating tool calls at the MCP boundary
   so any MCP-aware host can plug in.

## Coding-agent host built-ins (what Denyx wires *into*)

Every modern coding agent ships its own permissions layer. These are
real and useful — Denyx supplements them rather than replacing them
(`denyx host-config` writes both Denyx's MCP wiring *and* the host's
deny lists from the same `denyx.toml`).

- **[Claude Code](https://docs.claude.com/en/docs/claude-code)** —
  `settings.json` with `permissions.allow` / `deny` / `ask` arrays;
  rules like `Bash(npm run *)`, `Read(./src/**)`, `WebFetch(domain:...)`,
  `mcp__server__tool`. Deny precedence; first-match. Claude Code v2
  added an OS sandbox stanza (bubblewrap on Linux, Seatbelt on macOS).
  Closest in spirit to Denyx's filesystem section; no value-tier, no
  cross-host translation, no tamper-evident audit.
- **[Cursor](https://cursor.com/docs/reference/permissions)** —
  `~/.cursor/cli-config.json` and per-project `.cursor/cli.json` with
  allow/deny arrays for `Shell()`, `Read()`, `Write()`, plus an MCP
  server allowlist. UI toggles for built-in tools; no project-local
  deny mechanism for them.
- **[opencode](https://opencode.ai/docs/permissions/)** — `opencode.json`
  with a `permission` block keyed by tool name (`read`, `edit`, `bash`,
  `webfetch`, `external_directory`) → `allow` / `ask` / `deny`. Last-
  matching-rule semantics. The cleanest shape of the open-source hosts;
  Denyx wires the built-ins *off* via `tools: false` and a
  `"*": "deny" + "denyx*": "allow"` whitelist.
- **[Cline](https://docs.cline.bot/features/auto-approve)** /
  **[Continue](https://docs.continue.dev/cli/tool-permissions)** /
  **[Aider](https://aider.chat/docs/config/options.html)** — all three
  have category-level auto-approve toggles. Continue's `tools: []`
  empty-allowlist is the only one that approaches a project-local
  lockdown; Cline and Aider are click-per-call or `--yes-always`.
- **[GitHub Copilot agent mode](https://docs.github.com/en/copilot/reference/copilot-allowlist-reference)**
  — org-managed firewall allowlist for the cloud agent VM, plus
  per-repo MCP server allowlist (VS 2026). Cloud-side, not in-process.

**The pattern across all of them:** allow / deny / ask glob lists
with deny precedence. None offer a value-level "use but don't leak"
tier; none translate to other hosts; none ship hash-chained audit.
That's the niche `denyx host-config` fills — see
[host-config.md](host-config.md) for the translation table.

## MCP-layer scanners and gateways

These sit between the agent and an MCP server, scanning or proxying.

- **[Invariant mcp-scan](https://github.com/invariantlabs-ai/mcp-scan)**
  (now repackaged as **Snyk agent-scan**) — open-source. Two modes:
  static scan of installed MCP servers for prompt-injection / tool-
  poisoning / cross-origin shadowing, plus a runtime *proxy* mode with
  PII detection, secrets detection, tool restrictions, custom rules
  (`~/.mcp-scan/guardrails-config.yml`). Tool Pinning (hash tools to
  detect rug-pulls) is a notable feature. **MCP-layer enforcement: ✅.
  Tamper-evident audit: ✗. Value-tier IFC: ✗** (PII regex only).
- **[Snyk Agent Scan / Skill Inspector](https://snyk.io/blog/snyk-vercel-securing-agent-skill-ecosystem/)**
  — commercial layer over the mcp-scan core; auto-discovers across
  Claude Code, Claude Desktop, Cursor, Gemini CLI, Windsurf. Supply-
  chain framing; not a runtime policy gate in the Denyx sense.
- **[Lasso Security](https://www.lasso.security/)** — commercial
  agentic-AI security platform; runtime protection at proxy/API/AI
  Gateway layer. Released an open-source MCP Gateway. Intent-aware
  policies, RBAC, DLP. None of the (1)-(5) properties documented as
  shipping features.
- **[MCPX (Lunar.dev)](https://www.lunar.dev/post/the-best-open-source-mcp-gateways-in-2026)**,
  **Microsoft MCP Gateway for Kubernetes**, **Obot**, **ContextForge**,
  **MintMCP** — open-source MCP gateways. Pattern is consistent: authn,
  authz, rate limiting, observability, sometimes RBAC. None advertise
  value-tier IFC, hash-chained audit, or cross-host config translation.

**Where Denyx differs:** Denyx is the MCP server, not a proxy in front
of one. The gate is in-process with the runtime that interprets the
agent's code (Starlark), so the policy check happens *before* the
syscall, with both verifier-pass and audit-emit paths in one place.
Proxies catch the call after the model has emitted it; Denyx's
verifier rejects the source before evaluation begins.

## LLM guardrail frameworks

Mostly content-classifier shape: detect patterns in input/output text.

- **[NVIDIA NeMo Guardrails](https://github.com/NVIDIA-NeMo/Guardrails)**
  — open-source. Colang-defined input / dialog / retrieval / execution
  / output rails. Targets jailbreaks, topical drift, content safety —
  not capability gating. Sub-80ms claim.
- **[Guardrails AI](https://github.com/guardrails-ai/guardrails)** —
  open-source. `Guard` wrapper + validators (PII, toxicity, schema).
  Same shape: classifier framework.
- **[Llama Firewall](https://meta-llama.github.io/PurpleLlama/LlamaFirewall/)**
  — Meta. PromptGuard 2 (DeBERTa, 86M) + AlignmentCheck (Llama 4) +
  CodeShield (Semgrep on generated code). Production at Meta; >90%
  attack-success reduction on AgentDojo.
- **[Lakera Guard](https://www.lakera.ai/lakera-guard)** — commercial,
  acquired by Check Point Sept 2025. Single-API endpoint, classifier-
  style, sub-50ms.
- **[Protect AI LLM Guard](https://github.com/protectai/llm-guard)** /
  **[Rebuff](https://github.com/protectai/rebuff)** — open-source MIT,
  35+ scanners for input/output (PII anonymisation, secret redaction,
  prompt-injection detection).
- **[CalypsoAI](https://calypsoai.com/inference-platform/)** /
  **[Robust Intelligence (Cisco AI Defense)](https://www.cisco.com/site/us/en/products/security/ai-defense)** /
  **[HiddenLayer](https://www.hiddenlayer.com/platform)** — commercial
  platforms. Network-proxy or endpoint enforcement; classifier-based.
- **[Promptfoo](https://www.promptfoo.dev/docs/red-team/guardrails/)** —
  primarily eval/red-team; enterprise tier adds Adaptive Guardrails
  (input policies derived from failed scans).

**Where Denyx differs:** Denyx is not a content classifier. It does
not score whether a request "looks malicious"; it answers whether the
*action* the model is about to take is in the policy. Both are useful
and complementary. A team running Lakera in front of the model can
also run Denyx behind the agent; one filters intent in natural
language, the other gates capability calls in code.

## Information-flow control / capability research

This is the slice closest to Denyx's `local_only_*` tier — but mostly
research, not productised.

- **[CaMeL](https://arxiv.org/abs/2503.18813)** (DeepMind, "Defeating
  Prompt Injections by Design") — Privileged LLM (planner) + Quarantined
  LLM (handles untrusted data) + custom Python interpreter that enforces
  IFC on every value. Each value carries capability metadata. 77% on
  AgentDojo with provable security. Authors note the user has to
  codify the policies.
- **[FIDES](https://arxiv.org/abs/2505.23643)** (Microsoft Research,
  May 2025) — formal IFC model for agent planners; confidentiality and
  integrity labels with dynamic taint tracking; "selective hiding" swaps
  tool results for opaque variable references when appending them would
  raise the security label.
- **[NeuroTaint](https://arxiv.org/abs/2604.23374)** — extends taint
  propagation to semantic transformation, causal influence, cross-
  session memory. Outperforms FIDES on source-sink propagation. Offline.
- **[StruQ + SecAlign](https://bair.berkeley.edu/blog/2025/04/11/prompt-injection-defense/)**
  (Berkeley) — model fine-tuning defence; structured prompt vs data
  channels. Model-level, not gate-level.
- **[Spotlighting](https://arxiv.org/abs/2403.14720)** (Microsoft) —
  prompt-engineering family (delimiting, datamarking, encoding) marking
  input provenance. Reduced GPT attack-success from >50% to <2% in the
  paper's setup.

**Where Denyx differs:** Denyx is the closest *productised* analogue to
CaMeL's value-capability idea. The `local_only_*` tier on filesystem
reads, network hosts, and environment variables marks values as
tainted; the [output-boundary redactor](04-security-threat-model.md)
scrubs them and their encoded forms (byte-reverse, hex, single-byte
XOR, hex(XOR) compositions, base64, ROT-N, per-character chunking)
from stdout, audit payloads, and MCP tool results. The transform set
is not exhaustive — a script-generated key (AES, RC4, custom invertible
permutation) escapes — but it raises the floor well above regex
secret scanning. See
[examples/local_executor/run_exfil.py](../examples/local_executor/run_exfil.py)
for the empirical 12-technique probe (0 LEAK / 3 WEAK_LEAK / 9
REDACTED).

## Tamper-evident audit peers

Hash-chained or signed per-action audit, the rare slice.

- **[OpenFang](https://www.openfang.sh/)** — open-source Rust agent OS,
  ~32 MB. SHA-256 Merkle hash-chain over typed actions (ToolCall,
  ToolResult, FileWrite, FileRead, NetworkRequest, ShellExec,
  SecretAccess, ConfigChange). Plus WASM dual-metered sandbox, Ed25519
  manifest signing, taint tracking, secret zeroization, prompt-injection
  scanner. Closest functional analogue to Denyx's audit shape — but
  pitched as a full agent OS, not a gate.
- **[nono](https://nono.sh/)** — kernel-level isolation (Landlock /
  Seatbelt / Windows). **Sigstore-backed signing of instruction files**
  (CLAUDE.md, SKILLS.md). **Merkle-tree-committed session logs** with
  optional DSSE attestations verified by `nono audit verify`. Targets
  Claude Code specifically. Early alpha per their docs.
- **[Pipelock](https://github.com/luckyPipewrench/pipelock)** —
  Apache-2.0 Go binary, ~20 MB, May 2026. Inline MCP/HTTP/A2A proxy
  with capability separation between processes (agent has secrets but
  no network; Pipelock has network but no secrets) and **signed
  receipts plus mediation metadata**. 11-layer scan pipeline; DLP with
  48 credential patterns + checksum validators (Luhn, mod-97, ABA, WIF).
- **[Microsoft Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit)**
  — open-source MIT, April 2026. Sub-millisecond p99 governance latency.
  Maps explicitly to all 10 OWASP Agentic Top-10 risks. Capability
  sandboxing + DID identity + **Ed25519 plugin signing** + execution
  rings + Cross-Model Verification Kernel for memory poisoning. Ships
  in Python, TypeScript, .NET, Rust, Go SDKs. Closest *policy-engine*
  peer; no documented value-tier IFC or hash-chained per-action runtime
  audit.
- **[draft-sharif-agent-audit-trail (IETF)](https://datatracker.ietf.org/doc/draft-sharif-agent-audit-trail/)**
  — internet-draft for hash-chained audit (RFC 8785 canonicalization)
  with optional ECDSA signatures, motivated by EU AI Act Article 12.
- **[Sigstore A2A](https://github.com/sigstore/sigstore-a2a)** —
  keyless OIDC signing of Agent Cards; SLSA provenance; Rekor entries.
  Supply-chain provenance, not per-action audit.
- **[LangSmith](https://www.langchain.com/langsmith)** /
  **[Langfuse](https://langfuse.com/)** /
  **[Helicone](https://helicone.ai/)** — observability platforms. None
  publicly claim cryptographic / hash-chained audit; they are trace
  stores. Helicone has been in maintenance mode since 3 March 2026.

**Where Denyx differs:** Denyx's audit ([06-policy-file.md](06-policy-file.md))
is SHA-256-chained per event with `denyx audit verify` for post-hoc
detection of tampering, removal, or insertion. Closest peer set is
OpenFang / nono / Pipelock; none of those combine the audit with the
cross-host config translator and the value-tier IFC the way the
default Denyx setup does.

## Code-execution sandboxes

Different shape: these isolate processes; they don't enforce a policy.

- **[E2B](https://github.com/e2b-dev/E2B)** — Firecracker microVMs,
  ~150ms cold start. Pure isolation primitive.
- **[Daytona](https://github.com/daytonaio/daytona)** — Docker / Kata /
  Sysbox; pivoted Feb 2025 from devenvs to AI-code-execution.
- **[Modal Sandboxes](https://modal.com/docs/guide/sandboxes)** —
  gVisor-based.
- **[Cloudflare Sandbox / Dynamic Workers](https://developers.cloudflare.com/sandbox/)**
  — V8 isolate, ms-startup; April 2026 GA.
- **[Microsoft Hyperlight Wasm](https://github.com/hyperlight-dev/hyperlight-wasm)**
  — micro-VM, 1-2 ms startup.

**Complementary to Denyx, not competing.** A Denyx-gated agent inside
an E2B sandbox is strictly stronger than either alone: the sandbox
contains kernel-level escape, Denyx prevents the agent from issuing
disallowed effects in the first place. The Linux-only `bwrap` mode in
Denyx ([04-security-threat-model.md](04-security-threat-model.md))
is the in-tree equivalent.

## Generic policy engines

Bolted onto LLM endpoints by some teams.

- **[Open Policy Agent (OPA)](https://www.openpolicyagent.org/)** —
  Rego rules; commonly placed in front of LLM endpoints.
- **[Cerbos](https://www.cerbos.dev/features-benefits-and-use-cases/agentic-authorization)**
  — open-core authz; YAML policies; sub-ms decisions. Pitches "non-
  human identities under one policy decision model."
- **[Pomerium](https://www.pomerium.com/secure-ai-agent-access/control-agentic-sprawl)**
  — identity-aware access proxy.

**Where Denyx differs:** these are RBAC/ABAC engines applied to AI
contexts. They answer "is this identity allowed to call this endpoint?"
Denyx answers "is this *value* allowed to flow to this *sink*?" — a
different question with different machinery.

## Where Denyx sits

The combination Denyx ships that no surveyed tool combines as of
May 2026:

1. **`local_only_*` value tier** with output-boundary redaction across
   encoded forms — the only productised IFC-style "use but don't leak"
   I found. CaMeL and FIDES are research; Pipelock has process-level
   capability separation but not value-level tiering.
2. **Cross-host policy translation** via `denyx host-config` — one
   `denyx.toml` becomes Claude Code's `settings.json` deny list,
   opencode's `permission` + `tools` block, Cursor's `.cursor/mcp.json`,
   Copilot's `.vscode/settings.json`, Continue's `.continue/config.json`,
   Cline's stderr snippet. Not found anywhere else. See
   [host-config.md](host-config.md).
3. **SHA-256-chained tamper-evident audit** with `denyx audit verify`
   post-hoc — rare but not unique (OpenFang, nono, Pipelock peers).
4. **MCP server + standalone CLI + embeddable Rust crate** from one
   workspace — fits both "drop into Claude Code" and "use as a CI gate
   without any host" without forcing one integration model.
5. **Capability builtins under a Starlark substrate**, with policy as
   parsed config (NOT Starlark-as-policy). The agent can't emit code
   that mutates the policy because the policy is data the model
   doesn't see and the runtime doesn't expose mutation primitives.

The honest counter-positioning: if your threat model is "block specific
bad commands," the host built-ins are sufficient and Denyx is overkill.
If it's "the agent can use credentials and vendor responses without
those values bubbling up to the chat / logs / a prompt-injected exfil
request, and I want the audit log to be tamper-evident across a team" —
that's the slice Denyx fills.

## When NOT to use Denyx

- **You need OS-level isolation as the primary boundary.** Denyx is
  language-runtime enforcement plus optional `bwrap` on Linux. If you
  need namespace / VM / Wasm-grade isolation, run an E2B sandbox or
  containerise. Denyx pairs well with these but does not replace them.
- **You want content-safety / prompt-injection classification on
  natural-language input.** That's NeMo Guardrails, Lakera, Llama
  Firewall territory. Denyx doesn't classify text; it gates capability
  calls.
- **You need to enforce policy on a non-Denyx runtime today.** The
  policy format is documented as a portable spec
  ([agent-policy-spec.md](agent-policy-spec.md)) — but actual
  enforcement requires running scripts under `denyx-host` or
  `denyx-mcp`. If your agent can only call hosted APIs, an MCP
  proxy/gateway (Invariant, Lasso) sits between the agent and the
  service in a way Denyx doesn't.
- **Production-critical, unattended workloads, today.** Denyx is
  pre-1.0 and has not had a human-led security review yet. The
  README's status section is honest about this. Use the host built-ins
  + a sandbox until that review lands.

## Reading on

- [01-why-denyx](01-why-denyx.md) — the problem statement Denyx was
  built to address.
- [04-security-threat-model](04-security-threat-model.md) — what
  Denyx claims to defend against and what it explicitly does *not*.
- [05-owasp-agentic-coverage](05-owasp-agentic-coverage.md) —
  empirical scoring against the OWASP Agentic Top 10.
- [host-config.md](host-config.md) — the cross-host translation table.
