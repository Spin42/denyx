# Changelog

All notable changes to Denyx (`denyx-policy`, `denyx-host`,
`denyx-cli`, `denyx-mcp`, `denyx-local-mcp`) are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The agent-policy spec (the TOML schema documented in
[docs/agent-policy-spec.md](docs/agent-policy-spec.md)) is versioned
**independently** from the implementation crates. The spec is at
`v1.0.0`; the implementation crates are at `0.x` and may have
breaking API changes between minor versions until they hit `1.0.0`.

## [Unreleased]

### Added

- **Doctor's over-broad-allow-list check.** `denyx doctor` now
  flags entries in `filesystem.{read,write,delete}_allow` that
  defeat the deny-by-default property. Three risk tiers:
  Universal patterns (`**`, `/**`, `/`) → Warning; HomeDir
  patterns (`~`, `~/**`, `$HOME/**`) → Warning; top-level system
  directories (`/tmp/**`, `/etc/**`, `/usr/**`, `/var/**`,
  `/opt/**`, `/home/**`, `/Users/**`) → Info. Issues aggregate
  per `(section, risk)` so the doctor prints at most one line
  per class, not one per pattern. Surfaces the operator-side
  footgun the Round 2 pentest caught in the fixture. Tests in
  `crates/host/src/policy_host_consistency.rs::tests`
  (`classify_overbroad_*`, `overbroad_*`).
- **`denyx host-config --strict-mcp`.** New flag for Claude Code
  / Cursor wiring (the two hosts that use a shared `.mcp.json`).
  When set, refuses to merge if any non-denyx `mcpServers` entry
  is already present. Closes the architectural-configuration
  gap noted in the Round 2 report: the threat-model claim that
  "the cloud orchestrator only sees `delegate_to_local`" depends
  on denyx-local-mcp being the sole configured MCP server, and
  this flag enforces the precondition at host-config time
  rather than leaving it to operator diligence. The existing
  file is left untouched on refusal; the error names the
  offending entries. Tests in
  `crates/cli/src/host_config.rs::tests::strict_mcp_*` and
  end-to-end coverage in
  `crates/cli/tests/setup_flow.rs::host_config_strict_mcp_*`.
- **`denyx init --permissive`.** Polarity flip: the default
  `denyx init` now strips the `/tmp/**` entry from `write_allow`
  so the doctor doesn't warn on the starter policy out of the
  box. Operators who want the broader scratch-tree behaviour
  pass `--permissive` explicitly. The honest tradeoff is
  surfaced in the post-init message (the minimal mode prints
  the rationale + the flag). Tests in
  `crates/cli/src/init.rs::tests` (8 tests covering the strip,
  the permissive path, TOML validity, and protection against
  over-stripping).
- **Pre-exec tainted-output-flow refusal.** `verifier::verify`
  now statically refuses scripts whose data flow couples a
  literal-argument `env.read`/`fs.read` of a local-only value with
  any output-producing call (`print`, `fs.write`, `fs.delete`,
  `net.http_*`, `subprocess.exec`). The same property used to be
  enforced at runtime by the IFC scrubber + arg-side gate; the
  verifier now catches the literal-argument shape before the
  Starlark evaluator runs, which gives a cleaner audit signal.
  Variable-argument reads still flow through the unchanged
  runtime IFC. `VerifierRejection` gains a `TaintFlow` variant
  (the type is now an enum). Implementation in
  `crates/host/src/verifier.rs` (`taint_flow` submodule); tests
  in `crates/host/tests/verifier.rs` (`taint_flow_*`).
- **End-to-end regression test for the single-tool MCP wire
  surface.** `tools_list_advertises_only_delegate_to_local` in
  `crates/local-mcp/tests/end_to_end.rs` spawns the real binary
  and asserts that an MCP `tools/list` returns exactly one tool
  named `delegate_to_local`. The threat-model claim "the cloud
  orchestrator sees exactly one tool" depends on this and on
  operator-side host configuration (see Round 2 report).
- **`examples/local_executor/run_tool_poisoning_probe.py`** —
  three-round probe (step injection, encoding bypass, deny-by-
  default audit) driving `denyx-local-mcp` directly via JSON-RPC.
  Reproducer for the Round 2 pentest.
- **`examples/local_executor/probes.py`** — canonical taxonomy of
  47 hand-crafted probes across 12 categories, used by both the
  runtime probe and the detector-comparison harness. Sources for
  each probe are documented in-file (Greshake, HackAPrompt,
  Willison, denyx-r1, novel).
- **`examples/local_executor/run_detector_comparison.py`** —
  detector-comparison harness that runs the 47-probe set through
  llm-guard's `PromptInjection` (DeBERTa classifier), NeMo
  Guardrails' `self_check_input` rail (LLM-as-judge with a local
  Ollama model), and Denyx's `</task>` literal-substring guard.
  Tabulates detection rates per category.
- **Local pre-commit hook** mirroring CI's fmt + clippy gates.
  `scripts/precommit.sh` plus a one-line `.githooks/pre-commit`
  wrapper; one-time setup is `git config core.hooksPath .githooks`.

### Changed

- Tests in `crates/host/tests/taint.rs` that previously exercised
  the runtime scrubber via literal-argument reads now use
  variable-argument reads, so they continue to exercise the
  runtime path (which is unchanged). The pre-exec refusal of the
  literal-argument shape has dedicated tests in
  `crates/host/tests/verifier.rs`.
- Threat model and OWASP-coverage docs were rewritten to be
  honest about what each layer defends: the LLM-side `<task>`
  wrappers and system-prompt warning did not measurably reduce
  injection obedience in the Round 2 sample, and the enforcement
  Denyx actually provides is on the script's runtime behaviour,
  not on the LLM's reasoning.

### Pentest follow-up — Round 2

See [docs/security-pentest-r2-tool-poisoning.md](docs/security-pentest-r2-tool-poisoning.md).
Headline:

- Tested three LLM-side step-parameter defenses (delimiter
  wrapping, system-prompt warning, literal-`</task>` rejection)
  against four local code models (qwen2.5-coder 7B/14B, phi4
  14B, codestral 22B). The wrappers did not measurably reduce
  injection obedience on this n=4 sample.
- The runtime IFC + capability gate absorbed every leak attempt;
  0 literal or recovered leaks across 80 probe attempts. Read
  this as evidence the runtime stack works, not as evidence the
  LLM-side wrappers do.
- One operator-side footgun caught during testing: too-broad
  `**`-rooted globs in `read_allow` defeat deny-by-default by
  construction. Surfacing this in `denyx doctor` is the
  recommended follow-up.
- `denyx host-config` does not emit `--strict-mcp-config`, so
  the "cloud orchestrator only sees `delegate_to_local`" claim
  depends on operator setup Denyx doesn't enforce. Worth fixing
  or qualifying.

A v3 follow-up (same day) added a 47-probe taxonomy and a
detector-comparison experiment against two off-the-shelf
prompt-injection detectors:

- **llm-guard `PromptInjection`** (DeBERTa-v3 classifier):
  43/47 (91%) detected. Misses concentrate in `cover_task`
  (legitimate-looking framings) and `deny_by_default`.
- **NeMo Guardrails `self_check_input`** (LLM-as-judge with
  `qwen2.5-coder:7b`): 30/47 (63%) detected. Significantly
  weaker than the dedicated classifier, with 0% detection on
  `cover_task` and `translation` categories.
- **Denyx's `</task>` literal-substring guard**: 3/47 (6%) —
  only catches probes that happen to contain the byte sequence.
  It was never a general-purpose detector and should not be
  documented as one.

No detector caught every probe (lowest false-negative rate was
9%). The runtime gates remain the load-bearing layer in Denyx's
defense; detection and runtime enforcement are complementary, not
substitutes. Full data + per-category breakdown in the Round 2
report.

## [0.2.0] — 2026-05-09

A "make Denyx pleasant to wire into a real coding agent" release.
The capability gate, IFC layer, and audit chain shipped in 0.1.0 are
unchanged in shape. What's new is the *operational* surface: a
single command that wires Denyx into Claude Code / opencode / Cursor
/ Copilot / Continue / Cline from one TOML, a doctor that catches
policy-vs-host-config drift before it silently bypasses the gate,
a local-LLM bridge ported to Rust, and a startup-time guard that
refuses to advertise capability tools when the local config is out
of sync with the policy.

### Added

- **`denyx host-config` — cross-host wiring from one policy.** Single
  CLI command writes the right MCP server entry, built-in-tool deny
  list, and (Claude Code v2) OS-sandbox stanza for any of: Claude
  Code, opencode, Cursor, VSCode + GitHub Copilot agent mode,
  VSCode + Continue, VSCode + Cline. Auto-detects the host from
  env vars and cwd files; `--host all` writes for every supported
  host in one pass. Merge semantics preserve unrelated keys.
  `--dry-run` previews without writing. `--policy-url` /
  `--audit-url` switch the generated MCP entry into team mode
  (centralised policy fetch + audit POST). `--no-mcp` writes only
  the lockdown layer for callers using a non-Denyx MCP server.
  `--platform native|lima|wsl` adapts the command shape for VM-
  hosted setups. Full flag reference at
  [docs/host-config.md](docs/host-config.md).
- **`denyx doctor` — canonical project preflight.** Single entry
  point for "is my Denyx setup right?". Combines the project-side
  diagnosis (policy file, host configs, audit dir, `.gitignore`,
  built-in-tool lockdown) with cross-cutting consistency checks
  (policy ↔ host-config: same file? launch-flag freshness?
  sandbox stanza derived from current policy?). `--fix` applies
  mechanical re-derivations interactively (refuses on stdin-not-TTY
  so CI invocations stay safe). Full flag reference at
  [docs/doctor.md](docs/doctor.md).
- **`denyx-mcp doctor` — narrower variant** for VM-hosted setups
  where only `denyx-mcp` is on `$PATH` (e.g. inside a Lima VM).
  Read-only project-side checks; no `--fix`.
- **`denyx-local-mcp` — new binary, port of `local_mcp.py` to Rust.**
  The local-executor bridge that fronts a small local 7B model and
  forwards delegated steps through `denyx-mcp` under policy. Drops
  the Python prerequisite for the local-executor flow. Implicit
  default subcommand preserves pre-existing `.mcp.json` invocations
  that don't pass a subcommand.
- **`denyx-local-mcp doctor` — LLM-side preflight.** Two modes:
  scan mode probes the standard local-LLM ports (Ollama 11434,
  llama.cpp 8080, LM Studio 1234, vLLM 8000, Text Gen WebUI 5000)
  and suggests a serve command; targeted mode (`--endpoint <url>`)
  verifies a specific server end-to-end including chat + embed
  model availability and Ollama's `num_ctx` truncation pitfall.
  `--no-project` skips the project-state check for LLM-only
  validation.
- **Blocked-startup mode (`denyx-mcp` and `denyx-local-mcp`).** When
  the cross-cutting consistency check finds Critical-severity
  inconsistency between the loaded policy and the project's host
  configs, the MCP server **refuses to advertise its capability
  tools**. `tools/list` returns only a single `denyx_blocked` tool
  whose description tells the agent to surface the situation to
  the user; every `tools/call` returns a structured fix-instructions
  payload (`isError: true`, `denyx_error_kind: "blocked_startup"`).
  The model has no path to a real capability until the operator
  runs `denyx doctor --fix` and restarts the host. First-run guard
  skips the check when no host configs exist (so the very first
  startup before `denyx host-config` doesn't lock itself out).
- **`denyx_host::project_diagnosis` module.** Reusable diagnosis of
  policy file, host configs (`.mcp.json`, `opencode.json`,
  `.cursor/mcp.json`, `.vscode/settings.json`,
  `.continue/config.json`), audit dir, `.gitignore`, and the Claude
  Code OS-sandbox snapshot. Powers all three doctors.
- **`denyx_host::policy_host_consistency` module.** Cross-cutting
  consistency checks: tool URLs in `[tools.X]` against
  `http_*_allow`, declared capabilities against the policy's
  effective function set, `requires_approval` vs `--confirm-mode
  auto-allow`, conflicting policy paths across host configs,
  declared paths that don't exist, sandbox stanza drift.
- **`denyx_host::startup_block` module.** Shared blocked-mode
  rendering used by both MCP binaries (tool description, call-text
  payload, stderr banner).
- **Re-exports**: `denyx_host::Policy` and `denyx_host::PolicyError`
  promoted from private use to `pub use`, so embedders don't need
  a direct `denyx-policy` dep.

### Changed

- **README repositioning.** Broadened from "Claude Code / opencode"
  to "any MCP-aware coding host", reflecting the
  `host-config` matrix. The `denyx-setup-prompt.md` flow now uses
  `--host auto` and walks through the full lockdown for whichever
  host is detected.
- **`denyx-local-mcp doctor`** handles Ollama's `:latest` tag
  resolution correctly when matching a `--model` argument that
  omits the tag.
- **`local_mcp.py` is preserved for harness reproducibility** at
  `examples/local_executor/local_mcp.py`, but new wirings should
  use the Rust `denyx-local-mcp` binary.

### Documentation

- **[docs/comparison.md](docs/comparison.md)** — landscape across
  host built-ins (Claude Code, Cursor, opencode, Cline, Continue,
  Copilot), MCP gateways (Invariant, Snyk, Lasso, MCPX, Microsoft
  AGT), LLM guardrail frameworks (NeMo, Lakera, LLM Guard, Llama
  Firewall, CalypsoAI, HiddenLayer, Promptfoo), IFC research
  (CaMeL, FIDES, NeuroTaint), audit-shape peers (OpenFang, nono,
  Pipelock, Sigstore A2A), code-execution sandboxes (E2B, Daytona,
  Modal, Cloudflare, Hyperlight), and generic policy engines (OPA,
  Cerbos, Pomerium). Includes "when not to use Denyx".
- **[docs/host-config.md](docs/host-config.md)** — complete flag
  reference for `denyx host-config`: per-host wiring matrix,
  sandbox modes, merge-vs-replace semantics, team-mode flags,
  lockdown-only mode, platform variants.
- **[docs/doctor.md](docs/doctor.md)** — complete flag reference for
  all three `doctor` binaries; canonical-vs-narrower decision matrix;
  scan vs targeted modes; exit codes; common findings table flagging
  which are auto-fixable by `denyx doctor --fix`.
- **[docs/14-other-hosts.md](docs/14-other-hosts.md)** — Cursor /
  Copilot / Continue / Cline setup guide with honest lockdown-
  completeness matrix.
- **[docs/macos-deployment.md](docs/macos-deployment.md) /
  [docs/windows-deployment.md](docs/windows-deployment.md)** —
  rewritten to lead with `denyx host-config --platform lima/wsl`.
- **[docs/12-local-executor.md](docs/12-local-executor.md)** —
  rewritten around `denyx-local-mcp`; provider matrix
  (Ollama/llama.cpp/LM Studio/vLLM/Text Gen WebUI) with
  per-provider notes.
- **[docs/11-denyx-for-teams.md](docs/11-denyx-for-teams.md)** —
  documents the policy-update flow ("fetch new policy → run
  `denyx doctor --fix` locally → restart"), the rationale for
  refusing to auto-rewrite host configs from server-fetched policy.
- Existing numbered docs updated to point at the new reference
  pages where appropriate (09-claude-code, 10-opencode, 12-local-
  executor, 14-other-hosts, README index).

### CI

- **Sharded mutation-testing workflow.** `cargo-mutants --shard k/4`
  splits the ~450-mutant security-core sweep across four parallel
  matrix runners (~25-30 min each) instead of a single 3-6 hour
  runner that GitHub was reaping at the ~35-minute mark. A combine
  job aggregates per-shard `missed`/`timeout`/`unviable`/`caught`
  reports into one summary so the badge / `GITHUB_STEP_SUMMARY`
  show one coherent view. Also drops `timeout_multiplier` from
  5.0 to 2.5 and excludes infinite-loop counter mutants
  (`+= → *=`, `+= → -=` on `usize` loop counters in
  `strip_strings_and_comments`, `contains_word`, `b64_encode`)
  that contribute zero new test signal.

### Tests

- ~50 new tests added across the workspace, the bulk driven by
  mutation-testing surfacing test gaps in the security-critical
  core (policy gate decisions, taint redaction boundaries,
  verifier `strip_strings_and_comments`). Workspace test count
  passed 600.
- New integration tests for blocked-startup mode in both MCP
  binaries (synthesised inconsistent project; verifies
  `tools/list` returns only `denyx_blocked` and `tools/call`
  returns the structured fix payload).
- New end-to-end setup-flow regression guard for the
  `denyx host-config` matrix.

### Pre-release validation

- 600+ workspace unit + integration tests: **all pass**.
- `clippy --all-targets -- -D warnings` and `fmt --check`: clean.
- Local-executor harnesses (qwen2.5-coder:7b alone):
  `run.py` **10/10**, `run_multistep.py` **36/36**,
  `run_exfil.py` **9 REDACTED / 3 WEAK_LEAK / 0 LEAK**.
- Cloud-orchestrated harness with both models on a fresh GitHub
  rate-limit quota: **Sonnet 31/36** ($1.37, +1 vs the 0.1.0
  baseline), **Opus 36/36** ($2.88, +1 vs the 0.1.0 baseline).

### Known limitations (carried from 0.1.0)

- **No human security review yet.**
- **MCP `requires_approval` falls back to `auto-deny`** when the
  client doesn't advertise elicitation support.
- **OS isolation is opt-in.** Linux: bubblewrap. macOS: Lima VM.
  Windows: WSL2.
- **IFC transform set is finite.** Covers reverse, hex, XOR,
  base64, ROT-N, chunking. Does not catch script-generated
  cryptography or pure side channels (length, comparison oracles,
  substring guesses).
- **`denyx init --lang python` `write_allow` includes `/tmp/**`.**
  If a user inits a project *inside* `/tmp/`, the resulting policy
  is rejected by the runtime's self-write guard. Real-world
  projects in `~/projects/`, `/home/`, etc. are unaffected.
  Will be fixed in 0.2.x.

## [0.1.0] — 2026-05-06

Initial public release. Project was previously developed under the
name **Aegis** and renamed to **Denyx** before publishing because
the `aegis-*` crate names were partially taken on crates.io.

### Added

- **Policy crate** (`denyx-policy`):
  - TOML loader with preset inheritance (`secure-defaults` baseline)
    and override semantics (extend / negate).
  - Capability gates: `check_fs_read`, `check_fs_write`,
    `check_fs_delete`, `check_http_*` (per-verb), `check_subprocess_command`,
    `check_subprocess_argv_paths`, `check_env_read`.
  - Visibility classes: `allow` / `local_only_*` / `deny_*` per
    resource section; `local_only` values are tainted and redacted
    at output boundaries.
  - Reserved-env-var invariant: `DENYX_AUTH_TOKEN`, `DENYX_TOKEN`,
    `DENYX_SERVER_TOKEN`, `DENYX_JWT`, `DENYX_API_KEY` are
    never-readable regardless of policy.
  - Bubblewrap argv constructor for Linux subprocess sandboxing.
- **Host crate** (`denyx-host`):
  - Embeddable Starlark runtime with capability-typed builtins
    (`fs.read`, `fs.write`, `fs.delete`, `subprocess.exec`,
    `net.http_get`, `net.http_post`, `net.http_put`,
    `net.http_patch`, `net.http_delete`, `env.read`).
  - Pre-execution verifier (rejects scripts referencing forbidden
    capabilities before evaluation begins).
  - IFC layer with transform-aware redaction: reverse, hex (lower /
    upper), single-byte XOR + hex(XOR), base64 (std + url-safe),
    ROT-1..25, and chunking-detection on subsequence assembly.
  - SHA-256 hash-chained audit log with `JsonlAuditSink`,
    `HttpAuditSink`, and a buffer sink for testing.
  - Confirmation hook (`ConfirmHook` trait): CLI prompt, MCP
    elicitation, allow-all, deny-all variants.
  - Auto-redirect-disabled HTTP client (any 3xx response surfaces
    as an error, forcing the script to call `net.http_*` again on
    the new URL so the policy gate fires).
- **CLI crate** (`denyx-cli`):
  - `denyx run` — execute a Starlark script under a policy.
  - `denyx init` — generate a starter policy by language.
  - `denyx policy explain` — show what a policy allows for a
    capability + path.
  - `denyx policy diff` — diff two policy files semantically.
  - `denyx audit tail` / `audit verify` — inspect and verify the
    hash chain.
- **MCP crate** (`denyx-mcp`):
  - JSON-RPC 2.0 over stdio (MCP protocol 2025-06-18).
  - `aegis_*` (now `denyx_*`) tool family covering all capability
    gates, with sugar tools for common patterns
    (`denyx_fs_read`/`write`/`delete`, `denyx_subprocess_exec`,
    `denyx_net_http_get`/`post`, `denyx_env_read`).
  - Server mode: `DENYX_POLICY_URL` for centralised policy fetch,
    `DENYX_AUDIT_URL` for audit POST, `DENYX_AUTH_TOKEN` for
    bearer auth. Cascading dotenv loader
    (`process env > ~/.config/denyx/.env > /etc/denyx/.env`).
  - Confirmation modes: `auto` (try elicitation, fall back to
    `auto-deny`), `elicit`, `auto-allow`, `auto-deny`.

### Security

- 16-surface static bypass assessment
  ([docs/security-audit.md](docs/security-audit.md)).
- 12-technique exfil probe at **0 LEAK / 3 WEAK_LEAK / 9 REDACTED**.
- AI-driven pentest with Sonnet and Opus (two High findings, both
  closed; [docs/security-pentest-report.md](docs/security-pentest-report.md)).
- `cargo-fuzz` + 200 000-iteration regression sweep
  ([fuzz/](fuzz/README.md)).
- Mutation testing on the security-critical core
  ([docs/mutation-testing.md](docs/mutation-testing.md)) — gate-decision
  functions at near-100% kill rate; workspace baseline ~85%.

### Known limitations

- **No human security review yet.** External review is the single
  biggest gating item between today and unattended production use.
- **MCP `requires_approval` falls back to `auto-deny`** when the
  client doesn't advertise elicitation support (most clients in
  2026, including Claude Code 2.1.x in `-p` mode).
- **OS isolation is opt-in.** Linux: bubblewrap. macOS: Lima VM.
  Windows: WSL2. Without one of these, Denyx is the language-level
  gate only.
- **IFC transform set is finite.** Covers reverse, hex, XOR,
  base64, ROT-N, chunking. Does NOT catch scripts running their
  own crypto (AES, custom permutations) or pure side channels
  (length, comparison oracles, substring guesses).

[Unreleased]: https://github.com/Spin42/denyx/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Spin42/denyx/releases/tag/v0.2.0
[0.1.0]: https://github.com/Spin42/denyx/releases/tag/v0.1.0
