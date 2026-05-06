# Changelog

All notable changes to Denyx (`denyx-policy`, `denyx-host`,
`denyx-cli`, `denyx-mcp`) are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The agent-policy spec (the TOML schema documented in
[docs/agent-policy-spec.md](docs/agent-policy-spec.md)) is versioned
**independently** from the implementation crates. The spec is at
`v1.0.0`; the implementation crates are at `0.x` and may have
breaking API changes between minor versions until they hit `1.0.0`.

## [Unreleased]

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

[Unreleased]: https://github.com/Spin42/denyx/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Spin42/denyx/releases/tag/v0.1.0
