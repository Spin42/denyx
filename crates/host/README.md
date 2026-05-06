# denyx-host

The embeddable Starlark host for [Denyx](https://github.com/mlainez/denyx),
a default-deny capability layer for AI-agent runtimes.

This crate is what you reach for when you want to **execute**
policy-gated Starlark in your own process. It registers
capability-typed builtins (`fs.read`, `net.http_get`,
`subprocess.exec`, `env.read`, ...), enforces the
[`Policy`](https://docs.rs/denyx-policy) at every effecting call,
runs a pre-execution verifier that rejects scripts referencing
forbidden capabilities, and emits a hash-chained audit log.

## When to depend on this crate

- You're building a custom MCP server, CI runner, or background
  agent that needs to evaluate untrusted Starlark with bounded
  effects.
- You want the verifier + capability gates + IFC-tainted output
  redaction in one library, without the CLI or stdio MCP
  scaffolding.

If you want a ready-made CLI, install
[`denyx-cli`](https://crates.io/crates/denyx-cli). For an
out-of-the-box MCP server (Claude Code, opencode, etc.), install
[`denyx-mcp`](https://crates.io/crates/denyx-mcp).

## Quick example

```rust,ignore
use denyx_host::{Runner, JsonlAuditSink, AllowAllConfirm};
use denyx_policy::{Policy, PolicyFile};
use std::{path::PathBuf, sync::Arc};

let policy = Policy::from_file(
    PolicyFile::from_toml_str(r#"
        [filesystem]
        read_allow = ["src/**"]
    "#)?,
    PathBuf::from("."),
)?;

let runner = Runner::builder()
    .policy(policy)
    .audit_sink(Arc::new(JsonlAuditSink::stdout()))
    .confirm_hook(Arc::new(AllowAllConfirm))
    .build()?;

runner.run(r#"print(fs.read("src/main.rs"))"#)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Status

Pre-1.0. Read the [main README](https://github.com/mlainez/denyx)
disclosure block before using in production — the runtime is
empirically tested (fuzz, exfil probe, AI-driven pentest, mutation
testing) but has not yet been reviewed by an external human
security engineer.

## License

MIT. See [LICENSE](LICENSE).
