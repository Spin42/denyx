# denyx-policy

The policy types and TOML loader for [Denyx](https://github.com/mlainez/denyx),
a default-deny capability layer for AI-agent runtimes.

This crate is the **specification side** of Denyx: it parses
`denyx.toml` files, applies preset inheritance and overrides,
validates the merged configuration, and exposes typed
`Policy::check_*` methods that the host calls at every effecting
operation. It has no runtime side effects of its own — it doesn't
read files, fetch URLs, or spawn processes.

## When to depend on this crate

- You're embedding Denyx via [`denyx-host`](https://crates.io/crates/denyx-host)
  and need to load or construct policies in your own code.
- You're building a tool that **inspects** or **rewrites** Denyx
  policies (linter, policy diff, IDE plugin) without running
  scripts.
- You want the same capability-decision logic the runtime uses,
  for offline analysis.

If you want to **execute** policy-gated Starlark, depend on
`denyx-host` instead — it pulls this crate in transitively.

## Quick example

```rust,ignore
use denyx_policy::{Policy, PolicyFile};
use std::path::PathBuf;

let toml = r#"
inherits = "secure-defaults"

[filesystem]
read_allow  = ["src/**"]
write_allow = ["/tmp/**"]

[network]
http_get_allow = ["api.github.com"]
"#;

let file = PolicyFile::from_toml_str(toml)?;
let policy = Policy::from_file(file, PathBuf::from("."))?;

policy.check_fs_read(std::path::Path::new("src/main.rs"))?;
assert!(policy.check_fs_read(std::path::Path::new("/etc/passwd")).is_err());
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Status

Pre-1.0. The schema is documented in
[docs/agent-policy-spec.md](https://github.com/mlainez/denyx/blob/main/docs/agent-policy-spec.md)
(spec at v1.0.0; implementation at 0.x). See the [main README](https://github.com/mlainez/denyx)
for the threat-model and security disclosures before using in
production.

## License

MIT. See [LICENSE](LICENSE).
