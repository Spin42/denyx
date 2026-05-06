# denyx-cli

Command-line interface for [Denyx](https://github.com/Spin42/denyx),
a default-deny capability layer for AI-agent runtimes.

Installs a `denyx` binary that runs a Starlark script under a
TOML-declared policy. Forbidden filesystem reads, network calls,
subprocess spawns, and environment-variable accesses fail at the
runtime — there is no soft-warn or fallback path.

## Install

```sh
cargo install denyx-cli
```

This installs the `denyx` binary into `~/.cargo/bin/`.

> **Heads-up**: there's an unrelated `aegis-cli` crate on crates.io
> (a 2FA TOTP tool) that also installs a binary called `aegis`.
> Denyx installs `denyx`, so they don't collide directly, but the
> name is close enough to mention.

## Usage

```sh
# Generate a starter policy for the current project
denyx init --lang python --output denyx.toml

# Run a script under the policy
denyx run --policy denyx.toml --script my_agent.star

# Inspect what the policy actually allows
denyx policy explain --policy denyx.toml --capability fs.read --path src/main.rs

# Tail the audit log
denyx audit tail --since 1h
```

Full subcommand reference: `denyx --help` or the [main
README](https://github.com/Spin42/denyx).

## Status

Pre-1.0. Read the [main README](https://github.com/Spin42/denyx)
disclosure block before using against systems you can't afford to
recover.

## License

MIT. See [LICENSE](LICENSE).
