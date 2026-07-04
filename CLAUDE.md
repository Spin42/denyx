# Denyx — agent directives

This file is read at the start of every Claude Code session in this
repo. Keep it short.

## Tone

Denyx is a security tool. **Write like a security researcher
documenting what was measured, not like a marketer documenting what
was built.**

- **Neutral, honest, precise.** Reports state what was tested, what
  was observed, what the sample size was, and what the limits are.
- **No headline metrics framed for excitement.** "0 leaks across 80
  attempts" without context is misleading when most of the credit
  belongs to a pre-existing layer; spell out which layer caught
  what.
- **Sample size is a first-class fact.** When n is small (n=4
  models, 10 probes, single-shot), say so up front. Avoid
  generalising past the panel.
- **Don't claim defenses you can't show.** If a wrapper or warning
  did not measurably reduce obedience in the test, the honest word
  is "mitigation," not "boundary." Note empirical evidence by
  reference to the round / model panel.
- **Distinguish accidental from designed defense.** A Starlark
  parser rejecting Python idiom is not a Denyx defense. Document it
  as parser behaviour, not as protection.
- **Operator-side caveats belong next to the property they
  invalidate**, not in a footnote. Over-broad globs, missing
  `--strict-mcp-config`, etc.
- **Acknowledge that the LLM obeys injection.** Denyx's enforcement
  is on the script's runtime behaviour, not on the model's
  reasoning. Don't write copy that implies otherwise.
- **No "comprehensive" / "robust" / "production-grade" without
  citation.** If the work has these properties, cite the
  pentest/audit doc that demonstrates them. If it doesn't, don't
  use the words.
- **Prior work exists.** Greshake et al on indirect injection,
  CaMeL/FIDES on IFC-in-LLMs, Llama Firewall, Invariant Labs,
  Lakera. Position Denyx among these honestly when relevant.

## Reference points

- `docs/security-pentest-report.md` (Round 1) and
  `docs/security-pentest-r2-tool-poisoning.md` (Round 2) are the
  tone reference. Match their level of caveat density.
- `docs/04-security-threat-model.md` has a "What it does NOT defend
  against" section that pulls weight equal to the "defends against"
  table. New defenses belong in both.

## Test-first (TDD)

- New behaviour: write the failing test before the implementation.
- Bug fixes: write a test that reproduces the bug before touching
  the fix. Confirm it fails, then fix, then confirm it passes.
- No exceptions for "small" changes in `crates/policy` or
  `crates/host` — these are the security-critical crates; the test
  is the spec.

## Maintenance duties

- Editing `crates/policy/src/lib.rs`, `crates/host/src/taint.rs`, or
  `crates/host/src/verifier.rs`: re-check every line-anchored regex
  in `.cargo/mutants.toml`'s `exclude_re`, and every in-code "this
  test targets line N" comment in that file's own test module, still
  points at the right code. Line numbers drift silently when a file
  grows — see `docs/mutation-testing.md`.
- Check `backlog.md` at the start of a session; add or remove
  entries per its own rules.

## Behaviour shortcuts

- Run `./scripts/precommit.sh` (or rely on the hook installed via
  `git config core.hooksPath .githooks`) before committing — same
  fmt + clippy gates as CI.
- When in doubt about whether a finding is novel, assume it isn't.
  Document what was tested and let the reader decide.
