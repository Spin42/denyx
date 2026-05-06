# Mutation testing

> ← [Back to docs README](README.md)

Aegis runs mutation testing on its security-critical core via
[`cargo-mutants`](https://mutants.rs/). The CI workflow is
[`.github/workflows/mutants.yml`](../.github/workflows/mutants.yml);
the per-project configuration is
[`.cargo/mutants.toml`](../.cargo/mutants.toml). This doc covers what
the tool does, why we run it, and what to do when a mutant survives.

## What mutation testing actually measures

Line coverage answers "did this line execute under any test?"
Mutation testing answers a sharper question: "if I change the
*behaviour* of this line, does any test fail?"

The tool walks the source, generates "mutants" — small mechanical
edits to single expressions — and runs the test suite against each
one. Examples of mutants:

- replace `==` with `!=`
- replace `<=` with `<`
- replace `&&` with `||`
- delete a `!`
- replace a function body with `Default::default()`
- replace a `Vec::push(x)` with no-op

If the test suite **passes** with a mutant in place, that mutant
"survived" — meaning the tests don't actually verify the line's
behaviour. Surviving mutants are pointers to weak tests.

For ordinary code this overlaps heavily with line coverage. For a
**policy gate** the gap is the whole game: a test that calls
`policy.check_fs_read("/etc/passwd")` and asserts `result.is_err()`
covers the line, but might still pass if you flipped the path-glob
match operator — the test would still see *some* error, just for
the wrong reason. That's the failure mode mutation testing catches.

## Scope: only the security-critical files

`.cargo/mutants.toml` restricts the tool to three files:

| File                              | Why mutate it                                                                 |
|-----------------------------------|--------------------------------------------------------------------------------|
| `crates/policy/src/lib.rs`        | Every `Policy::check_*` decision routes through here. Wrong operator = bypass. |
| `crates/host/src/taint.rs`        | The IFC layer. A miscomputed transform = silent secret leak.                  |
| `crates/host/src/verifier.rs`     | The capability scanner. An off-by-one in word-boundary detection = bypass.    |

That's roughly 1 000 LOC and ~450 mutants. Mutating the rest of the
workspace (the MCP server, the CLI, the Starlark-runtime glue) would
generate ~1 000 additional mutants, most of them "equivalent" — code
that's syntactically different but semantically identical, like
`Result::Ok(()) → Result::Ok(())` in a path that always returns Ok.
The triage cost is real and the signal is poor on those modules.

## Schedule, not gate

Mutation testing is too slow for PR-time. A typical scoped run takes
30–90 minutes on a 4-core runner. If we gated PRs on it, every PR
would be blocked for an hour and developers would route around it.

The workflow runs:

- **Weekly**, every Monday at 06:00 UTC, on a `cron` schedule.
- **On-demand** via the GitHub Actions UI (`workflow_dispatch`) —
  use this right after a security-critical change rather than
  waiting for the weekly cycle.

Surviving mutants are surfaced in the workflow's GitHub Step Summary
and uploaded as an artefact. We don't auto-open issues for now;
triage is a human-in-the-loop step.

## Reading a `cargo-mutants` report

The tool produces these files under `mutants-output/`:

| File              | Meaning                                                                |
|-------------------|------------------------------------------------------------------------|
| `caught.txt`      | Mutants the test suite caught. **The good outcome.**                   |
| `missed.txt`      | Mutants that survived. **Each line is a potential weak test.**         |
| `timeout.txt`     | Mutants whose test run exceeded the per-mutant timeout. Usually means an infinite loop introduced by the mutation — *also* counts as caught (the tests didn't return success). |
| `unviable.txt`    | Mutants that didn't compile (type-system or borrow-check rejected the change). Uninteresting; ignore. |

A line in `missed.txt` looks like:

```
crates/policy/src/lib.rs:1234:42: replace == with != in check_fs_read
```

That tells you: line 1234, column 42, the mutator changed `==` to
`!=`, and the tests didn't notice.

## Triage: what to do with a surviving mutant

For each entry in `missed.txt`, decide:

1. **Real test gap.** The mutated behaviour is genuinely different,
   but no test exercised the change-sensitive case. Fix: add a
   targeted test that fails when the mutation is applied. The test
   case usually drops out of reading the mutant — *what input would
   make the original-vs-mutated branches diverge?*

2. **Equivalent mutant.** The mutated code is semantically
   identical to the original. Common patterns:
   - replacing `Vec::push(x)` with no-op when the resulting Vec is
     never read,
   - replacing a `> 0` check with `>= 0` when the underlying type
     can't be negative,
   - replacing `Some(x.clone())` with `Some(Default::default())`
     when `x` is itself `Default`-valued in tests.
   Fix: add a `# Equivalent mutant: …` comment and skip via the
   `examine_re` / `exclude_re` config knobs, or mark the function
   with `#[mutants::skip]` (cargo-mutants supports an attribute).

3. **Dead code.** No test exercises the function at all because
   nothing calls it. Fix: delete the function (or the unreachable
   branch). Either is the right answer; "add a test that asserts
   dead code stays dead" is rarely useful.

The acceptance bar for an Aegis PR is **no new surviving mutants in
the security core**. If the weekly run shows new survivors, opening
a fix PR is the next step — same workflow as a failing test, just
on a slower clock.

## Honest limits

- **Mutation testing measures the *test suite*, not the code.** A
  zero-survivors result means "the tests are sensitive to single-
  line mutations of the security gates." It does NOT mean "the gates
  are correct" — a logic bug in the original code that's also in the
  test's expectation passes mutation testing trivially.
- **Slow even when scoped.** 30–90 minutes per run. Real-time
  feedback is impossible.
- **Equivalent mutants take operator time.** Budget 5–10 minutes
  per surviving mutant for triage on a clean run.
- **Doesn't compose with flaky tests.** A 1% flake rate gets
  amplified to a wall of false survivors when the test suite is
  rerun 450 times. If a mutant run shows weird variance, fix the
  flake first; the mutant signal is unusable until tests are
  deterministic.

## Where this fits in the security toolbox

Mutation testing is one of several empirical signals on top of the
threat model:

| Signal                                                | What it answers                                                |
|-------------------------------------------------------|----------------------------------------------------------------|
| [`cargo-fuzz` + stable randomized sweep](../fuzz/README.md) | "Does the parser / verifier panic on malformed input?"   |
| [Hand-written exfil probe](../examples/local_executor/run_exfil.py) | "Does the IFC layer block the attacks we already know about?" |
| [AI-driven pentest harness](../examples/local_executor/run_pentest.py) | "Does the IFC layer block attacks Sonnet/Opus invent?" |
| Mutation testing (this doc)                          | "Do the tests catch one-character regressions in the gates?"   |
| [Static bypass audit](security-audit.md)              | "Did a human review every code path with hostile intent?"     |

Each one catches a different class of mistake. Mutation testing's
specific contribution: it's the only mechanical signal on **test
quality**. Coverage tells you what ran. Pentests tell you what an
adversary couldn't bypass. Mutation testing tells you whether the
tests would *notice* if the gate broke.

## Running locally

```sh
# Install cargo-mutants once.
cargo install cargo-mutants --locked

# Run the full configured scope (the three security-critical files):
cargo mutants --jobs 4 --no-shuffle

# Run on a single file for quick iteration:
cargo mutants --jobs 4 --no-shuffle -f crates/policy/src/lib.rs

# List the mutants without running them — useful for estimating
# scope before kicking off a long run:
cargo mutants --list -f crates/host/src/taint.rs

# Re-run only previously-missing mutants (after adding tests):
cargo mutants --jobs 4 --in-place --iterate
```

Output lands in `mutants.out/` (or whatever `--output` says). Open
`mutants.out/missed.txt` for triage.
