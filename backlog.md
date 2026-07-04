# Backlog

A coordination scratchpad for in-flight or near-term work — not a
changelog and not a design doc (that's `docs/project-plan.md`). Git
log is the permanent record of what shipped; this file only tracks
what hasn't yet.

**Rules for agents:**

- Add an entry for work that's multi-session or easy to forget
  (a follow-up you noticed but aren't doing right now). Don't add
  something you'll finish in the same session — just do it.
- Check this file at the start of a session; a relevant item here
  should inform what you work on next.
- Remove an entry in the same commit that finishes the work. Don't
  let checked-off items accumulate — `## Done` is a short, recent
  glance, not an archive.
- One line per entry: `- [ ] <task> — <why, one line> (added
  YYYY-MM-DD)`. If it needs more than one line, it's not backlog-
  sized — write a design doc or open plan mode instead.

## Active

- [ ] Re-run the full `cargo-mutants` sweep and refresh
      `docs/mutation-testing.md`'s "Baseline as of v0.1" numbers —
      `crates/host/src/verifier.rs` has grown substantially (the T6
      AST-based taint-propagation pass) since that baseline was
      measured, so the mutant counts and survivor breakdown are
      stale. (added 2026-07-04)

## Done

<!-- Keep the last ~10 here as a short glance; older entries are
     just deleted — see them in `git log` instead. -->
