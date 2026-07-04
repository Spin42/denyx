---
id: TASK-1
title: Refresh mutation-testing.md's v0.1 baseline after re-running cargo-mutants
status: To Do
assignee: []
created_date: '2026-07-04 16:01'
updated_date: '2026-07-04 16:02'
labels:
  - mutation-testing
  - tech-debt
dependencies: []
ordinal: 1000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
crates/host/src/verifier.rs has grown substantially (the T6 AST-based taint-propagation pass), so the mutant counts and survivor breakdown in the 'Baseline as of v0.1' section are stale. Could not be run in the sandboxed dev environment (cargo-mutants unavailable).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Full cargo-mutants sweep run against the current .cargo/mutants.toml scope
- [ ] #2 docs/mutation-testing.md's Baseline section updated with fresh numbers
<!-- AC:END -->
