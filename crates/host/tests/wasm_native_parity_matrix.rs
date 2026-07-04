//! Table-driven wasm/native parity matrix (Phase 3 of the wasm/native
//! parity hardening review — see docs/security-pentest-r4-wasm-path-regressions.md).
//!
//! Runs the same policy + script through both `Runner` (native) and
//! `WasmRunner` (wasm, the default execution path since v0.4.0) and
//! asserts they produce the same *outcome class* (success, or which
//! `DenyxError` variant). This is the low-friction net Phase 3 set out
//! to build: adding a fixture for a future finding is one entry in
//! `FIXTURES`, not a whole new test function.
//!
//! Scope: only fixtures that need no dynamic setup (no real files,
//! network listeners, or external binaries) live here, so the whole
//! matrix runs in milliseconds. Fixtures needing a real filesystem
//! path, a loopback listener, or bubblewrap have their own dedicated
//! test files (each already runs both runners for its specific
//! finding):
//!   - crates/host/src/wasm_runner.rs's `tests` module: dns_check
//!     (SSRF/deny_ips), HTTP timeout, bwrap sandbox, guest-length
//!     bounds, the no-output-after-local-only-read flag, call-count
//!     caps, the local-only-command outbound-taint fix.
//!   - crates/host/tests/audit_scrub_wasm_native_parity.rs: the
//!     audit-log taint-scrub fix.
//!
//! When a future pentest or review finds another wasm/native
//! divergence that DOESN'T need dynamic setup, add it to `FIXTURES`
//! rather than writing a new test — that's the point of this file.

use std::path::PathBuf;

use denyx_host::{DenyxError, Runner, WasmRunner};
use denyx_policy::{Policy, PolicyFile};

/// Coarse outcome class both runners must agree on. Not the exact
/// message (wording legitimately differs between runners in places —
/// e.g. wasm's argv-path-gate error text vs native's), just the
/// variant, which is what exit-code mapping and calling code actually
/// branch on.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Success,
    Policy,
    Verifier,
    RuntimeLimit,
    ConfirmDenied,
    Starlark,
}

fn classify(result: &Result<denyx_host::RunOutcome, DenyxError>) -> Outcome {
    match result {
        Ok(_) => Outcome::Success,
        Err(DenyxError::Policy(_)) => Outcome::Policy,
        Err(DenyxError::Verifier(_)) => Outcome::Verifier,
        Err(DenyxError::RuntimeLimit(_)) => Outcome::RuntimeLimit,
        Err(DenyxError::ConfirmDenied(_)) => Outcome::ConfirmDenied,
        Err(DenyxError::Starlark(_)) => Outcome::Starlark,
        Err(other) => panic!("unexpected DenyxError variant in parity matrix: {other:?}"),
    }
}

struct Fixture {
    name: &'static str,
    toml: &'static str,
    script: &'static str,
    expected: Outcome,
}

const FIXTURES: &[Fixture] = &[
    Fixture {
        name: "plain_print_succeeds",
        toml: "",
        script: r#"print("hello")"#,
        expected: Outcome::Success,
    },
    Fixture {
        // Round 3/4: argv[0] basename-only matching → arbitrary code
        // execution. secure-defaults denies shell evaluators outright.
        name: "argv0_shell_evaluator_denied_by_secure_defaults",
        toml: r#"
inherits = "secure-defaults"
[subprocess]
allow_commands = ["echo"]
"#,
        script: r#"subprocess.exec(["bash", "-c", "id"])"#,
        expected: Outcome::Policy,
    },
    Fixture {
        // Round 3: a full-path deny_commands entry must also catch
        // the bare-name invocation of the same binary.
        name: "deny_commands_full_path_catches_bare_name_invocation",
        toml: r#"
[subprocess]
allow_commands = ["git"]
deny_commands = ["/usr/bin/git"]
"#,
        script: r#"subprocess.exec(["git", "status"])"#,
        expected: Outcome::Policy,
    },
    Fixture {
        // secure-defaults' /proc deny must hold even with a broad
        // read_allow re-granting it.
        name: "proc_self_environ_denied_under_secure_defaults",
        toml: r#"
inherits = "secure-defaults"
[filesystem]
read_allow = ["/**"]
"#,
        script: r#"fs.read("/proc/self/environ")"#,
        expected: Outcome::Policy,
    },
    Fixture {
        // Was a real parity mismatch: native raised a bare anyhow
        // error (DenyxError::Starlark, exit 1, no audit event) while
        // wasm explicitly captured+audited it (DenyxError::Policy,
        // exit 2). Fixed by making native match wasm's more complete
        // behavior — found by this very matrix on its first run.
        name: "empty_argv_denied",
        toml: r#"
[subprocess]
allow_commands = ["echo"]
"#,
        script: r#"subprocess.exec([])"#,
        expected: Outcome::Policy,
    },
    Fixture {
        name: "unallowed_capability_denied_by_verifier",
        toml: r#"
[filesystem]
read_allow = ["src/**"]
"#,
        // net.http_get is never populated by any [network] allow-list,
        // so the capability itself isn't granted — caught pre-exec.
        script: r#"net.http_get("http://example.com/")"#,
        expected: Outcome::Verifier,
    },
    Fixture {
        // The static verifier's literal-argument tainted-output-flow
        // check: a literal local-only fs.read paired with print.
        name: "literal_local_only_read_then_print_refused_by_verifier",
        toml: r#"
[filesystem]
local_only_read = ["/tmp/denyx-parity-matrix-nonexistent.txt"]
"#,
        script: "x = fs.read(\"/tmp/denyx-parity-matrix-nonexistent.txt\")\nprint(x)",
        expected: Outcome::Verifier,
    },
    Fixture {
        // max_callstack_size is forwarded straight to Starlark's own
        // Evaluator::set_max_callstack_size — the overflow surfaces as
        // a plain Starlark evaluation error on both runners, not a
        // DenyxError::RuntimeLimit (that variant is reserved for
        // Denyx's own wall-time/fuel/call-count caps, which run a
        // separate check before the effect, not Starlark's internal
        // recursion guard).
        name: "max_callstack_size_denies_deep_recursion",
        toml: r#"
[runtime]
max_callstack_size = 5
"#,
        script:
            "def rec(n):\n    if n <= 0:\n        return 0\n    return 1 + rec(n - 1)\nrec(1000)",
        expected: Outcome::Starlark,
    },
    Fixture {
        name: "requires_approval_denied_by_default_deny_confirm",
        // requires_approval must come before any [table] header — TOML
        // parses bare keys after a table header as belonging to that
        // table, not the document root (a real gotcha this fixture
        // tripped over on its first draft: `requires_approval` placed
        // after `[subprocess]` silently became `subprocess.requires_approval`
        // and both runners correctly allowed the call, which looked
        // like a parity bug but was a fixture-authoring mistake).
        toml: r#"
requires_approval = ["subprocess.exec"]

[subprocess]
allow_commands = ["echo"]
"#,
        script: r#"subprocess.exec(["echo", "hi"])"#,
        expected: Outcome::ConfirmDenied,
    },
];

fn native_policy(toml: &str, root: PathBuf) -> Policy {
    let file = PolicyFile::from_toml_str(toml)
        .unwrap()
        .resolve_inheritance()
        .unwrap();
    Policy::from_file(file, root).unwrap()
}

#[test]
fn wasm_and_native_agree_on_every_matrix_fixture() {
    let mut failures = Vec::new();
    for fixture in FIXTURES {
        let root = std::env::temp_dir();
        let native = Runner::new(native_policy(fixture.toml, root.clone()));
        let native_result = native.run("t1", fixture.script, "test.star");
        let native_outcome = classify(&native_result);

        let wasm = WasmRunner::new(native_policy(fixture.toml, root));
        let wasm_result = wasm.run("t1", fixture.script, "test.star");
        let wasm_outcome = classify(&wasm_result);

        if native_outcome != fixture.expected {
            failures.push(format!(
                "{}: native produced {:?}, expected {:?} (result: {:?})",
                fixture.name, native_outcome, fixture.expected, native_result
            ));
        }
        if wasm_outcome != fixture.expected {
            failures.push(format!(
                "{}: wasm produced {:?}, expected {:?} (result: {:?})",
                fixture.name, wasm_outcome, fixture.expected, wasm_result
            ));
        }
        if native_outcome == fixture.expected
            && wasm_outcome == fixture.expected
            && native_outcome != wasm_outcome
        {
            failures.push(format!(
                "{}: runners disagree despite both matching expected (should be unreachable)",
                fixture.name
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "parity matrix failures:\n{}",
        failures.join("\n")
    );
}
