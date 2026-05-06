//! Pentest-style unit tests for the DENYX_RESERVED_VAR_NAMES
//! invariant.
//!
//! The runtime denies a fixed list of variable names — the bearer
//! token, the policy URL, the audit URL, and a few aliases — to all
//! agent scripts under all policies. These tests model an attacker
//! authoring a hostile policy that *tries* to grant the agent access
//! to a reserved name through every available mechanism, and assert
//! that every mechanism is closed.

use std::path::PathBuf;

use denyx_policy::{is_denyx_reserved_var, Policy, PolicyFile, DENYX_RESERVED_VAR_NAMES};

fn build(toml: &str) -> Policy {
    let file = PolicyFile::from_toml_str(toml).unwrap();
    Policy::from_file(file, PathBuf::from("/tmp")).unwrap()
}

#[test]
fn reserved_list_includes_token_url_and_aliases() {
    // Spec sanity: the curated list must include the obvious names.
    // If a future change accidentally drops one of these, this test
    // surfaces the regression before it ships.
    let must_include = ["DENYX_AUTH_TOKEN", "DENYX_POLICY_URL", "DENYX_AUDIT_URL"];
    for name in must_include {
        assert!(
            DENYX_RESERVED_VAR_NAMES.contains(&name),
            "DENYX_RESERVED_VAR_NAMES should contain {name}; current set: {:?}",
            DENYX_RESERVED_VAR_NAMES
        );
        assert!(is_denyx_reserved_var(name), "{name} should be reserved");
    }
}

#[test]
fn reserved_names_denied_when_listed_in_allow_vars() {
    // Attack: a hostile (or careless) policy explicitly grants
    // `env.read("DENYX_AUTH_TOKEN")` via allow_vars. The runtime
    // invariant fires before allow_vars is consulted, so the read
    // is denied regardless.
    let policy = build(
        r#"
[environment]
allow_vars = ["DENYX_AUTH_TOKEN", "PATH"]
"#,
    );
    assert!(
        policy.check_env_read("DENYX_AUTH_TOKEN").is_err(),
        "DENYX_AUTH_TOKEN must be denied even when listed in allow_vars"
    );
    // Sanity: the non-reserved name in the same allow list still works.
    assert!(policy.check_env_read("PATH").is_ok());
}

#[test]
fn reserved_names_denied_when_listed_in_local_only_vars() {
    // Attack: the policy lists DENYX_AUTH_TOKEN under local_only_vars,
    // hoping the local-only-tainted-but-readable semantics apply.
    // Same answer: the runtime invariant denies the read outright.
    let policy = build(
        r#"
[environment]
local_only_vars = ["DENYX_AUTH_TOKEN"]
"#,
    );
    assert!(policy.check_env_read("DENYX_AUTH_TOKEN").is_err());
}

#[test]
fn reserved_names_denied_with_negation_attack() {
    // Attack: the policy inherits secure-defaults (which has
    // DENYX_AUTH_TOKEN in deny_vars) but tries to lift the deny via
    // gitignore-style negation — `!DENYX_AUTH_TOKEN` removes the
    // entry from the inherited deny_vars list. THEN puts the same
    // name in allow_vars, hoping to get net access. The runtime
    // invariant doesn't read deny_vars at all for the reserved
    // names, so the negation has no effect.
    let policy = build(
        r#"
inherits = "secure-defaults"

[environment]
deny_vars = ["!DENYX_AUTH_TOKEN"]
allow_vars = ["DENYX_AUTH_TOKEN"]
"#,
    );
    assert!(
        policy.check_env_read("DENYX_AUTH_TOKEN").is_err(),
        "negation cannot circumvent the reserved-name invariant"
    );
}

#[test]
fn subprocess_env_filters_reserved_names_even_in_allow_vars() {
    // Attack: the policy lists DENYX_AUTH_TOKEN in allow_vars AND
    // declares a subprocess command. A naive port might pass the
    // token through to the child env (since allow_vars is the
    // primary list `subprocess_env` consults). The runtime
    // filters reserved names out unconditionally.
    std::env::set_var("DENYX_AUTH_TOKEN", "this-must-not-leak");
    let policy = build(
        r#"
[environment]
allow_vars = ["DENYX_AUTH_TOKEN", "PATH"]

[subprocess]
allow_commands = ["echo"]
"#,
    );
    let env_pairs = policy.subprocess_env("echo");
    let names: Vec<&str> = env_pairs.iter().map(|(k, _)| k.as_str()).collect();
    assert!(
        !names.contains(&"DENYX_AUTH_TOKEN"),
        "DENYX_AUTH_TOKEN must NOT be in child env; got: {names:?}"
    );
    // Sanity: PATH (a non-reserved name in the same allow list)
    // still passes through.
    assert!(
        names.contains(&"PATH"),
        "PATH should still propagate to children"
    );
    std::env::remove_var("DENYX_AUTH_TOKEN");
}

#[test]
fn all_reserved_names_consistently_denied() {
    // For every name on the reserved list, all three attack paths
    // (allow_vars, local_only_vars, both) must fail.
    for name in DENYX_RESERVED_VAR_NAMES {
        for clause in [
            format!("[environment]\nallow_vars = [\"{name}\"]"),
            format!("[environment]\nlocal_only_vars = [\"{name}\"]"),
            format!("[environment]\nallow_vars = [\"{name}\"]\nlocal_only_vars = [\"{name}\"]"),
        ] {
            let policy = build(&clause);
            assert!(
                policy.check_env_read(name).is_err(),
                "policy with `{clause}` should still deny env.read({name})"
            );
        }
    }
}

#[test]
fn similarly_named_but_not_reserved_vars_still_work() {
    // The reserved list is an explicit set, NOT a prefix. Test
    // fixtures and operator-managed conventions sometimes use
    // names that start with `DENYX_` (the exfil probe uses
    // `DENYX_DEMO_SECRET`). Those must continue to work — only
    // the curated list is reserved.
    let policy = build(
        r#"
[environment]
allow_vars = ["DENYX_DEMO_SECRET", "DENYX_TAINT_TEST_VAR", "DENYX_NOT_A_RESERVED_NAME"]
"#,
    );
    for name in [
        "DENYX_DEMO_SECRET",
        "DENYX_TAINT_TEST_VAR",
        "DENYX_NOT_A_RESERVED_NAME",
    ] {
        assert!(
            policy.check_env_read(name).is_ok(),
            "non-reserved {name} (despite DENYX_ prefix) should be readable when in allow_vars"
        );
    }
}
