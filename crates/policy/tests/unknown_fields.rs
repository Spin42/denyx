//! AEG-PEN-R5-017: a misspelled key must fail policy load. Allow-list
//! typos fail closed on their own (default deny), but a typo in a deny
//! list, a limit, or a section header silently dropped a restriction.

use denyx_policy::PolicyFile;

fn rejects(toml: &str) {
    assert!(
        PolicyFile::from_toml_str(toml).is_err(),
        "policy with a misspelled key was accepted:\n{toml}"
    );
}

#[test]
fn misspelled_deny_list_is_rejected() {
    rejects("[filesystem]\ndenny = [\"secret/**\"]\n");
}

#[test]
fn misspelled_section_is_rejected() {
    rejects("[enviroment]\ndeny_vars = [\"X\"]\n");
}

#[test]
fn misspelled_runtime_limit_is_rejected() {
    rejects("[runtime]\nmax_secs = 1\n");
}

#[test]
fn misspelled_top_level_key_is_rejected() {
    rejects("requires_aproval = [\"fs.delete\"]\n");
}

#[test]
fn misspelled_subprocess_and_network_keys_are_rejected() {
    rejects("[subprocess]\ndeny_comands = [\"bash\"]\n");
    rejects("[network]\ndeny_host = [\"evil.example\"]\n");
}

#[test]
fn removed_functions_block_names_the_replacement() {
    // `[functions].allow` once restricted capabilities; it is ignored
    // now, so a policy that still carries it grants more than its author
    // believes. Load fails and says what replaced it.
    let err = PolicyFile::from_toml_str("[functions]\nallow = [\"fs.read\"]\n").unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("[functions]") && msg.contains("resource sections"),
        "unhelpful error: {msg}"
    );
}

#[test]
fn well_formed_policy_still_loads() {
    PolicyFile::from_toml_str(
        r#"
inherits = "secure-defaults"
requires_approval = ["fs.delete"]
[filesystem]
read_allow = ["src/**"]
deny = ["secret/**"]
[network]
deny_hosts = ["evil.example"]
[runtime]
max_seconds = 5
[environment]
deny_vars = ["X"]
[subprocess]
deny_commands = ["bash"]
"#,
    )
    .unwrap();
}
