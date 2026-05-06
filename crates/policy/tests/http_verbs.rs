//! Per-verb HTTP allow-list tests.
//!
//! `check_http_get` and `check_http_post` were already covered by
//! the main policy test suite. PUT / PATCH / DELETE were added later
//! and never got matching coverage; this file fills that gap.
//!
//! The tests mirror the GET/POST shape: each verb has its own
//! `[network].http_<verb>_allow` list, deny_hosts wins over allow,
//! deny_ips wins over both via the resolved-IP path, and a denied
//! verb cleanly errors with a typed `HostDenied`.

use std::path::PathBuf;

use aegis_policy::{Policy, PolicyFile};

fn build(toml: &str) -> Policy {
    let file = PolicyFile::from_toml_str(toml).unwrap();
    Policy::from_file(file, PathBuf::from("/tmp")).unwrap()
}

// ---- PUT -----------------------------------------------------------------

#[test]
fn http_put_allow_accepts_listed_host() {
    let p = build(
        r#"
[network]
http_put_allow = ["api.example.com"]
"#,
    );
    let url = p
        .check_http_put("https://api.example.com/v1/widgets/42")
        .unwrap();
    assert_eq!(url.host_str(), Some("api.example.com"));
}

#[test]
fn http_put_denies_unlisted_host() {
    let p = build(
        r#"
[network]
http_put_allow = ["api.example.com"]
"#,
    );
    let err = p.check_http_put("https://other.example/").unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("other.example"), "{msg}");
}

#[test]
fn http_put_glob_matches_subdomain() {
    let p = build(
        r#"
[network]
http_put_allow = ["*.example.com"]
"#,
    );
    p.check_http_put("https://api.example.com/").unwrap();
    p.check_http_put("https://staging.example.com/x").unwrap();
    assert!(p.check_http_put("https://example.org/").is_err());
}

#[test]
fn http_put_deny_hosts_wins_over_allow() {
    let p = build(
        r#"
[network]
http_put_allow = ["*.example.com"]
deny_hosts = ["evil.example.com"]
"#,
    );
    p.check_http_put("https://good.example.com/").unwrap();
    assert!(p.check_http_put("https://evil.example.com/").is_err());
}

// ---- PATCH ---------------------------------------------------------------

#[test]
fn http_patch_allow_accepts_listed_host() {
    let p = build(
        r#"
[network]
http_patch_allow = ["api.example.com"]
"#,
    );
    p.check_http_patch("https://api.example.com/v1/widgets/42")
        .unwrap();
}

#[test]
fn http_patch_denies_unlisted_host() {
    let p = build(
        r#"
[network]
http_patch_allow = ["api.example.com"]
"#,
    );
    assert!(p.check_http_patch("https://other.example/").is_err());
}

#[test]
fn http_patch_independent_of_get_allow() {
    // A host that's allowed for GET should NOT automatically be
    // allowed for PATCH unless it's in http_patch_allow too. Per-verb
    // allow lists are the whole point.
    let p = build(
        r#"
[network]
http_get_allow   = ["api.example.com"]
http_patch_allow = []
"#,
    );
    p.check_http_get("https://api.example.com/").unwrap();
    assert!(p.check_http_patch("https://api.example.com/").is_err());
}

// ---- DELETE --------------------------------------------------------------

#[test]
fn http_delete_allow_accepts_listed_host() {
    let p = build(
        r#"
[network]
http_delete_allow = ["api.example.com"]
"#,
    );
    p.check_http_delete("https://api.example.com/v1/widgets/42")
        .unwrap();
}

#[test]
fn http_delete_denies_unlisted_host() {
    let p = build(
        r#"
[network]
http_delete_allow = ["api.example.com"]
"#,
    );
    assert!(p.check_http_delete("https://other.example/").is_err());
}

#[test]
fn http_delete_independent_of_post_allow() {
    let p = build(
        r#"
[network]
http_post_allow   = ["api.example.com"]
http_delete_allow = []
"#,
    );
    p.check_http_post("https://api.example.com/").unwrap();
    assert!(p.check_http_delete("https://api.example.com/").is_err());
}

// ---- Cross-verb consistency ---------------------------------------------

#[test]
fn empty_per_verb_allow_lists_deny_that_verb() {
    // A policy that lists nothing for a verb means the agent cannot
    // use it at all (default-deny).
    let p = build(
        r#"
[network]
http_get_allow = ["api.example.com"]
"#,
    );
    p.check_http_get("https://api.example.com/").unwrap();
    for fn_name in ["POST", "PUT", "PATCH", "DELETE"] {
        let err = match fn_name {
            "POST" => p.check_http_post("https://api.example.com/"),
            "PUT" => p.check_http_put("https://api.example.com/"),
            "PATCH" => p.check_http_patch("https://api.example.com/"),
            "DELETE" => p.check_http_delete("https://api.example.com/"),
            _ => unreachable!(),
        };
        assert!(
            err.is_err(),
            "verb {fn_name} should be denied when its allow list is empty"
        );
    }
}

#[test]
fn deny_ips_blocks_all_verbs() {
    // The deny_ips list applies to every verb.
    let p = build(
        r#"
[network]
http_get_allow    = ["169.254.169.254"]
http_post_allow   = ["169.254.169.254"]
http_put_allow    = ["169.254.169.254"]
http_patch_allow  = ["169.254.169.254"]
http_delete_allow = ["169.254.169.254"]

# secure-defaults' link-local CIDR mirrored locally for clarity.
deny_ips = ["169.254.0.0/16"]
"#,
    );
    let url = "http://169.254.169.254/latest/meta-data/";
    assert!(p.check_http_get(url).is_err());
    assert!(p.check_http_post(url).is_err());
    assert!(p.check_http_put(url).is_err());
    assert!(p.check_http_patch(url).is_err());
    assert!(p.check_http_delete(url).is_err());
}
