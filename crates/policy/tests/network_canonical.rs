//! AEG-PEN-R5-008: unspecified addresses reach loopback on Linux and
//! must never be connectable.
//! AEG-PEN-R5-009: host patterns must match the same host however its
//! name is spelled (trailing root dot, ASCII case).

use std::net::IpAddr;
use std::path::PathBuf;

use denyx_policy::{Policy, PolicyFile};

fn build(toml: &str) -> Policy {
    let file = PolicyFile::from_toml_str(toml)
        .unwrap()
        .resolve_inheritance()
        .unwrap();
    Policy::from_file(file, PathBuf::from("/tmp")).unwrap()
}

const WILDCARD: &str = r#"
[network]
http_get_allow = ["*"]
"#;

#[test]
fn unspecified_ip_literals_are_denied_without_any_preset() {
    let p = build(WILDCARD);
    for url in [
        "http://0.0.0.0:8080/",
        "http://0:8080/",
        "http://[::]:8080/",
        "http://[::ffff:0.0.0.0]:8080/",
    ] {
        assert!(p.check_http_get(url).is_err(), "{url} must be denied");
    }
}

#[test]
fn unspecified_resolved_ip_is_denied_without_any_preset() {
    let p = build(WILDCARD);
    for ip in ["0.0.0.0", "::"] {
        let ip: IpAddr = ip.parse().unwrap();
        assert!(
            p.check_resolved_ip("http_get", "evil.example", ip).is_err(),
            "resolved {ip} must be denied"
        );
    }
}

#[test]
fn secure_defaults_denies_this_network_cgnat_and_ipv4_embedding_ranges() {
    let p = build(
        r#"
inherits = "secure-defaults"
[network]
http_get_allow = ["*"]
"#,
    );
    for ip in [
        "0.1.2.3",
        "100.100.100.200",
        "::127.0.0.1",
        "64:ff9b::7f00:1",
    ] {
        let ip: IpAddr = ip.parse().unwrap();
        assert!(
            p.check_resolved_ip("http_get", "h", ip).is_err(),
            "secure-defaults must deny {ip}"
        );
    }
}

#[test]
fn negating_ipv6_loopback_still_reallows_it_under_secure_defaults() {
    let p = build(
        r#"
inherits = "secure-defaults"
[network]
http_get_allow = ["*"]
deny_ips = ["!127.0.0.0/8", "!::1/128"]
"#,
    );
    for ip in ["::1", "127.0.0.1"] {
        let ip: IpAddr = ip.parse().unwrap();
        assert!(
            p.check_resolved_ip("http_get", "h", ip).is_ok(),
            "{ip} should be re-allowed by the negation"
        );
    }
}

#[test]
fn trailing_dot_does_not_escape_deny_hosts() {
    let p = build(
        r#"
[network]
http_get_allow = ["*"]
deny_hosts = ["evil.example.com", "*.blocked.example.com"]
"#,
    );
    for url in [
        "http://evil.example.com./",
        "http://x.blocked.example.com./",
    ] {
        assert!(p.check_http_get(url).is_err(), "{url} must be denied");
    }
}

#[test]
fn uppercase_pattern_still_matches_lowercased_host() {
    let p = build(
        r#"
[network]
http_get_allow = ["*"]
deny_hosts = ["Evil.Example.COM"]
"#,
    );
    assert!(p.check_http_get("http://evil.example.com/").is_err());
}

#[test]
fn trailing_dot_host_is_still_local_only() {
    let p = build(
        r#"
[network]
local_only_hosts = ["vault.example.com"]
"#,
    );
    let url = p.check_http_get("http://vault.example.com./s").unwrap();
    assert!(p.host_is_local_only(url.host_str().unwrap()));
}

#[test]
fn trailing_dot_allow_still_permits_canonical_host() {
    let p = build(
        r#"
[network]
http_get_allow = ["api.example.com."]
"#,
    );
    assert!(p.check_http_get("https://api.example.com/").is_ok());
    assert!(p.check_http_get("https://api.example.com./").is_ok());
}
