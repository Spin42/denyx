//! Tests for redirect-blocking. The headline property: a redirect
//! returned by an allowed origin is NOT auto-followed by Aegis. The
//! script sees a clear error pointing at the Location header and
//! must call net.http_get / post again with the new URL — which
//! goes through the [network] policy gate, including the deny_ips
//! / allow_hosts check.
//!
//! Without this fix, a permissive origin (`https://example.com`)
//! could redirect to an internal IP (`http://10.0.0.1/`) and ureq's
//! default 5-redirect policy would follow it without Aegis having
//! any visibility into the new URL.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::thread;

use aegis_host::Runner;
use aegis_policy::{Policy, PolicyFile};

fn runner_for(toml: &str) -> Runner {
    let file = PolicyFile::from_toml_str(toml).unwrap();
    let policy = Policy::from_file(file, std::env::temp_dir()).unwrap();
    Runner::new(policy)
}

/// Spin a local TCP listener that responds to one HTTP request with
/// a 302 redirect, then closes. Returns the bound port.
fn spawn_redirect_server(redirect_to: &'static str) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf);
            let response = format!(
                "HTTP/1.1 302 Found\r\nLocation: {}\r\nContent-Length: 0\r\n\r\n",
                redirect_to
            );
            let _ = sock.write_all(response.as_bytes());
        }
    });
    port
}

#[test]
fn redirect_to_internal_ip_does_not_silently_follow() {
    let port = spawn_redirect_server("http://10.0.0.1/internal");
    let toml = format!(
        r#"
[network]
http_get_allow = ["127.0.0.1"]
"#
    );
    let runner = runner_for(&toml);
    let src = format!(
        r#"out = net.http_get("http://127.0.0.1:{port}/maybe-redirect")
print(out)
"#
    );
    let err = runner.run("t", &src, "test.star").unwrap_err();
    let msg = err.to_string();
    // The error should clearly mention the redirect AND the
    // Location target so the script (or operator reading logs)
    // can see what was attempted.
    assert!(
        msg.contains("302") || msg.contains("redirect"),
        "expected redirect error, got: {msg}"
    );
    assert!(
        msg.contains("10.0.0.1"),
        "error should name the redirect target so it's auditable: {msg}"
    );
}

#[test]
fn pure_policy_finalize_redirect_returns_error() {
    // Direct unit-style smoke test: given a 3xx Response, the
    // finalize helper must error and name the Location.
    //
    // We can't easily synthesize a ureq::Response without an actual
    // HTTP roundtrip, so this test goes through a local server.
    let port = spawn_redirect_server("https://elsewhere.example.com/x");
    let toml = format!(
        r#"
[network]
http_get_allow = ["127.0.0.1"]
"#
    );
    let runner = runner_for(&toml);
    let src = format!(r#"net.http_get("http://127.0.0.1:{port}/")"#);
    let err = runner.run("t", &src, "test.star").unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("elsewhere.example.com"), "got: {msg}");
    assert!(
        msg.contains("does not auto-follow") || msg.contains("redirect"),
        "got: {msg}"
    );
}
