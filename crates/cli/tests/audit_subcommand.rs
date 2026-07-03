//! Integration tests for `denyx audit verify` and the audit-log
//! protected-path guard wired into `denyx run`.

use std::path::PathBuf;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_denyx");

fn fresh_dir(prefix: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "denyx_audit_subcmd_{}_{}_{}",
        prefix,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn audit_verify_clean_chain_succeeds() {
    let dir = fresh_dir("verify_ok");
    let log = dir.join("audit.jsonl");
    // Write a hand-crafted 2-line valid chain.
    let l1 = serde_json::json!({
        "ts": "2026-05-05T00:00:00Z",
        "task_id": "t", "step": 1, "capability": "env.read",
        "status": "allowed", "detail": {"name": "PATH", "error": null},
        "denyx_seq": 1,
        "denyx_prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
    });
    let l1s = serde_json::to_string(&l1).unwrap();
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(l1s.as_bytes());
    let l1_hex: String = h.finalize().iter().map(|b| format!("{:02x}", b)).collect();

    let l2 = serde_json::json!({
        "ts": "2026-05-05T00:00:01Z",
        "task_id": "t", "step": 2, "capability": "env.read",
        "status": "allowed", "detail": {"name": "USER", "error": null},
        "denyx_seq": 2,
        "denyx_prev_hash": l1_hex,
    });
    let l2s = serde_json::to_string(&l2).unwrap();
    std::fs::write(&log, format!("{l1s}\n{l2s}\n")).unwrap();

    let out = Command::new(BIN)
        .args(["audit", "verify"])
        .arg(&log)
        .output()
        .expect("spawn");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("OK:"));
    assert!(stdout.contains("2 entries"));
}

#[test]
fn audit_verify_min_seq_passes_when_met_and_fails_when_truncated() {
    // Round-4 pentest finding: verify_chain alone can't distinguish
    // an honestly-short log from one whose tail was truncated (both
    // are internally consistent). --min-seq is the mitigation: an
    // operator who remembers the log's previous length can catch a
    // regression.
    let dir = fresh_dir("verify_min_seq");
    let log = dir.join("audit.jsonl");
    let l1 = serde_json::json!({
        "ts": "2026-05-05T00:00:00Z",
        "task_id": "t", "step": 1, "capability": "env.read",
        "status": "allowed", "detail": {"name": "PATH", "error": null},
        "denyx_seq": 1,
        "denyx_prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
    });
    let l1s = serde_json::to_string(&l1).unwrap();
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(l1s.as_bytes());
    let l1_hex: String = h.finalize().iter().map(|b| format!("{:02x}", b)).collect();

    let l2 = serde_json::json!({
        "ts": "2026-05-05T00:00:01Z",
        "task_id": "t", "step": 2, "capability": "env.read",
        "status": "allowed", "detail": {"name": "USER", "error": null},
        "denyx_seq": 2,
        "denyx_prev_hash": l1_hex,
    });
    let l2s = serde_json::to_string(&l2).unwrap();

    // Full 2-line log: --min-seq 2 must pass.
    std::fs::write(&log, format!("{l1s}\n{l2s}\n")).unwrap();
    let out_full = Command::new(BIN)
        .args(["audit", "verify", "--min-seq", "2"])
        .arg(&log)
        .output()
        .expect("spawn");
    assert!(
        out_full.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out_full.stderr)
    );

    // Truncated to just the first line (simulating a deleted last
    // event): internally valid on its own, but now below the
    // previously-recorded minimum of 2.
    let truncated = dir.join("audit_truncated.jsonl");
    std::fs::write(&truncated, format!("{l1s}\n")).unwrap();
    let out_truncated_no_check = Command::new(BIN)
        .args(["audit", "verify"])
        .arg(&truncated)
        .output()
        .expect("spawn");
    assert!(
        out_truncated_no_check.status.success(),
        "a truncated-but-internally-consistent log must still report \
         valid without --min-seq — that's the whole point of the finding"
    );

    let out_truncated_checked = Command::new(BIN)
        .args(["audit", "verify", "--min-seq", "2"])
        .arg(&truncated)
        .output()
        .expect("spawn");
    assert!(
        !out_truncated_checked.status.success(),
        "--min-seq 2 must fail against a log truncated down to seq 1"
    );
    let stderr = String::from_utf8_lossy(&out_truncated_checked.stderr);
    assert!(stderr.contains("BELOW"), "stderr: {stderr}");
}

#[test]
fn audit_verify_tampered_log_fails_with_specific_line_number() {
    let dir = fresh_dir("verify_fail");
    let log = dir.join("audit.jsonl");
    // Two valid chained lines, but mutate line 2's seq to bogus.
    let l1 = serde_json::json!({
        "ts": "T", "task_id": "t", "step": 1, "capability": "env.read",
        "status": "allowed", "detail": {},
        "denyx_seq": 1,
        "denyx_prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
    });
    let l1s = serde_json::to_string(&l1).unwrap();
    let l2 = serde_json::json!({
        "ts": "T", "task_id": "t", "step": 2, "capability": "env.read",
        "status": "allowed", "detail": {},
        "denyx_seq": 999,   // jump
        "denyx_prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",  // wrong
    });
    let l2s = serde_json::to_string(&l2).unwrap();
    std::fs::write(&log, format!("{l1s}\n{l2s}\n")).unwrap();

    let out = Command::new(BIN)
        .args(["audit", "verify"])
        .arg(&log)
        .output()
        .expect("spawn");
    assert!(!out.status.success(), "should fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("BROKEN"));
    assert!(stderr.contains("line 2"));
    // Should report at least one of: seq jump and/or prev_hash
    // mismatch (this fixture has both).
    assert!(
        stderr.contains("denyx_seq jump") || stderr.contains("denyx_prev_hash mismatch"),
        "expected reason in stderr: {stderr}"
    );
}

#[test]
fn audit_verify_missing_file_fails_cleanly() {
    let out = Command::new(BIN)
        .args(["audit", "verify", "/tmp/denyx_does_not_exist_99999.jsonl"])
        .output()
        .expect("spawn");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.is_empty());
}

#[test]
fn denyx_run_refuses_audit_log_path_reachable_to_agent() {
    // If the policy grants write access to the audit-log path, the
    // run path must refuse to start (the agent could otherwise
    // tamper with its own audit trail).
    let dir = fresh_dir("guard");
    let policy_path = dir.join("denyx.toml");
    let log = dir.join("audit.jsonl");
    let log_str = log.to_string_lossy().replace('\\', "/");
    let body = format!(
        r#"
[filesystem]
write_allow = ["{log_str}"]
"#
    );
    std::fs::write(&policy_path, body).unwrap();
    let script = dir.join("noop.star");
    std::fs::write(&script, "x = 1\n").unwrap();

    let out = Command::new(BIN)
        .args(["run", "--policy"])
        .arg(&policy_path)
        .arg("--audit-log")
        .arg(&log)
        .arg(&script)
        .output()
        .expect("spawn");
    assert!(!out.status.success(), "should refuse");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("audit log") || stderr.contains("audit-log"),
        "expected audit-log guard error in stderr: {stderr}"
    );
}
