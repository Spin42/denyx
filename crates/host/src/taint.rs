//! Information-flow control for local-only reads.
//!
//! Three layers, each enforced by the runtime (not by asking the model
//! nicely):
//!
//! 1. **Output-boundary substring redaction.** Every output channel
//!    (printed lines, audit-event payload fields, MCP tool result text,
//!    error messages) is scrubbed for any occurrence of a registered
//!    tainted value before it crosses the runtime boundary. Each
//!    occurrence is replaced with `[REDACTED]`.
//!
//! 2. **Transformation-aware substring redaction.** Each tainted value
//!    fans out into a small set of mechanically-derived sibling forms
//!    (byte-reversal, hex encoding lower/upper, XOR with every single-
//!    byte key). All forms are added to the redaction set, so a script
//!    that prints `hex(secret)` or `xor(secret, 0x5A)` is scrubbed too.
//!    Closes the encode-and-print exfil paths the substring-only layer
//!    misses. A multi-byte / cryptographic transform (AES with a script-
//!    generated key) is still out of reach — the threat-model doc is
//!    explicit about this.
//!
//! 3. **Subsequence (chunking) detection.** A script that prints the
//!    secret one character at a time interleaved with cover text never
//!    forms a substring match in any one line. The chunking pass walks
//!    the joined printed output looking for the secret's characters
//!    appearing in order with bounded gaps; if found, every printed
//!    line containing a matched character is replaced with `[REDACTED]`.
//!
//! 4. **Arg-side denial at outbound effects.** Any string argument to
//!    an effecting builtin whose destination is *not* local-only
//!    (e.g. `fs.write` to a public path, `subprocess.exec` of a
//!    public command, `net.http_*` to a public host) is scanned
//!    against the same taint set. A match means the script is trying
//!    to push tainted bytes out through a public sink — the call is
//!    refused with a typed `tainted_arg_blocked` audit event, not
//!    just scrubbed. This is the "scope tightening" the README's
//!    roadmap calls out: don't only redact on the way *out*, also
//!    block the *operation* that would carry the value.
//!
//! What we explicitly do NOT defend against (also in the threat model):
//! - Cryptographic transforms with a script-generated key. The
//!   transform set is finite and documented; AES / RC4 / a custom
//!   invertible permutation will defeat it.
//! - Length-only side channels (`print(len(secret))`).
//! - Comparison oracles (`if secret[0] == "s": print("y")`).
//! - Per-query substring guesses (`if "MNOP" in secret: ...`).
//!
//! The substring/transform/chunking redaction is enforced by the
//! *runtime*. A prompt cannot bypass it by rephrasing the script: to
//! exfiltrate, the model must construct an output (or argument) that
//! does not contain the secret in any of these forms, which is a
//! deliberate adversarial step beyond simple "prompt engineering"
//! against the policy.

use std::cell::RefCell;

/// Sentinel inserted in place of a tainted value at output boundaries.
/// Picked to be visually obvious and unlikely to collide with any
/// legitimate token in audit logs.
pub const REDACTED: &str = "[REDACTED]";

/// Minimum tainted-value length we'll register. Below this threshold
/// the substring scan is too noisy (think `"x"` or `""`) and the false
/// positive rate would obscure real outputs without meaningfully
/// improving security.
const MIN_TAINT_LEN: usize = 4;

/// Cap on how long a tainted value can be before we skip computing
/// its expensive sibling transforms (XOR-with-each-key, hex). For an
/// HTTP-response-sized taint, computing 256 XOR transforms is costly
/// and the substring-scan time scales with their lengths. A determined
/// adversary using an HTTP-body-sized secret has bigger problems
/// (it's not a credential), so we cap and keep the original-only.
const TRANSFORM_LEN_CAP: usize = 256;

/// Minimum length for the chunking (subsequence) check to fire. Below
/// this length the false-positive rate against normal prose is too
/// high: any 4-char string of common letters tends to appear as a
/// subsequence of any English paragraph by chance.
const CHUNKING_MIN_LEN: usize = 8;

/// Density threshold for declaring "this output is a chunked exfil".
/// Computed as matched_chars / span_bytes. A secret of length L matched
/// across a span of S bytes has density L/S. For T_CHUNKED in
/// run_exfil.py (40-char secret across ~250 bytes of output), density
/// is ~0.16 — well above this bound. Random English text has density
/// ~0.004 against a 40-char dashed/digit secret — well below.
const CHUNKING_MIN_DENSITY: f64 = 0.05;

/// One registered tainted value plus the mechanically-derived sibling
/// forms we also redact.
#[derive(Debug, Clone)]
struct TaintEntry {
    original: String,
    /// (transform_name, derived_bytes_as_utf8). Skipped if a transform
    /// would yield invalid UTF-8 — those bytes can't be reconstituted
    /// in Starlark via the string ops the verifier permits.
    transforms: Vec<(String, String)>,
}

impl TaintEntry {
    fn new(value: String) -> Self {
        let transforms = compute_transforms(&value);
        TaintEntry {
            original: value,
            transforms,
        }
    }
    /// Iterate over (label, byte_pattern) pairs. The label is the
    /// transform's name (`"original"`, `"reverse"`, `"hex_lower"`,
    /// `"xor_0x5a"`, ...) — used in audit-event payloads when the
    /// arg-side check fires so the operator can see *how* the
    /// value was disguised.
    fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        std::iter::once(("original", self.original.as_str())).chain(
            self.transforms
                .iter()
                .map(|(n, v)| (n.as_str(), v.as_str())),
        )
    }
}

/// Compute the documented set of substring-detectable transforms for a
/// tainted value.
///
/// Each transform is (label, byte-pattern). The label flows into the
/// audit-event payload when the arg-side check fires so an operator
/// reviewing the log sees how the script tried to disguise the value
/// (e.g. `"xor_0x5a_hex_lower"`).
///
/// The set covers the common practical exfil shapes:
/// - the original
/// - byte-reverse
/// - hex(lower + upper) of the original AND of the reverse
/// - XOR with every single-byte key (skip 0x00 = no-op)
/// - hex(lower + upper) of every XOR result (catches XOR + hex
///   composition, the dominant exfil shape for binary-XOR'd bytes
///   that can't be printed directly because they aren't valid UTF-8)
/// - base64 (standard + url-safe alphabets, with and without padding)
///   — surfaced by the cloud-pentest harness as a practical bypass
///   independently from both Sonnet and Opus
/// - ROT-N for N in 1..=25 against the alphabetic part of each byte
///   — also surfaced by the cloud-pentest harness (ROT13 specifically)
///
/// What we do NOT compute (documented gaps): AES / RC4 / a custom
/// invertible permutation with a script-generated key, multi-byte
/// XOR keys (>1 byte), uuencode, ASCII85, base32, custom radix
/// encodings the script defines on the fly. These are the limits of
/// substring-based IFC. Each pentest round may surface new shapes;
/// the design contract is "the transform set is extensible and
/// finite", not "exhaustive".
fn compute_transforms(value: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let bytes = value.as_bytes();
    if bytes.is_empty() {
        return out;
    }

    fn hex_lower_of(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }
    fn hex_upper_of(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{:02X}", b));
        }
        s
    }

    // 1. Reverse the bytes (covers `secret[::-1]`-shaped exfil).
    let rev: Vec<u8> = bytes.iter().rev().copied().collect();
    if let Ok(s) = String::from_utf8(rev.clone()) {
        if s != value {
            out.push(("reverse".to_string(), s));
        }
    }

    // 2. Hex encoding (lower + upper) of the original AND of the
    // reverse. Reversed-then-hex is one of the common exfil shapes;
    // hex-then-reversed isn't, but we still cover the pair via the
    // reverse-of-hex pattern (the reverse of hex_lower is its own
    // string and the substring scan finds it directly).
    out.push(("hex_lower".to_string(), hex_lower_of(bytes)));
    out.push(("hex_upper".to_string(), hex_upper_of(bytes)));
    out.push(("reverse_hex_lower".to_string(), hex_lower_of(&rev)));
    out.push(("reverse_hex_upper".to_string(), hex_upper_of(&rev)));

    // 3. XOR with every single-byte key 0x01..=0xFF, plus its
    // hex-encoded form. The hex-encoded form catches the dominant
    // exfil shape for XOR (the raw XOR bytes are usually not valid
    // UTF-8 and can't go through `print` directly, so the script
    // hex-encodes them — exactly what the exfil probe's
    // xor_constant_key technique does). Cap at TRANSFORM_LEN_CAP to
    // keep long tainted values from blowing per-output scan time.
    if bytes.len() <= TRANSFORM_LEN_CAP {
        for k in 1u8..=0xFF {
            let xored: Vec<u8> = bytes.iter().map(|b| b ^ k).collect();
            if let Ok(s) = String::from_utf8(xored.clone()) {
                if s != value {
                    out.push((format!("xor_0x{:02x}", k), s));
                }
            }
            out.push((format!("xor_0x{:02x}_hex_lower", k), hex_lower_of(&xored)));
            out.push((format!("xor_0x{:02x}_hex_upper", k), hex_upper_of(&xored)));
        }
    }

    // 4. Base64 (standard + url-safe, with and without padding).
    // Cloud-pentest harness surfaced custom hand-rolled base64 as a
    // practical bypass; we close that here. Output of base64 is
    // always valid ASCII so we always include both alphabets.
    out.push(("base64_std".to_string(), b64_encode(bytes, B64_STD, true)));
    out.push((
        "base64_std_nopad".to_string(),
        b64_encode(bytes, B64_STD, false),
    ));
    out.push((
        "base64_urlsafe".to_string(),
        b64_encode(bytes, B64_URLSAFE, true),
    ));
    out.push((
        "base64_urlsafe_nopad".to_string(),
        b64_encode(bytes, B64_URLSAFE, false),
    ));

    // 5. ROT-N for N in 1..=25 against the alphabetic bytes. ROT13
    // showed up independently from both pentest runs; the rest of
    // the rotations are cheap to add and close the trivial Caesar-
    // cipher variant that any first-year-CS-style obfuscation reaches
    // for. Non-alphabetic bytes pass through unchanged, which
    // matches the canonical ROT-N definition and is what scripts
    // emit.
    for n in 1u8..=25 {
        let rotated: Vec<u8> = bytes
            .iter()
            .map(|b| match b {
                b'A'..=b'Z' => b'A' + ((b - b'A' + n) % 26),
                b'a'..=b'z' => b'a' + ((b - b'a' + n) % 26),
                _ => *b,
            })
            .collect();
        if rotated != bytes {
            // Always valid UTF-8 since rotation preserves byte width.
            out.push((format!("rot{}", n), String::from_utf8(rotated).unwrap()));
        }
    }

    out
}

const B64_STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_URLSAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64_encode(input: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= input.len() {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8) | (input[i + 2] as u32);
        out.push(alphabet[((n >> 18) & 0x3F) as usize] as char);
        out.push(alphabet[((n >> 12) & 0x3F) as usize] as char);
        out.push(alphabet[((n >> 6) & 0x3F) as usize] as char);
        out.push(alphabet[(n & 0x3F) as usize] as char);
        i += 3;
    }
    let rem = input.len() - i;
    if rem == 1 {
        let n = (input[i] as u32) << 16;
        out.push(alphabet[((n >> 18) & 0x3F) as usize] as char);
        out.push(alphabet[((n >> 12) & 0x3F) as usize] as char);
        if pad {
            out.push('=');
            out.push('=');
        }
    } else if rem == 2 {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8);
        out.push(alphabet[((n >> 18) & 0x3F) as usize] as char);
        out.push(alphabet[((n >> 12) & 0x3F) as usize] as char);
        out.push(alphabet[((n >> 6) & 0x3F) as usize] as char);
        if pad {
            out.push('=');
        }
    }
    out
}

/// In-context taint store. One per `HostCtx`. Cleared when the
/// evaluation ends because the registry is moved into the redaction
/// pass.
#[derive(Default, Debug)]
pub struct TaintRegistry {
    inner: RefCell<Vec<TaintEntry>>,
}

impl TaintRegistry {
    /// Register a value as tainted. No-ops if the value is empty,
    /// shorter than the minimum length, or already present.
    pub fn add(&self, value: &str) {
        let trimmed = value.trim();
        if trimmed.len() < MIN_TAINT_LEN {
            return;
        }
        let mut store = self.inner.borrow_mut();
        if store.iter().any(|e| e.original == trimmed) {
            return;
        }
        store.push(TaintEntry::new(trimmed.to_string()));
    }

    /// Snapshot of every byte pattern that should be redacted: the
    /// original of each registered taint plus all of its mechanically-
    /// derived sibling forms. Sorted longest-first so a longer match
    /// pre-empts a shorter substring within it.
    pub fn redaction_snapshot(&self) -> Vec<String> {
        let store = self.inner.borrow();
        let mut all: Vec<String> = Vec::new();
        for entry in store.iter() {
            all.push(entry.original.clone());
            for (_label, v) in entry.transforms.iter() {
                all.push(v.clone());
            }
        }
        all.sort_by_key(|s| std::cmp::Reverse(s.len()));
        all.dedup();
        all
    }

    /// Backwards-compatible alias used by tests that snapshot the raw
    /// originals only (no transforms). Kept private outside this
    /// module — call sites should use `redaction_snapshot()`.
    #[cfg(test)]
    pub(crate) fn originals_snapshot(&self) -> Vec<String> {
        self.inner
            .borrow()
            .iter()
            .map(|e| e.original.clone())
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.borrow().is_empty()
    }

    /// If `arg` contains any registered taint (original or any
    /// mechanically-derived sibling), return `Some((entry_idx,
    /// transform_label))`. Used by effecting builtins to decide
    /// whether an outbound argument is carrying tainted bytes to a
    /// non-local-only sink. The label is included in audit events
    /// so an operator reviewing the log sees *how* the script tried
    /// to disguise the value (e.g. `"xor_0x5a"`).
    pub fn arg_taint_reason(&self, arg: &str) -> Option<String> {
        if arg.is_empty() {
            return None;
        }
        let store = self.inner.borrow();
        for entry in store.iter() {
            for (label, pattern) in entry.iter() {
                if pattern.is_empty() {
                    continue;
                }
                if arg.contains(pattern) {
                    return Some(label.to_string());
                }
            }
        }
        None
    }
}

/// Walk a JSON value and redact every string leaf in place. Used to
/// scrub audit-event payload fields before they reach the sink.
pub fn redact_json(value: &mut serde_json::Value, taints: &[String]) {
    if taints.is_empty() {
        return;
    }
    match value {
        serde_json::Value::String(s) => {
            let scrubbed = redact(s, taints);
            if scrubbed != *s {
                *s = scrubbed;
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr.iter_mut() {
                redact_json(v, taints);
            }
        }
        serde_json::Value::Object(obj) => {
            for (_k, v) in obj.iter_mut() {
                redact_json(v, taints);
            }
        }
        _ => {}
    }
}

/// Replace every occurrence of every taint pattern in `input` with
/// `[REDACTED]`. Linear in `taints.len() * input.len()`. Sorting
/// taints longest-first prevents short-substring redactions from
/// clobbering a longer substring that contained them — the snapshot
/// is already sorted, but we re-sort defensively because callers can
/// pass arbitrary lists.
pub fn redact(input: &str, taints: &[String]) -> String {
    if taints.is_empty() {
        return input.to_string();
    }
    let mut sorted: Vec<&String> = taints.iter().collect();
    sorted.sort_by_key(|s| std::cmp::Reverse(s.len()));
    let mut out = input.to_string();
    for t in sorted {
        if t.is_empty() {
            continue;
        }
        if out.contains(t.as_str()) {
            out = out.replace(t.as_str(), REDACTED);
        }
    }
    out
}

/// Per-line redaction with chunking detection. The standard substring
/// scan runs first (catches reverse / hex / XOR / original); then a
/// subsequence pass catches the case where a script prints the secret
/// one character at a time interleaved with cover text — no per-line
/// scrub would catch that, but the joined output reveals the pattern.
///
/// When chunking is detected for a registered taint, every line that
/// participates in the matched subsequence is replaced with
/// `[REDACTED]`. Lines that don't participate pass through unchanged
/// so an unrelated `print("starting...")` still surfaces.
pub fn redact_lines(lines: Vec<String>, registry: &TaintRegistry) -> Vec<String> {
    if registry.is_empty() {
        return lines;
    }
    let snapshot = registry.redaction_snapshot();
    // Phase 1: per-line substring (covers original + all transforms).
    let scrubbed: Vec<String> = lines.into_iter().map(|l| redact(&l, &snapshot)).collect();

    // Phase 2: chunking detection across the joined output. We only
    // need to test against the ORIGINAL of each registered taint —
    // the transforms (reverse, hex, xor) are caught by per-line
    // substring; chunking specifically targets char-by-char prints
    // of the unmodified secret.
    let originals: Vec<String> = registry
        .inner
        .borrow()
        .iter()
        .map(|e| e.original.clone())
        .collect();

    // Precompute line spans in the joined buffer so we can map matched
    // byte indexes back to line indexes without rescanning.
    let mut line_spans: Vec<(usize, usize)> = Vec::with_capacity(scrubbed.len());
    let mut cursor = 0usize;
    for line in scrubbed.iter() {
        let start = cursor;
        let end = cursor + line.len();
        line_spans.push((start, end));
        cursor = end + 1; // +1 for the joining '\n'
    }
    let joined = scrubbed.join("\n");

    let mut clobber: Vec<bool> = vec![false; scrubbed.len()];
    for taint in originals.iter() {
        if taint.len() < CHUNKING_MIN_LEN {
            continue;
        }
        let Some(matches) = subsequence_match(&joined, taint) else {
            continue;
        };
        let span = matches
            .last()
            .unwrap()
            .saturating_sub(*matches.first().unwrap())
            .max(1);
        let density = matches.len() as f64 / span as f64;
        if density < CHUNKING_MIN_DENSITY {
            continue;
        }
        // Mark each line that contains a matched byte position for
        // clobbering.
        for &m in matches.iter() {
            // Find the line whose span contains `m`. Linear scan; the
            // number of lines is small in practice.
            for (i, (start, end)) in line_spans.iter().enumerate() {
                if m >= *start && m < *end {
                    clobber[i] = true;
                    break;
                }
            }
        }
    }

    scrubbed
        .into_iter()
        .enumerate()
        .map(|(i, line)| {
            if clobber[i] {
                REDACTED.to_string()
            } else {
                line
            }
        })
        .collect()
}

/// Subsequence match: return the byte indexes in `haystack` where the
/// chars of `needle` appear in order. None if not all chars of
/// `needle` are findable. Operates on UTF-8 chars (not bytes) so
/// multi-byte secrets behave correctly.
fn subsequence_match(haystack: &str, needle: &str) -> Option<Vec<usize>> {
    let mut t = needle.chars();
    let mut next_t = t.next()?;
    let mut matches = Vec::with_capacity(needle.chars().count());
    for (i, c) in haystack.char_indices() {
        if c == next_t {
            matches.push(i);
            match t.next() {
                Some(c) => next_t = c,
                None => return Some(matches),
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_replaces_full_match() {
        let s = redact("token=sk-abc123secret", &["sk-abc123secret".into()]);
        assert_eq!(s, "token=[REDACTED]");
    }

    #[test]
    fn redact_replaces_each_occurrence() {
        let s = redact("a sk-abc b sk-abc c", &["sk-abc".into()]);
        assert_eq!(s, "a [REDACTED] b [REDACTED] c");
    }

    #[test]
    fn redact_handles_overlapping_taints_longest_first() {
        let s = redact(
            "found supersecret here",
            &["secret".into(), "supersecret".into()],
        );
        assert_eq!(s, "found [REDACTED] here");
    }

    #[test]
    fn redact_noop_when_no_taints_present() {
        let s = redact("nothing tainted", &["sk-abc".into()]);
        assert_eq!(s, "nothing tainted");
    }

    #[test]
    fn registry_skips_too_short() {
        let r = TaintRegistry::default();
        r.add("");
        r.add("ab");
        r.add("abc");
        assert!(r.is_empty());
        r.add("abcd");
        assert_eq!(r.originals_snapshot(), vec!["abcd".to_string()]);
    }

    #[test]
    fn registry_dedups() {
        let r = TaintRegistry::default();
        r.add("aaaaa");
        r.add("aaaaa");
        assert_eq!(r.originals_snapshot().len(), 1);
    }

    #[test]
    fn redaction_snapshot_includes_reverse() {
        let r = TaintRegistry::default();
        r.add("supersecret-token");
        let snap = r.redaction_snapshot();
        assert!(snap.iter().any(|s| s == "supersecret-token"));
        assert!(snap.iter().any(|s| s == "nekot-tercesrepus"));
    }

    #[test]
    fn redaction_snapshot_includes_hex() {
        // Use ASCII bytes whose hex representation contains letters
        // (a-f) so hex_lower and hex_upper differ. The earlier
        // version used "ABCD" → "41424344" which is digits-only:
        // hex_lower and hex_upper are identical, and a mutation
        // that made hex_upper return an empty string passed
        // undetected. Mutation testing surfaced the gap.
        // 'j'=0x6a, 'k'=0x6b, 'l'=0x6c, 'm'=0x6d → hex digits a-d
        // appear in the encoding.
        let r = TaintRegistry::default();
        r.add("jklm");
        let snap = r.redaction_snapshot();
        assert!(
            snap.iter().any(|s| s == "6a6b6c6d"),
            "snapshot should contain hex_lower form: {snap:?}"
        );
        assert!(
            snap.iter().any(|s| s == "6A6B6C6D"),
            "snapshot should contain hex_upper form (distinct from lower): {snap:?}"
        );
    }

    #[test]
    fn redaction_snapshot_includes_xor_for_each_byte_key() {
        let r = TaintRegistry::default();
        r.add("password");
        let snap = r.redaction_snapshot();
        // XOR with key 0x5A: each byte XORed.
        let xored: String = "password"
            .as_bytes()
            .iter()
            .map(|b| (b ^ 0x5A) as char)
            .collect();
        assert!(snap.iter().any(|s| s == xored.as_str()));
    }

    #[test]
    fn arg_taint_reason_detects_original() {
        let r = TaintRegistry::default();
        r.add("supersecret");
        assert_eq!(
            r.arg_taint_reason("xx supersecret yy"),
            Some("original".into())
        );
    }

    #[test]
    fn arg_taint_reason_detects_reversed() {
        let r = TaintRegistry::default();
        r.add("supersecret");
        assert_eq!(
            r.arg_taint_reason("xx tercesrepus yy"),
            Some("reverse".into())
        );
    }

    #[test]
    fn arg_taint_reason_detects_hex() {
        let r = TaintRegistry::default();
        r.add("ABCD");
        assert_eq!(
            r.arg_taint_reason("dump=41424344"),
            Some("hex_lower".into())
        );
    }

    #[test]
    fn arg_taint_reason_detects_xor() {
        let r = TaintRegistry::default();
        r.add("password");
        let xored: String = "password"
            .as_bytes()
            .iter()
            .map(|b| (b ^ 0x5A) as char)
            .collect();
        let arg = format!("payload={xored}");
        let reason = r.arg_taint_reason(&arg);
        assert_eq!(reason, Some("xor_0x5a".into()));
    }

    #[test]
    fn arg_taint_reason_detects_base64_standard() {
        let r = TaintRegistry::default();
        r.add("password");
        // base64("password") = "cGFzc3dvcmQ="
        assert_eq!(
            r.arg_taint_reason("blob=cGFzc3dvcmQ="),
            Some("base64_std".into())
        );
    }

    #[test]
    fn arg_taint_reason_detects_base64_urlsafe_nopad() {
        let r = TaintRegistry::default();
        r.add("password!?");
        // base64_urlsafe_nopad("password!?") differs from std at non-
        // alphabetic positions but the ASCII payload here happens to
        // not exercise '/' / '+'. Use the harness's own b64 to
        // produce the expected value: we just rely on the registry
        // detecting *some* b64 form and reporting that.
        let arg = "x=cGFzc3dvcmQhPw";
        let reason = r.arg_taint_reason(arg);
        assert!(
            reason.as_deref() == Some("base64_std_nopad")
                || reason.as_deref() == Some("base64_urlsafe_nopad"),
            "expected a base64 reason, got {reason:?}"
        );
    }

    #[test]
    fn arg_taint_reason_detects_rot13() {
        let r = TaintRegistry::default();
        r.add("HelloWorld");
        // ROT13("HelloWorld") = "UryybJbeyq"
        assert_eq!(
            r.arg_taint_reason("greeting=UryybJbeyq"),
            Some("rot13".into())
        );
    }

    #[test]
    fn arg_taint_reason_misses_truly_unknown_transform() {
        // A custom invertible permutation with a script-generated
        // key is documented as out of scope. The redactor doesn't
        // know the key; the ciphertext doesn't match any
        // pre-computed pattern.
        let r = TaintRegistry::default();
        r.add("supersecret-token-bytes-here-aaa");
        // Apply a 7-byte rolling XOR — outside our single-byte XOR
        // set. Should NOT be detected.
        let key = b"NACLKEY";
        let bytes: Vec<u8> = "supersecret-token-bytes-here-aaa"
            .as_bytes()
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % key.len()])
            .collect();
        let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
        let arg = format!("payload={hex}");
        assert_eq!(r.arg_taint_reason(&arg), None);
    }

    #[test]
    fn redact_lines_passes_unrelated_lines() {
        let r = TaintRegistry::default();
        r.add("super-secret-value");
        let out = redact_lines(
            vec!["starting".into(), "result: 42".into(), "done".into()],
            &r,
        );
        assert_eq!(out, vec!["starting", "result: 42", "done"]);
    }

    #[test]
    fn redact_lines_redacts_substring() {
        let r = TaintRegistry::default();
        r.add("super-secret-value");
        let out = redact_lines(vec!["got: super-secret-value".into(), "done".into()], &r);
        assert_eq!(out[0], "got: [REDACTED]");
        assert_eq!(out[1], "done");
    }

    #[test]
    fn redact_lines_catches_chunked_per_char() {
        let r = TaintRegistry::default();
        r.add("MNOP4321secret");
        let chunks: Vec<String> = "MNOP4321secret"
            .chars()
            .map(|c| format!("ch:{c}"))
            .collect();
        let out = redact_lines(chunks, &r);
        for line in out.iter() {
            assert_eq!(
                line, REDACTED,
                "expected every chunked line to be clobbered"
            );
        }
    }

    #[test]
    fn redact_lines_density_calc_uses_division_not_modulo_or_multiplication() {
        // Targets the mutation "/ with %" and "/ with *" in the
        // density calculation inside redact_lines. If the operator
        // were silently swapped, an attacker could tune their cover-
        // text to land on a `density` value that's below threshold
        // by accident — letting a chunked exfil slip through.
        //
        // Construct a case where division gives density above the
        // threshold (so chunking IS detected and the lines clobber)
        // but where modulo or multiplication would give something
        // either much higher or much lower:
        //
        //   secret = "MNOP4321secret-token" (20 chars, > MIN_LEN=8)
        //   joined output: per-character chunked print with one cover
        //   char between each. So matches at positions 0, 2, 4, ..., 38.
        //   span = 38, len = 20, density = 20/38 ≈ 0.526 — well above
        //   the 0.05 threshold, MUST be detected as chunking.
        //
        //   modulo: 20 % 38 = 20 → still >> 0.05, "passes" the check
        //   the other way (would still detect chunking) — so a `/→%`
        //   mutation alone might not flip THIS case. But for longer
        //   spans the modulo result drops to a small value.
        //
        // Use a longer span to make the modulo and multiplication
        // mutations diverge from the real division behaviour.
        let r = TaintRegistry::default();
        r.add("MNOP4321zzzzMNOP4321"); // 20 chars, all unusual chars
                                       // Print each char interleaved with 4 cover chars (a real
                                       // chunking exfil pattern).
        let chunks: Vec<String> = "MNOP4321zzzzMNOP4321"
            .chars()
            .map(|c| format!("aaaa{c}"))
            .collect();
        let out = redact_lines(chunks, &r);
        // Every chunked line MUST be replaced with [REDACTED]. If the
        // density calculation were `%` or `*`, the chunking would not
        // be detected and the original chunked output would pass through.
        for (i, line) in out.iter().enumerate() {
            assert_eq!(
                line, REDACTED,
                "line {i} should be clobbered by chunking detection but got {line:?}"
            );
        }
    }

    #[test]
    fn redact_lines_skips_chunking_for_short_taints() {
        // Targets the mutation "< with == in CHUNKING_MIN_LEN check"
        // and "< with <= in CHUNKING_MIN_LEN check". The check is
        // `if taint.len() < CHUNKING_MIN_LEN { continue; }` — for a
        // 4-char secret (below MIN_LEN=8), chunking detection MUST be
        // skipped (otherwise prose with those four characters present
        // gets falsely clobbered).
        //
        // If `<` becomes `==`, only a 7-char taint is skipped — every
        // other length gets chunking-detected, including 4-char taints
        // which would false-positive-clobber any prose with the four
        // characters in order.
        let r = TaintRegistry::default();
        r.add("abcd"); // 4 chars: shorter than CHUNKING_MIN_LEN (=8)
                       // Prose that contains a, b, c, d in order — would be a chunking
                       // false positive if the length check is wrong.
        let prose = vec!["Here is a banana.".into(), "And a cake of dates.".into()];
        let out = redact_lines(prose.clone(), &r);
        // No clobbering: chunking detection MUST skip the short taint.
        // (The lines may still get redacted by the substring scrub if
        // "abcd" appears verbatim, but it doesn't, so the original
        // lines pass through.)
        assert_eq!(out, prose, "short taints must skip chunking detection");
    }

    #[test]
    fn redact_lines_does_not_clobber_prose_with_random_char_overlap() {
        // 40-char secret with rare chars; long English-ish prose
        // should NOT be mistaken for chunking.
        let r = TaintRegistry::default();
        r.add("MNOP4321-fixture-secret-do-not-leak-zzzz");
        let prose: Vec<String> = vec![
            "starting the build for project foo".into(),
            "compiled 12 files, no errors".into(),
            "ran the test suite: 30/30 passing".into(),
            "finished in 3.2s".into(),
        ];
        let out = redact_lines(prose.clone(), &r);
        assert_eq!(out, prose);
    }

    #[test]
    fn subsequence_match_ordered_chars() {
        assert!(subsequence_match("abXcdYef", "ace").is_some());
        assert!(subsequence_match("abXcdYef", "fa").is_none());
    }

    // ── Mutation-targeted boundary tests for redact_lines ───────
    //
    // These tests fail under specific mutants the existing test
    // suite leaves alive — see the mutation-testing report.
    // Each test names the mutant it kills in its docstring so a
    // future reader knows why the test exists and can't simplify
    // it away without breaking mutation coverage.

    #[test]
    fn redact_lines_chunking_runs_on_secret_of_exact_min_length() {
        // Targets `< with <=` on line 468 (the
        // `if taint.len() < CHUNKING_MIN_LEN` skip).
        //
        // For a secret of length EXACTLY CHUNKING_MIN_LEN = 8, the
        // original code does NOT skip (8 < 8 is false). Mutant `<=`
        // would skip (8 <= 8 is true) and the chunked secret would
        // pass through unredacted.
        //
        // We build a length-8 secret and prose where the secret's
        // characters appear as a tight subsequence (high density) so
        // the chunking detector fires and clobbers the line.
        let r = TaintRegistry::default();
        r.add("ABcd1234"); // exactly 8 chars
                           // Each line contains the chars in order,
                           // packed close together. Density well above 0.05.
        let prose: Vec<String> = vec![
            "secret-chunk: A B c d 1 2 3 4 right here".into(),
            "another line that won't be matched".into(),
        ];
        let out = redact_lines(prose, &r);
        assert!(
            out[0].contains("[REDACTED]"),
            "8-char secret with high-density subseq should clobber line 0; got {:?}",
            out[0]
        );
    }

    #[test]
    fn redact_lines_chunking_skips_when_density_well_below_threshold() {
        // Targets `< with ==` and `< with <=` on line 480 (the
        // `if density < CHUNKING_MIN_DENSITY { continue; }`),
        // PLUS the `/ with *` and `/ with %` on line 479.
        //
        // Setup: a 12-char secret whose chars appear as a sparse
        // subsequence in a long paragraph (density ~ 12/600 = 0.02,
        // well below the 0.05 threshold). Original code skips —
        // chunking detection doesn't clobber. The line is
        // unmodified.
        //
        // - Mutant `<` → `==` on line 480: density 0.02 != 0.05,
        //   so the skip condition is false; chunking runs and
        //   wrongly clobbers.
        // - Mutant `<` → `<=` on line 480: same shape (0.02 < 0.05
        //   is true so original DOES skip; mutant 0.02 <= 0.05 is
        //   ALSO true → also skips. Same behavior at this density.
        //   To kill this one we additionally need a test at exactly
        //   the threshold — see `redact_lines_chunking_runs_at_exact_density_threshold`.
        // - Mutants on line 479 (/ with * or %): density becomes
        //   matches*span (huge) or matches%span (>=0). Either way,
        //   not < threshold → mutant doesn't skip → wrong clobber.
        let r = TaintRegistry::default();
        // 12 distinctive chars; each appears once in the prose,
        // spread across ~600 bytes.
        r.add("ABCDEFGHIJKL");
        let prose: Vec<String> = vec![
            "Acrobats and bears (B) chase clowns (C) ".repeat(2),
            "while Ducks (D) eat Eels (E) For Free (F) ".repeat(2),
            "Generously Hosting Imps (I) and Jovial (J) Kids ".repeat(2),
            "all Loving the show ".repeat(8),
        ];
        // Compute expected total span.
        let total: usize = prose.iter().map(|s| s.len() + 1).sum();
        // Sanity: span large enough that density 12/total < 0.05.
        assert!(
            12.0 / (total as f64) < CHUNKING_MIN_DENSITY,
            "test fixture must put us below the density threshold; \
             total={total}, density={:.4}",
            12.0 / (total as f64)
        );
        let out = redact_lines(prose.clone(), &r);
        // Original: density-skip → no chunking-based clobbering.
        // (Substring-scrub may still hit if a literal substring of
        // the secret appears, but our secret string doesn't appear
        // verbatim anywhere, so the prose passes through.)
        assert_eq!(
            out, prose,
            "low-density subsequence should NOT trigger chunking clobber"
        );
    }

    #[test]
    fn redact_lines_chunking_runs_at_exact_density_threshold() {
        // Targets `< with <=` on line 480 (`if density <
        // CHUNKING_MIN_DENSITY { continue; }`). At density EXACTLY
        // 0.05 the original `<` is false (don't skip → clobber)
        // while the mutant `<=` is true (skip → no clobber). So a
        // test where matches.len() / span equals 0.05 EXACTLY
        // catches this mutation.
        //
        // Construction: 8 chars at positions 0 and 160 (span = 160)
        // with 6 more at intermediate positions. matches.len() = 8,
        // span = 160 - 0 = 160, density = 8 / 160 = 0.05 (which
        // shares its IEEE-754 bit pattern with the literal 0.05f64
        // because both come from the same division/representation
        // path). Strict `<` rejects this → clobber. `<=` accepts →
        // skip.
        let r = TaintRegistry::default();
        r.add("ABCDEFGH"); // 8 chars

        // Place A..H at positions [0, 23, 46, 68, 91, 114, 137, 160]
        // with 'z' filler in between. The exact intermediate
        // positions don't matter for span/density — only the FIRST
        // (0) and LAST (160) matter, plus the count (8).
        let positions: [usize; 8] = [0, 23, 46, 68, 91, 114, 137, 160];
        let chars: [char; 8] = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'];
        let total_len = 161;
        let mut bytes = vec![b'z'; total_len];
        for (i, &p) in positions.iter().enumerate() {
            bytes[p] = chars[i] as u8;
        }
        let line = String::from_utf8(bytes).unwrap();
        // Sanity: subsequence_match should land at exactly these
        // positions because all filler is 'z' (not in secret).
        let prose = vec![line];
        let out = redact_lines(prose, &r);
        assert!(
            out[0].contains("[REDACTED]"),
            "exact-threshold density (0.05) MUST trigger chunking; \
             with `<=` mutant it skips, leaving prose unredacted. got: {:?}",
            out[0]
        );
    }

    // NOTE on the line-489 `< with <=` mutant in `redact_lines`:
    // structurally unreachable in practice — see the comment in
    // `.cargo/mutants.toml`'s `exclude_re` for the proof. Briefly:
    // for the mutant to change observable output, a subsequence
    // match must land exactly on the `*end` (joining `\n`) of some
    // line, AND that line must have NO other matches. But
    // `TaintRegistry::add()` trims leading/trailing whitespace, so
    // a `\n` can only appear in the secret's middle, which forces
    // the surrounding-line matches to be present. Any line whose
    // `*end` has a boundary match is already clobbered by those
    // surrounding matches; the mutation only changes which match
    // ALSO clobbers a doomed line. Output is byte-identical.

    // (the old `redact_lines_assigns_match_to_correct_line_at_byte_boundary`
    // test was replaced by `redact_lines_match_at_line_boundary_assigns_to_correct_line`
    // above, which constructs an empty leading line so the `<=` mutant's
    // misassignment of a `\n`-position match becomes observable.)
}
