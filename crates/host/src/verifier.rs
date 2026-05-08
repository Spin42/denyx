//! Pre-execution verifier. Walks the script source for any reference to
//! a known Denyx capability name and rejects the script before evaluation
//! if the capability is not in `policy.functions.allow`.
//!
//! This is the "compile-time" line of defense. The runtime interceptor
//! is the second line — both must agree before a capability fires. The
//! verifier strips comments and string literals first so capability names
//! quoted as data don't cause false positives.

use std::collections::BTreeSet;

use denyx_policy::Policy;

use crate::CAPABILITIES;

#[derive(Debug, thiserror::Error)]
#[error("verifier: capability {capability:?} called by script but not allowed by policy")]
pub struct VerifierRejection {
    pub capability: String,
}

pub fn verify(source: &str, policy: &Policy) -> Result<(), VerifierRejection> {
    let stripped = strip_strings_and_comments(source);
    let used = scan_capabilities(&stripped);
    for cap in used {
        if policy.check_function(&cap).is_err() {
            return Err(VerifierRejection { capability: cap });
        }
    }
    Ok(())
}

fn scan_capabilities(source: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for cap in CAPABILITIES {
        if contains_word(source, cap.name) || contains_word(source, cap.raw) {
            out.insert(cap.name.to_string());
        }
    }
    out
}

fn contains_word(haystack: &str, word: &str) -> bool {
    let bytes = haystack.as_bytes();
    let needle = word.as_bytes();
    if needle.is_empty() {
        return false;
    }
    let mut i = 0;
    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] == needle {
            let before_ok = i == 0 || !is_ident_byte(bytes[i - 1]);
            let after_ok =
                i + needle.len() == bytes.len() || !is_ident_byte(bytes[i + needle.len()]);
            if before_ok && after_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// "Capability identifier" boundary: alphanumeric, underscore, or dot.
/// Treating `.` as part of the token prevents false matches like
/// `obj.fs.read` matching `fs.read` — the leading `.` is now part of
/// the identifier context, so the boundary check fails.
fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'.'
}

/// Strip Starlark `# line comments`, `"..."`, `'...'`, `"""..."""`,
/// `'''...'''`. Replaces stripped regions with a single space so word
/// boundaries are preserved. Operates on bytes; safe because Starlark
/// identifiers and keywords are ASCII (only stripped regions can contain
/// multibyte UTF-8).
fn strip_strings_and_comments(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'#' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            out.push(b' ');
        } else if c == b'"' || c == b'\'' {
            let q = c;
            let triple = i + 2 < bytes.len() && bytes[i + 1] == q && bytes[i + 2] == q;
            if triple {
                i += 3;
                while i + 2 < bytes.len() {
                    if bytes[i] == q && bytes[i + 1] == q && bytes[i + 2] == q {
                        i += 3;
                        break;
                    }
                    i += 1;
                }
            } else {
                i += 1;
                while i < bytes.len() && bytes[i] != q && bytes[i] != b'\n' {
                    if bytes[i] == b'\\' && i + 1 < bytes.len() {
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                if i < bytes.len() && bytes[i] == q {
                    i += 1;
                }
            }
            out.push(b' ');
        } else {
            out.push(c);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap_or_default()
}

#[cfg(test)]
mod strip_tests {
    //! Direct unit tests for `strip_strings_and_comments`. The
    //! verifier's integration tests in `tests/verifier.rs` exercise
    //! the strip indirectly (via verify() → scan_capabilities), but
    //! mutation testing showed that path under-constrains the
    //! function: many byte-arithmetic mutations inside the strip
    //! produce verifier-equivalent behaviour because the resulting
    //! output happens not to contain a capability name in either
    //! case.
    //!
    //! These tests assert the EXACT byte output of the strip on
    //! inputs crafted to push each mutation off the original's path.
    //! Inputs are short and explicit so a regression points to a
    //! specific code path.
    use super::strip_strings_and_comments;

    fn s(input: &str) -> String {
        strip_strings_and_comments(input)
    }

    // --- Single-quoted (non-triple) handling: lines 100-110 ---

    #[test]
    fn line_double_quoted_string_replaced_with_single_space() {
        // The base case of the non-triple branch: `"abc"` becomes a
        // single space and trailing real code is preserved verbatim.
        // Kills line 109 (post-loop closer-consume `i < len &&
        // bytes[i] == q`) and line 110 (`i += 1` after closer).
        assert_eq!(s("\"abc\"y"), " y");
    }

    #[test]
    fn newline_terminates_unclosed_double_quote_without_eating_newline() {
        // An unclosed string (`"abc\n...`) terminates at the newline.
        // The newline itself MUST stay in the output (the line-
        // counting downstream relies on it). Kills the line-109
        // `< → >` mutant: with `>` the post-loop closer-consume reads
        // OOB or skips, but specifically a `<` vs `>` flip on the
        // bounds check would change whether bytes[i]==q is even
        // evaluated at end-of-input. With `==` it consumes the close
        // quote when present; here there's no close quote, only `\n`,
        // and the newline must NOT be eaten.
        assert_eq!(s("\"abc\n_denyx_fs_read"), " \n_denyx_fs_read");
    }

    #[test]
    fn backslash_inside_string_escapes_following_byte() {
        // `"\""` is a one-char string containing `"`. The escape on
        // line 103 makes us advance 2 bytes past the `\` so the
        // following `"` is NOT treated as the closer.
        // Original output: " y" (5-byte string + 'y' → space + 'y').
        // Mutant 103:33 (== → !=) on `bytes[i] == b'\\'`: never sees
        // backslash → treats inner `"` as closer at i=2 → output
        // begins differently. Mutant 103:42 (&& → ||): combined with
        // the ==, takes escape branch unconditionally — `i += 2`
        // past end of string would walk off and hit different bytes.
        // Mutant 104:27 (+= → *=): `i *= 2` instead of `i += 2`
        // makes the post-escape index wrong.
        assert_eq!(s("\"\\\"\"y"), " y");
    }

    #[test]
    fn backslash_at_end_of_buffer_does_not_escape_off_end() {
        // `"\` with no following byte. The escape branch has a bounds
        // check `i + 1 < bytes.len()` (line 103). Without it the
        // mutant `i += 2` would index past the end. We require the
        // strip to NOT panic and to emit a single space (the
        // unterminated string is treated as eating to end).
        // Kills the line-103 bounds-check mutants:
        // - 103:47 (+ → -, + → *): wrong arithmetic in `i + 1` makes
        //   the bound `i - 1 < len` (always true for i>0) or `i*1
        //   < len` (true while i < len) — both let the escape branch
        //   be taken with no following byte.
        // - 103:51 (< → ==, < → >, < → <=): bounds check predicates
        //   that diverge from `<` near end-of-buffer.
        assert_eq!(s("\"\\"), " ");
    }

    #[test]
    fn escape_in_string_does_not_skip_real_capability_after() {
        // After an escaped quote inside a string, the strip must
        // resume past the *true* closing quote and leave the
        // following real code intact. Kills 104:27 (`i += 2` →
        // `i *= 2`): a wrong post-escape index would consume more
        // (or fewer) bytes than intended, shifting where the closer
        // is found, so the trailing real code starts at a different
        // offset and the output diverges.
        assert_eq!(s("x = \"a\\nb\"\nfs.read"), "x =  \nfs.read");
    }

    #[test]
    fn unterminated_double_quoted_string_at_eof_emits_space() {
        // Pure end-of-input case (no `\n`, no closer). Kills line
        // 109:48 (`bytes[i] == q` → `!=`): with the post-loop check
        // mutated, an unterminated string would (under == → !=)
        // try to consume a non-quote byte as the closer. Since
        // there are zero bytes, `i < bytes.len()` is false anyway
        // → harmless on this exact input. The combination with
        // 109:22 (`<` → `>`) would make the post-loop branch fire
        // wrongly. Output must be " " (one space).
        assert_eq!(s("\"abc"), " ");
    }

    #[test]
    fn single_quoted_string_handled_like_double() {
        // `'a'` is a Starlark single-quoted string. The strip uses
        // the same code path with q='\''. Asserts symmetry — kills
        // any mutation that special-cased the `"` quote handling.
        assert_eq!(s("'abc'y"), " y");
    }

    // --- Triple-quoted handling: lines 90, 92, 94 ---

    #[test]
    fn triple_quoted_at_start_of_input_strips_entire_block() {
        // Critical for line 92:19 (`i += 3` → `i *= 3`). When the
        // triple opens at i=0, `i *= 3` keeps i=0 — so the inner
        // while immediately matches the opener bytes as a closer
        // and breaks at i=3, leaving the docstring CONTENT exposed
        // to the outer loop. Output diverges: original emits a
        // single space, mutant emits ` <body> ` plus a trailing
        // partial-strip artefact.
        assert_eq!(s("\"\"\"hello\"\"\""), " ");
    }

    #[test]
    fn triple_single_quoted_at_start_of_input_strips_entire_block() {
        // Symmetric variant for the `'''...'''` form. Same line-92
        // kill applies, AND it forces the strip's quote-symmetry to
        // work: any mutation that hard-coded the closer to `"""`
        // would survive the double-quoted test but fail here.
        assert_eq!(s("'''hello'''"), " ");
    }

    #[test]
    fn triple_quoted_followed_by_real_code_preserves_real_code() {
        // The closer at line 94 must advance i past the closing
        // `"""` so the rest of the file scans normally. Kills:
        // - 94:33 (== → !=) on `bytes[i] == q`: the closer would be
        //   matched on any non-quote byte, ending the docstring
        //   on the very first content byte and exposing real
        //   docstring text.
        // - 94:38 (&& → ||): turns the closer-match into "ANY of
        //   {bytes[i]==q OR bytes[i+1..i+3]==qq}" → premature close
        //   on a SINGLE quote in the docstring.
        // - 94:49 (+ → *): `bytes[i * 1]` collapses the second
        //   check to `bytes[i] == q`, so the closer-match becomes
        //   `bytes[i]==q && bytes[i]==q && bytes[i+2]==q` —
        //   matches on a single-quote followed by something at i+2,
        //   prematurely closing on inputs like `"x"`.
        // - 94:59 (&& → ||): turns the third check into OR, so
        //   `bytes[i+2]==q` alone can close the docstring.
        // - 94:75 (== → !=) on `bytes[i + 2] == q`: closer-match
        //   would fire when bytes[i+2] is NOT q — i.e. on most
        //   docstring content.
        // Output: leading space (the docstring), then `\n` and the
        // real code untouched.
        assert_eq!(
            s("\"\"\"doc\"\"\"\nfs.read"),
            " \nfs.read"
        );
    }

    #[test]
    fn triple_quoted_with_inner_double_quote_does_not_close_early() {
        // `"""said "hi" then more"""` contains a single `"` and a
        // pair `""` (no, actually `said "hi"` is `"hi"` = single+
        // single but adjacent to non-quote). Either way it's NOT
        // `"""`. Kills the 94:38 / 94:59 (&& → ||) mutants:
        // those would close on the inner single `"`, exposing
        // ` then more` (and re-processing it as code).
        assert_eq!(
            s("\"\"\"said \"hi\" then\"\"\""),
            " "
        );
    }

    #[test]
    fn triple_quote_detection_requires_three_consecutive_quotes() {
        // Input: `"x"y"z"`. Three single-quoted strings, NO triples
        // anywhere. Kills line 90:57 (+ → *) on `bytes[i + 1]`:
        // mutant turns it into `bytes[i] == q` (always true in this
        // branch), so triple is detected whenever bytes[i+2]==q.
        // First `"` at i=0: bytes[2]='"' → mutant says triple, eats
        // to end. Original: bytes[1]='x' != q → not triple, strips
        // each pair correctly.
        assert_eq!(s("\"x\"y\"z\""), " y ");
    }

    #[test]
    fn triple_quoted_with_inner_two_separated_quotes_does_not_close() {
        // Input: `"""x"y"z"""`. Inside the docstring there are TWO
        // single-quote bytes separated by one byte each (`"y"` and
        // `"z"`). Kills 94:49 (+ → *): mutant collapses
        // `bytes[i + 1]` to `bytes[i]`, so the closer-match becomes
        // `bytes[i]==q && bytes[i]==q && bytes[i+2]==q`. At the
        // first inner `"` (position 4): bytes[4]==q AND bytes[6]==q
        // → mutant closes, jumping to i=7. The remaining `z"""` is
        // then re-opened as another triple → mutant output diverges
        // from original (which scans through to the real closing
        // `"""` at the end and emits exactly one space).
        assert_eq!(s("\"\"\"x\"y\"z\"\"\""), " ");
    }

    #[test]
    fn near_end_of_input_triple_detection_respects_bounds() {
        // Input where the bounds check `i + 2 < bytes.len()` is the
        // discriminator. With src = `"x"` (len=3), at i=0:
        // - Original: i+2=2 < 3 → true. bytes[1]='x' != q → triple
        //   = false. Strip as single-quoted → output " ".
        // - Without the bounds check (or with mutated bounds),
        //   reading bytes[i+2] near end would give different
        //   answers. Here we assert the basic-case output.
        // Combined with the longer triple_quote_detection_requires
        // test, this pins down the bounds + content discrimination.
        assert_eq!(s("\"x\""), " ");
    }

    // --- Comment handling: line 84 ---

    #[test]
    fn line_comment_stripped_to_single_space_preserving_newline() {
        // `# comment\nrest` → ` \nrest`. The `#` branch eats up to
        // (but not including) the newline. The newline survives
        // because the strip only emits one space for the comment
        // itself.
        assert_eq!(s("# fs.read foo\nx"), " \nx");
    }

    #[test]
    fn unterminated_line_comment_at_eof() {
        // `# fs.read` with no newline. The strip eats to EOF and
        // emits one space.
        assert_eq!(s("# fs.read"), " ");
    }
}
