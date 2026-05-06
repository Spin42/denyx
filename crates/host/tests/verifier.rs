//! Integration tests for the pre-execution verifier. Drives
//! `denyx_host::verifier::verify` directly. These tests assert the
//! same word-boundary and string/comment-stripping behavior that the
//! original inline unit tests covered, but routed through the public
//! entry point so the verifier's internal helpers stay private.

use std::path::PathBuf;

use denyx_host::verifier::verify;
use denyx_policy::{Policy, PolicyFile};

fn empty_policy() -> Policy {
    // Policy that allows nothing: any capability use should be flagged.
    let toml = r#"
[functions]
allow = []
"#;
    let file = PolicyFile::from_toml_str(toml).unwrap();
    Policy::from_file(file, PathBuf::from("/tmp")).unwrap()
}

#[test]
fn flags_underscored_capability_call() {
    // Direct use of the registered global is detected and rejected.
    let src = r#"_denyx_fs_read("x")"#;
    let err = verify(src, &empty_policy()).unwrap_err();
    assert_eq!(err.capability, "fs.read");
}

#[test]
fn ignores_substring_match_with_extra_prefix_or_suffix() {
    // Word-boundary discipline: `my_denyx_fs_read` and
    // `_denyx_fs_read_safe` are not the global the host registers.
    let safe_sources = [
        r#"x = my_denyx_fs_read("x")"#,
        r#"x = _denyx_fs_read_safe("x")"#,
    ];
    for src in safe_sources {
        verify(src, &empty_policy()).unwrap_or_else(|e| panic!("false positive on {src:?}: {e}"));
    }
}

#[test]
fn flags_dotted_capability_call() {
    let src = r#"x = fs.read("x")"#;
    let err = verify(src, &empty_policy()).unwrap_err();
    assert_eq!(err.capability, "fs.read");
}

#[test]
fn ignores_attribute_access_that_only_ends_in_capability_name() {
    // `obj.fs.read(...)` is not a top-level fs.read call: the leading
    // `.` extends the identifier context, so the boundary check rejects.
    let src = r#"x = obj.fs.read("x")"#;
    verify(src, &empty_policy())
        .unwrap_or_else(|e| panic!("false positive on attribute access: {e}"));

    // `fs.readme(...)` is similarly not fs.read.
    let src = r#"x = fs.readme("x")"#;
    verify(src, &empty_policy()).unwrap_or_else(|e| panic!("false positive on extended name: {e}"));
}

#[test]
fn ignores_capability_name_inside_string_literal() {
    // The verifier strips strings before scanning, so a capability
    // name quoted as data must NOT be flagged.
    let src = r#"x = "fs.read"
y = "_denyx_fs_read"
"#;
    verify(src, &empty_policy())
        .unwrap_or_else(|e| panic!("false positive on string literal: {e}"));
}

#[test]
fn ignores_capability_name_inside_line_comment() {
    let src = "# fs.read is dangerous\nx = 1\n";
    verify(src, &empty_policy()).unwrap_or_else(|e| panic!("false positive on line comment: {e}"));
}

#[test]
fn ignores_capability_name_inside_triple_quoted_string() {
    let src = r#"x = """
this docstring mentions fs.read and _denyx_fs_read
"""
y = 1
"#;
    verify(src, &empty_policy())
        .unwrap_or_else(|e| panic!("false positive on triple-quoted string: {e}"));
}

// Triple-quote-handling boundary tests.
//
// Mutation testing surfaced 22 surviving mutants in
// `strip_strings_and_comments`'s triple-quote logic — the byte-by-
// byte detection of `"""` and `'''` openers/closers. Some of those
// mutations under-strip (real code outside strings keeps getting
// scanned, capability uses get false-flagged → restrictive, no
// security regression) but some OVER-strip (real code AFTER an
// inner quote inside the triple-quoted region gets blanked,
// hiding capability uses → BYPASS at the verifier).
//
// These tests exercise the boundary cases the previous coverage
// missed: nested single-quote characters inside triple-quoted
// strings, triple-quoted strings that span multiple lines, and a
// triple-quoted string immediately followed by a real capability
// call.

#[test]
fn triple_quoted_with_inner_single_quotes_does_not_close_early() {
    // Inside a `"""...."""` Python/Starlark accepts any unbalanced
    // single quotes. A buggy strip that exits the triple-quoted
    // region on the first single quote would expose the inner
    // `fs.read` to the scanner — false positive (restrictive) at
    // best, real bypass (capability hidden by over-strip propagating
    // into following real code) at worst.
    let src = r#"x = """it's a docstring with fs.read('foo') as text"""
y = 1
"#;
    verify(src, &empty_policy()).unwrap_or_else(|e| {
        panic!("triple-quote with inner single quote false-positive: {e}")
    });
}

#[test]
fn triple_quoted_then_real_capability_call_flags_only_real_call() {
    // A docstring containing `fs.read` followed by code that DOES
    // call `fs.read`. The verifier MUST flag the real call (because
    // policy denies fs.read) but MUST NOT flag the docstring
    // mention. A mutation that mishandles the closing `"""` could
    // either (a) keep stripping past the docstring into the real
    // call, hiding it (BYPASS) or (b) close early, exposing the
    // docstring's mention to the scanner (FALSE POSITIVE).
    let src = r#"docstring = """this script will fs.read a file"""
result = fs.read("path")
"#;
    let err = verify(src, &empty_policy())
        .expect_err("real fs.read call must be flagged by verifier");
    assert_eq!(err.capability, "fs.read");
}

#[test]
fn unterminated_triple_quoted_string_does_not_panic() {
    // A truncated `"""...` with no closer must not panic the
    // verifier, regardless of how the strip's loop terminates.
    // Mutation testing surfaced offset-arithmetic mutants
    // (`i + 2 < len`, `i += 3` etc.) where wrong arithmetic could
    // walk off the end. The verifier should robustly tolerate
    // malformed input — the parser will reject it later anyway.
    let src = "x = \"\"\"truncated and never closed... fs.read appears here\n";
    let _ = verify(src, &empty_policy());
}

#[test]
fn triple_single_quoted_string_strips_capability_name() {
    // The strip handles both `"""..."""` AND `'''...'''`. Existing
    // tests cover the double-quoted variant; this exercises the
    // single-quoted path so a mutation that special-cases one quote
    // type is caught.
    let src = r#"x = '''this docstring uses fs.read and subprocess.exec'''
y = 1
"#;
    verify(src, &empty_policy()).unwrap_or_else(|e| {
        panic!("triple-single-quoted string false-positive: {e}")
    });
}

#[test]
fn capability_name_after_triple_quoted_string_is_still_flagged() {
    // The verifier must resume scanning AFTER the triple-quoted
    // closer. A mutation that fails to advance past the closing
    // `"""` would silently consume the rest of the file as part of
    // the string — and any capability call after the docstring
    // would be hidden from the scanner. BYPASS.
    let src = "doc = \"\"\"hello world\"\"\"\nresult = fs.read(\"path\")\n";
    let err = verify(src, &empty_policy())
        .expect_err("capability call after closing triple-quote must be flagged");
    assert_eq!(err.capability, "fs.read");
}

#[test]
fn allowed_capability_passes_verifier() {
    // Capabilities are now derived from populated resource sections.
    // Populating `read_allow` enables `fs.read`.
    let toml = r#"
[filesystem]
read_allow = ["**"]
"#;
    let file = PolicyFile::from_toml_str(toml).unwrap();
    let policy = Policy::from_file(file, PathBuf::from("/tmp")).unwrap();
    let src = r#"x = fs.read("x")"#;
    verify(src, &policy).expect("allowed capability must pass");
}
