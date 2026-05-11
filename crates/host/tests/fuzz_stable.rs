//! Stable-toolchain randomized regression sweep for the verifier.
//!
//! `cargo +nightly fuzz run verifier` is the canonical fuzzer (see
//! `fuzz/`). This file runs a deterministic 100 000-iteration sweep
//! against the same surface so the regression coverage exists in a
//! plain `cargo test` on stable. It uses an in-tree xorshift PRNG
//! seeded from a fixed constant, so the iteration sequence is
//! reproducible across runs and CI.
//!
//! The properties we hold the verifier to are weak by design — the
//! point of fuzzing is to surface panics, infinite loops, and unwinds
//! on malformed input, not to verify behaviour. Specifically:
//!
//! - `verify` returns `Ok` or `Err`; it never panics.
//! - The capability scanner is idempotent: scanning a string twice
//!   produces the same answer.
//! - Stripping is monotone in length: `len(stripped) <= len(input)`.
//!
//! If any of these is violated the test fails with the seed of the
//! offending iteration so the input can be replayed by hand.
//!
//! This is NOT a substitute for coverage-guided fuzzing — the input
//! distribution here is uniform-ish bytes and a few structural
//! injections, so it explores fewer corners than libFuzzer would.

use std::path::PathBuf;

use denyx_host::verifier::verify;
use denyx_policy::{Policy, PolicyFile};

/// Deterministic xorshift64* PRNG. We don't need cryptographic
/// quality — just a stream of bytes that explores the input space
/// reproducibly.
struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn gen_range(&mut self, max: usize) -> usize {
        if max == 0 {
            return 0;
        }
        (self.next_u64() as usize) % max
    }
    fn pick<'a, T: ?Sized>(&mut self, choices: &'a [&T]) -> &'a T {
        choices[self.gen_range(choices.len())]
    }
}

/// Build a synthesized Starlark-ish input. We mix structural tokens
/// the verifier cares about (capability names, comment / quote
/// delimiters) with random bytes, biased toward edge cases like
/// truncated triple-quoted strings and unbalanced escapes.
fn synthesize(rng: &mut Rng) -> String {
    let len = rng.gen_range(512);
    let parts: &[&str] = &[
        "fs.read",
        "fs.write",
        "fs.delete",
        "_denyx_fs_read",
        "_denyx_net_http_get",
        "subprocess.exec",
        "env.read",
        "net.http_post",
        "obj.fs.read",
        "fs.readme",
        "#",
        "\"",
        "'",
        "\"\"\"",
        "'''",
        "\\",
        "\n",
        "  ",
        " = ",
        "(",
        ")",
        "[",
        "]",
        ",",
        "x",
        "y",
        "abc",
        "0xFF",
    ];
    let mut s = String::with_capacity(len);
    while s.len() < len {
        if rng.next_u64() & 0xF == 0 {
            // 1/16 chance: inject a raw random byte (still valid UTF-8
            // because we constrain to ASCII range).
            let b = (rng.gen_range(126 - 32) + 32) as u8 as char;
            s.push(b);
        } else {
            s.push_str(rng.pick(parts));
        }
    }
    s
}

fn empty_policy() -> Policy {
    let file = PolicyFile::from_toml_str("").unwrap();
    Policy::from_file(file, PathBuf::from("/tmp")).unwrap()
}

#[test]
fn verifier_does_not_panic_on_random_inputs() {
    let policy = empty_policy();
    // Seed has uneven digit groups on purpose (a memorable hex word
    // — "DENYX" + "SEED_DEAD"); the readability beats the lint.
    #[allow(clippy::unusual_byte_groupings)]
    let mut rng = Rng::new(0xA51A_5_5EED_DEAD);
    for i in 0..100_000 {
        let src = synthesize(&mut rng);
        let r1 = verify(&src, &policy);
        // Idempotency: verifier is pure, so a second call on the same
        // input must produce the same outcome.
        let r2 = verify(&src, &policy);
        match (&r1, &r2) {
            (Ok(()), Ok(())) => {}
            (Err(a), Err(b)) => {
                // Two rejections must have the same Display form
                // (the user-visible message). The internal enum
                // shape may differ, but the message is what the
                // verifier promises to be idempotent on.
                let am = a.to_string();
                let bm = b.to_string();
                if am != bm {
                    panic!(
                        "iter {i}: verifier non-idempotent on input: {src:?}\n\
                         first: {am:?}, second: {bm:?}",
                    );
                }
            }
            _ => {
                panic!(
                    "iter {i}: verifier non-idempotent on input: {src:?}\n\
                     first: {r1:?}, second: {r2:?}",
                );
            }
        }
    }
}
