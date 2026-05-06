//! Stable-toolchain randomized regression sweep for the policy
//! TOML parser, glob compiler, and path matchers. See
//! `crates/host/tests/fuzz_stable.rs` for the rationale and PRNG
//! shape — same seed convention.

use std::path::{Path, PathBuf};

use aegis_policy::{Policy, PolicyFile};

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

fn synthesize_glob(rng: &mut Rng) -> String {
    let parts: &[&str] = &[
        "**", "*", "?", "[a-z]", "[!a-z]", "[]", "{a,b}", "{,}",
        "src", "tests", "lib", "x", "..", ".",
        "/", "/**/", "**/*.rs", ".env", "/tmp/", "deeply/nested/path",
        "\\", "/\\/", "[", "]", "{", "}",
    ];
    let mut s = String::new();
    let n = rng.gen_range(8) + 1;
    for _ in 0..n {
        s.push_str(rng.pick(parts));
        if rng.next_u64() & 1 == 0 {
            s.push('/');
        }
    }
    s
}

fn synthesize_path(rng: &mut Rng) -> String {
    let parts: &[&str] = &[
        "src", "tests", "lib", ".env", "secret",
        "..", ".", "/", "tmp", "rs", "py", "deeply", "nested",
    ];
    let mut s = String::new();
    let n = rng.gen_range(6) + 1;
    for _ in 0..n {
        if !s.is_empty() {
            s.push('/');
        }
        s.push_str(rng.pick(parts));
    }
    s
}

fn synthesize_toml(rng: &mut Rng) -> String {
    let mut out = String::new();
    if rng.next_u64() & 1 == 0 {
        out.push_str("inherits = \"secure-defaults\"\n");
    }
    let n_globs = rng.gen_range(5) + 1;
    let mut globs = Vec::new();
    for _ in 0..n_globs {
        globs.push(format!("\"{}\"", synthesize_glob(rng).replace('"', "'")));
    }
    let joined = globs.join(", ");
    out.push_str("[filesystem]\n");
    out.push_str(&format!("read_allow = [{joined}]\n"));
    out.push_str(&format!("write_allow = [{joined}]\n"));
    out.push_str(&format!("delete_allow = [{joined}]\n"));
    out.push_str("[network]\n");
    out.push_str("http_get_allow = [\"api.github.com\"]\n");
    out.push_str("[subprocess]\n");
    out.push_str("allow_commands = [\"git\"]\n");
    out
}

#[test]
fn parser_and_matchers_do_not_panic_on_random_input() {
    let mut rng = Rng::new(0xC0FF_EE_DEAD_BEEF);
    for i in 0..50_000 {
        let toml = synthesize_toml(&mut rng);
        // Parsing may succeed or fail; both are fine. Panics are not.
        let Ok(file) = PolicyFile::from_toml_str(&toml) else {
            continue;
        };
        // Resolution may fail (e.g. an invalid CIDR or bwrap missing on
        // this host). Both are fine. Panics are not.
        let Ok(policy) = Policy::from_file(file, PathBuf::from("/tmp/aegis_fuzz_stable")) else {
            continue;
        };
        // Run the matcher pipeline on a random path.
        let path = synthesize_path(&mut rng);
        let p = Path::new(&path);
        // We don't care about the answer — only that it returns.
        let _ = policy.check_fs_read(p);
        let _ = policy.check_fs_write(p);
        let _ = policy.check_fs_delete(p);

        // Also re-resolve idempotently: parsing + resolution twice on
        // the same input yields the same allow/deny decision.
        let file2 = PolicyFile::from_toml_str(&toml).unwrap();
        if let Ok(policy2) =
            Policy::from_file(file2, PathBuf::from("/tmp/aegis_fuzz_stable"))
        {
            let r1 = policy.check_fs_read(p).is_ok();
            let r2 = policy2.check_fs_read(p).is_ok();
            assert_eq!(
                r1, r2,
                "iter {i}: non-idempotent fs.read decision on toml: {toml}\npath: {path}"
            );
        }
    }
}

#[test]
fn parser_does_not_panic_on_random_bytes() {
    // Byte-level: feed mostly-junk to the TOML parser. We expect most
    // of these to fail to parse, but no panic must occur.
    let mut rng = Rng::new(0xFEED_BAD_C0DE);
    for _ in 0..50_000 {
        let len = rng.gen_range(512);
        let mut bytes = Vec::with_capacity(len);
        for _ in 0..len {
            // Bias toward printable ASCII so the TOML parser actually
            // gets to its lexer (random binary trips earlier).
            let b = (rng.gen_range(126 - 32) + 32) as u8;
            bytes.push(b);
        }
        let s = String::from_utf8(bytes).unwrap();
        let _ = PolicyFile::from_toml_str(&s);
    }
}
