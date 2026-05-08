//! In-process retrieval over a curated library of Starlark code
//! examples. Mirrors `examples/local_executor/rag.py`.
//!
//! The library is a static `&[Example]` array embedded in the binary.
//! Each entry has a description used for retrieval matching and a
//! Starlark code body that gets dropped into the system prompt. Adding
//! examples means appending to [`EXAMPLES`].
//!
//! Embeddings are produced by an [`EmbedProvider`] (the production
//! impl is `OllamaEmbed` in [`crate::ollama`]). For unit tests we
//! inject a deterministic stub — see the module-level tests.

use std::collections::HashMap;
use std::sync::Mutex;

/// One worked example: description used for retrieval, code body
/// rendered into the system prompt verbatim.
#[derive(Clone, Debug)]
pub struct Example {
    pub id: &'static str,
    pub desc: &'static str,
    pub code: &'static str,
}

/// The curated library. Ported 1:1 from `rag.py` `EXAMPLES`.
pub const EXAMPLES: &[Example] = &[
    Example {
        id: "iterate_lines_count_matching",
        desc: "iterate over the lines of a multi-line text and count how many lines match a substring or condition; write the count to a file. Pattern: wrap a for/if loop inside a def, then call the def. Top-level for/if is REJECTED.",
        code: r#"log = fs.read("/tmp/denyx_demo/log.txt")

def count_errors(text):
    n = 0
    for line in text.split("\n"):
        if "[ERROR]" in line:
            n = n + 1
    return n

errors = count_errors(log)
fs.write("/tmp/out/error_count.txt", str(errors))
print("errors: " + str(errors))"#,
    },
    Example {
        id: "iterate_filter_via_comprehension",
        desc: "filter the lines of a text that contain a substring, keeping only the matches. Pattern: list comprehension at top level (comprehensions ARE allowed at top level — only `for` statements are not).",
        code: r#"log = fs.read("/tmp/denyx_demo/log.txt")
lines = log.split("\n")
matches = [l for l in lines if "[ERROR]" in l]
fs.write("/tmp/out/errors.txt", "\n".join(matches))
print("found " + str(len(matches)) + " matching lines")"#,
    },
    Example {
        id: "extract_first_match_via_def",
        desc: "scan a multi-line file for the first line matching a prefix (like 'version = '), extract a substring, and write it. Pattern: def with for+if, returning the extracted value; use string .replace and .strip to clean.",
        code: r#"body = fs.read("/tmp/denyx_demo/manifest.toml")

def find_version(text):
    for line in text.split("\n"):
        if line.startswith("version = "):
            return line.replace("version = ", "").strip().strip('"')
    return ""

v = find_version(body)
fs.write("/tmp/out/version.txt", v)
print(v)"#,
    },
    Example {
        id: "compare_two_via_ternary",
        desc: "compare two values (file contents, integers, fields) and produce one result OR another based on which is greater or equal. Pattern: inline ternary `a if cond else b` works at top level. Top-level `if` statements do NOT work.",
        code: r#"a = fs.read("/tmp/denyx_demo/file_a.txt")
b = fs.read("/tmp/denyx_demo/file_b.txt")
result = "match" if a == b else "differ"
fs.write("/tmp/out/cmp.txt", result)
print(result)"#,
    },
    Example {
        id: "fetch_parse_extract_field",
        desc: "fetch a JSON API endpoint, decode the JSON, and extract a specific top-level field. Write the extracted value to a file. Pattern: net.http_get + json.decode + dict access.",
        code: r#"body = net.http_get("https://api.example.com/repo")
data = json.decode(body)
description = data["description"]
fs.write("/tmp/out/desc.txt", description)
print(description)"#,
    },
    Example {
        id: "fetch_extract_nested_field",
        desc: "fetch a JSON API and extract a NESTED field from the decoded object (e.g. data['owner']['login']). Pattern: chained dict access after json.decode.",
        code: r#"body = net.http_get("https://api.example.com/repo")
data = json.decode(body)
owner_login = data["owner"]["login"]
fs.write("/tmp/out/owner.txt", owner_login)
print("owner: " + owner_login)"#,
    },
    Example {
        id: "fetch_array_field_join",
        desc: "fetch a JSON API where one field is a list/array, decode and join the array elements into a comma-separated string. Handle empty array as a special case via inline ternary.",
        code: r#"body = net.http_get("https://api.example.com/repo")
data = json.decode(body)
topics = data["topics"]
result = ", ".join(topics) if len(topics) > 0 else "none"
fs.write("/tmp/out/topics.txt", result)
print(result)"#,
    },
    Example {
        id: "fetch_n_times_with_def",
        desc: "fetch a URL N times (N>=2) and aggregate the results into a single string with newline separators. Pattern: def wrapping `for i in range(n)`, returning the joined output.",
        code: r#"def fetch_n(url, n):
    out = []
    for i in range(n):
        out.append(net.http_get(url))
    return out

results = fetch_n("https://api.example.com/zen", 3)
agg = "\n".join(results)
fs.write("/tmp/out/aggregate.txt", agg)
print(agg)"#,
    },
    Example {
        id: "compare_two_api_responses",
        desc: "fetch two distinct API endpoints, decode each as JSON, compare a numeric field across them, write a JSON object mapping each name to its value, and print which is larger.",
        code: r#"body_a = net.http_get("https://api.example.com/repo/a")
body_b = net.http_get("https://api.example.com/repo/b")
a = json.decode(body_a)
b = json.decode(body_b)
sizes = {a["full_name"]: a["size"], b["full_name"]: b["size"]}
fs.write("/tmp/out/sizes.json", json.encode(sizes))
larger = a["full_name"] if a["size"] >= b["size"] else b["full_name"]
print("larger: " + larger)"#,
    },
    Example {
        id: "multi_subprocess_compose",
        desc: "run two or more subprocess commands sequentially, capture their outputs (with .strip), build a structured text body, write it to a file. Pattern: subprocess.exec calls + string concatenation.",
        code: r#"version = subprocess.exec(["git", "--version"]).strip()
help_text = subprocess.exec(["git", "--help"])
first = help_text.split("\n")[0]
body = "version: " + version + "\nfirst-help: " + first
fs.write("/tmp/out/git_info.txt", body)
print(body)"#,
    },
    Example {
        id: "subprocess_count_lines",
        desc: "run a subprocess command (find, ls, grep, etc.) whose output is line-separated, count the non-empty lines, write the integer count to a file. Pattern: subprocess.exec + .split + filter empties + len.",
        code: r#"out = subprocess.exec(["find", "/tmp/denyx_demo", "-name", "*.txt", "-type", "f"])
lines = [l for l in out.split("\n") if l.strip() != ""]
fs.write("/tmp/out/count.txt", str(len(lines)))
print("count: " + str(len(lines)))"#,
    },
    Example {
        id: "subprocess_extract_first_token",
        desc: "run a subprocess command whose output starts with a number followed by whitespace and other tokens (like `wc -l file` → '7 file'). Extract the first whitespace-separated token as an integer string.",
        code: r#"out = subprocess.exec(["wc", "-l", "/tmp/denyx_demo/log.txt"]).strip()
first = out.split()[0]
fs.write("/tmp/out/n.txt", first)
print("n: " + first)"#,
    },
    Example {
        id: "env_to_json",
        desc: "read multiple environment variables, build a JSON object with them, encode and write to a file. Pattern: env.read calls + dict literal + json.encode.",
        code: r#"user = env.read("USER")
home = env.read("HOME")
data = {"user": user, "home": home}
encoded = json.encode(data)
fs.write("/tmp/out/whoami.json", encoded)
print(encoded)"#,
    },
    Example {
        id: "render_template_with_replace",
        desc: "read a template file containing literal placeholders like {USER} and {HOME}, substitute the placeholders with values (env vars or computed), write the rendered output. Pattern: str.replace, NOT f-strings.",
        code: r#"tpl = fs.read("/tmp/denyx_demo/template.txt")
user = env.read("USER")
home = env.read("HOME")
rendered = tpl.replace("{USER}", user).replace("{HOME}", home)
fs.write("/tmp/out/rendered.txt", rendered)
print(rendered)"#,
    },
    Example {
        id: "merge_config_with_value",
        desc: "read a JSON config file, decode it, add or update a field (e.g. with an env var value), encode and write back. Pattern: json.decode + dict assignment + json.encode.",
        code: r#"body = fs.read("/tmp/denyx_demo/config.json")
cfg = json.decode(body)
cfg["home_dir"] = env.read("HOME")
fs.write("/tmp/out/config_merged.json", json.encode(cfg))
print(json.encode(cfg))"#,
    },
    Example {
        id: "count_per_category_via_def",
        desc: "iterate over rows of structured data (CSV, log lines, etc.), count occurrences per category/key, build a result dict, encode as JSON and write. Pattern: def with for loop accumulating into a dict.",
        code: r#"body = fs.read("/tmp/denyx_demo/data.csv")

def count_by_kind(text):
    counts = {}
    rows = text.split("\n")
    for row in rows[1:]:
        if row == "":
            continue
        parts = row.split(",")
        kind = parts[1]
        counts[kind] = counts.get(kind, 0) + 1
    return counts

result = count_by_kind(body)
fs.write("/tmp/out/by_kind.json", json.encode(result))
print(json.encode(result))"#,
    },
    Example {
        id: "build_table_with_format",
        desc: "read several files, compute a per-file statistic (word count, line count, etc.), write a formatted text table with header. Pattern: .format() for formatting numbers; string concatenation for the body.",
        code: r#"a = fs.read("/tmp/denyx_demo/a.txt")
b = fs.read("/tmp/denyx_demo/b.txt")
c = fs.read("/tmp/denyx_demo/c.txt")
header = "file\twords\n"
rows = (
    "a.txt\t{}\n".format(len(a.split())) +
    "b.txt\t{}\n".format(len(b.split())) +
    "c.txt\t{}\n".format(len(c.split()))
)
table = header + rows
fs.write("/tmp/out/word_table.tsv", table)
print(table)"#,
    },
    Example {
        id: "append_to_existing_log",
        desc: "read an existing log/audit file, append a new line, write back. Pattern: fs.read + concatenate with new line + fs.write.",
        code: r#"existing = fs.read("/tmp/denyx_demo/audit.txt")
extended = existing + "2026-05-04 entry-3\n"
fs.write("/tmp/out/audit_extended.txt", extended)
print(str(len(extended.split("\n")) - 1) + " lines")"#,
    },
    Example {
        id: "extract_dependency_names",
        desc: "read a manifest/config file with a [section] header and key=value lines under it (TOML-shaped), find the section, extract just the LHS names (dependency names), write them one per line. Pattern: def scanning lines, tracking in-section state, splitting on '='.",
        code: r#"body = fs.read("/tmp/denyx_demo/manifest.toml")

def deps_from_toml(text):
    out = []
    in_deps = False
    for line in text.split("\n"):
        s = line.strip()
        if s.startswith("[") and s.endswith("]"):
            in_deps = (s == "[dependencies]")
            continue
        if in_deps and "=" in s:
            name = s.split("=")[0].strip()
            if name != "":
                out.append(name)
    return out

names = deps_from_toml(body)
fs.write("/tmp/out/dep_names.txt", "\n".join(names))
print("count: " + str(len(names)))"#,
    },
];

/// Trait for "given text, return an embedding vector." The production
/// impl is [`crate::ollama::OllamaEmbed`]; tests use a deterministic
/// stub built from the input string.
pub trait EmbedProvider: Send + Sync {
    fn embed(&self, text: &str) -> anyhow::Result<Vec<f32>>;
}

/// Blanket impl: `Box<dyn EmbedProvider>` is itself an
/// `EmbedProvider`. Lets the runtime-selected provider in `main.rs`
/// pass through generic `E: EmbedProvider + ?Sized` parameters.
impl<T: ?Sized + EmbedProvider> EmbedProvider for Box<T> {
    fn embed(&self, text: &str) -> anyhow::Result<Vec<f32>> {
        (**self).embed(text)
    }
}

/// Embedding cache wrapper. Wraps any [`EmbedProvider`] and memoises
/// per-text vectors so repeated lookups (per-task library scan) don't
/// re-invoke the underlying model.
pub struct CachedEmbed<E: EmbedProvider> {
    inner: E,
    cache: Mutex<HashMap<String, Vec<f32>>>,
}

impl<E: EmbedProvider> CachedEmbed<E> {
    pub fn new(inner: E) -> Self {
        Self {
            inner,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Force-warm the cache for every example's description. Safe to
    /// call once at startup so the first task doesn't pay for K
    /// embeddings.
    pub fn precompute_library_embeddings(&self) -> anyhow::Result<()> {
        for ex in EXAMPLES {
            self.embed(ex.desc)?;
        }
        Ok(())
    }

    pub fn cache_size(&self) -> usize {
        self.cache.lock().expect("cache mutex").len()
    }
}

impl<E: EmbedProvider> EmbedProvider for CachedEmbed<E> {
    fn embed(&self, text: &str) -> anyhow::Result<Vec<f32>> {
        {
            let cache = self.cache.lock().expect("cache mutex");
            if let Some(v) = cache.get(text) {
                return Ok(v.clone());
            }
        }
        let v = self.inner.embed(text)?;
        let mut cache = self.cache.lock().expect("cache mutex");
        cache.insert(text.to_string(), v.clone());
        Ok(v)
    }
}

/// Cosine similarity. Returns 0.0 if either vector has zero norm.
pub fn cosine(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() {
        return 0.0;
    }
    let mut dot = 0.0_f32;
    let mut na = 0.0_f32;
    let mut nb = 0.0_f32;
    for (x, y) in a.iter().zip(b.iter()) {
        dot += x * y;
        na += x * x;
        nb += y * y;
    }
    if na == 0.0 || nb == 0.0 {
        return 0.0;
    }
    dot / (na.sqrt() * nb.sqrt())
}

/// Return the top-K examples by cosine similarity to the task's
/// description. Stable: ties broken by the example's position in
/// [`EXAMPLES`] (preserves intent of the curated ordering).
pub fn retrieve<E: EmbedProvider + ?Sized>(
    embed: &E,
    task_text: &str,
    k: usize,
) -> anyhow::Result<Vec<&'static Example>> {
    let task_vec = embed.embed(task_text)?;
    let mut scored: Vec<(f32, usize, &'static Example)> = Vec::with_capacity(EXAMPLES.len());
    for (i, ex) in EXAMPLES.iter().enumerate() {
        let v = embed.embed(ex.desc)?;
        let score = cosine(&task_vec, &v);
        scored.push((score, i, ex));
    }
    // Sort by descending score, then by ascending index for stability.
    scored.sort_by(|a, b| {
        b.0.partial_cmp(&a.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.1.cmp(&b.1))
    });
    Ok(scored.into_iter().take(k).map(|(_, _, ex)| ex).collect())
}

/// Render a list of examples as the WORKED EXAMPLES section of the
/// system prompt (column-0 friendly).
pub fn render_examples(examples: &[&Example]) -> String {
    let mut parts: Vec<String> = Vec::with_capacity(examples.len());
    for (i, ex) in examples.iter().enumerate() {
        parts.push(format!(
            "--- Example {n}: {desc} ---\n{code}\n",
            n = i + 1,
            desc = ex.desc,
            code = ex.code
        ));
    }
    parts.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Deterministic stub: text -> Vec<f32>. Each test sets up the
    /// mapping it wants and the stub returns the configured vector
    /// for matching strings, [0.0; 4] for unknown strings.
    struct StubEmbed {
        map: Mutex<HashMap<String, Vec<f32>>>,
        calls: Mutex<usize>,
    }

    impl StubEmbed {
        fn new(entries: &[(&str, &[f32])]) -> Self {
            let mut m = HashMap::new();
            for (k, v) in entries {
                m.insert((*k).to_string(), v.to_vec());
            }
            Self {
                map: Mutex::new(m),
                calls: Mutex::new(0),
            }
        }
        fn calls(&self) -> usize {
            *self.calls.lock().unwrap()
        }
    }

    impl EmbedProvider for StubEmbed {
        fn embed(&self, text: &str) -> anyhow::Result<Vec<f32>> {
            *self.calls.lock().unwrap() += 1;
            let m = self.map.lock().unwrap();
            Ok(m.get(text).cloned().unwrap_or_else(|| vec![0.0; 4]))
        }
    }

    #[test]
    fn cosine_handles_identical_vectors() {
        let v = vec![1.0, 2.0, 3.0, 4.0];
        let s = cosine(&v, &v);
        assert!(
            (s - 1.0).abs() < 1e-6,
            "cosine of a vector with itself ≈ 1.0; got {s}"
        );
    }

    #[test]
    fn cosine_handles_orthogonal_vectors() {
        let a = vec![1.0, 0.0, 0.0, 0.0];
        let b = vec![0.0, 1.0, 0.0, 0.0];
        assert!(cosine(&a, &b).abs() < 1e-6);
    }

    #[test]
    fn cosine_returns_zero_for_zero_norm() {
        let a = vec![0.0; 4];
        let b = vec![1.0; 4];
        assert_eq!(cosine(&a, &b), 0.0);
        assert_eq!(cosine(&b, &a), 0.0);
    }

    #[test]
    fn cosine_returns_zero_for_mismatched_lengths() {
        assert_eq!(cosine(&[1.0, 2.0], &[1.0, 2.0, 3.0]), 0.0);
    }

    #[test]
    fn retrieve_picks_highest_cosine_first() {
        // Rig embeddings so a specific example wins.
        let target = EXAMPLES[5].desc; // pick one in the middle
        let mut entries: Vec<(&str, &[f32])> = vec![
            ("query", &[1.0, 0.0, 0.0, 0.0]),
            (target, &[1.0, 0.0, 0.0, 0.0]), // identical → cosine=1
        ];
        // Every other example gets an orthogonal vector → cosine=0.
        let other: &[f32] = &[0.0, 1.0, 0.0, 0.0];
        let _other_descs: Vec<&str> = EXAMPLES.iter().map(|e| e.desc).collect();
        for ex in EXAMPLES.iter() {
            if ex.desc == target {
                continue;
            }
            entries.push((ex.desc, other));
        }
        let stub = StubEmbed::new(&entries);
        let top = retrieve(&stub, "query", 3).unwrap();
        assert_eq!(top.len(), 3);
        assert_eq!(
            top[0].id, EXAMPLES[5].id,
            "highest-cosine example should rank first"
        );
    }

    #[test]
    fn retrieve_breaks_ties_by_library_order() {
        // Every example gets the same vector → ties everywhere.
        // Result should preserve EXAMPLES ordering for the top-K.
        let mut entries: Vec<(&str, &[f32])> = vec![("query", &[1.0, 1.0, 0.0, 0.0])];
        let same: &[f32] = &[1.0, 1.0, 0.0, 0.0];
        for ex in EXAMPLES.iter() {
            entries.push((ex.desc, same));
        }
        let stub = StubEmbed::new(&entries);
        let top = retrieve(&stub, "query", 4).unwrap();
        assert_eq!(top.len(), 4);
        assert_eq!(top[0].id, EXAMPLES[0].id);
        assert_eq!(top[1].id, EXAMPLES[1].id);
        assert_eq!(top[2].id, EXAMPLES[2].id);
        assert_eq!(top[3].id, EXAMPLES[3].id);
    }

    #[test]
    fn cached_embed_does_not_reinvoke_for_repeats() {
        let inner = StubEmbed::new(&[("foo", &[1.0; 4])]);
        let cached = CachedEmbed::new(inner);
        let _ = cached.embed("foo").unwrap();
        let _ = cached.embed("foo").unwrap();
        let _ = cached.embed("foo").unwrap();
        assert_eq!(
            cached.inner.calls(),
            1,
            "repeated embed of same text should hit cache"
        );
    }

    #[test]
    fn precompute_warms_cache_for_every_example() {
        let mut entries: Vec<(&str, &[f32])> = Vec::new();
        let v: &[f32] = &[1.0; 4];
        for ex in EXAMPLES.iter() {
            entries.push((ex.desc, v));
        }
        let stub = StubEmbed::new(&entries);
        let cached = CachedEmbed::new(stub);
        cached.precompute_library_embeddings().unwrap();
        assert_eq!(cached.cache_size(), EXAMPLES.len());
    }

    #[test]
    fn render_examples_includes_index_desc_and_code() {
        let picked: Vec<&Example> = vec![&EXAMPLES[0], &EXAMPLES[1]];
        let s = render_examples(&picked);
        assert!(s.contains("--- Example 1: "));
        assert!(s.contains("--- Example 2: "));
        assert!(s.contains(EXAMPLES[0].code));
        assert!(s.contains(EXAMPLES[1].code));
    }

    #[test]
    fn examples_library_is_non_empty_and_has_unique_ids() {
        assert!(!EXAMPLES.is_empty());
        let mut seen = std::collections::HashSet::new();
        for ex in EXAMPLES {
            assert!(
                seen.insert(ex.id),
                "duplicate example id in library: {}",
                ex.id
            );
            assert!(!ex.desc.is_empty(), "example {} has empty desc", ex.id);
            assert!(!ex.code.is_empty(), "example {} has empty code", ex.id);
        }
    }
}
