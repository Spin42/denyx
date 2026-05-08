//! System-prompt assembly for the local executor model.
//!
//! Two pieces:
//!
//! - [`SYSTEM_PROMPT_TEMPLATE`] — the long Starlark-rules prompt (ported
//!   verbatim from `local_mcp.py`). Has two `{tools_routing}` and
//!   `{retrieved_examples}` placeholders we substitute at call time.
//! - [`load_tools_routing`] / [`render_tools_routing`] — pull the
//!   long-form `[tools.X]` block out of a policy TOML file and format
//!   it as a "DECLARED TOOLS" prompt section so the model uses the
//!   declared backend URLs instead of inventing different ones.

use std::path::Path;

/// The system prompt template. `{tools_routing}` and
/// `{retrieved_examples}` are substituted at runtime.
pub const SYSTEM_PROMPT_TEMPLATE: &str = r#"You are a local code executor running under the Denyx policy-enforced runtime.

A cloud orchestrator (Claude Sonnet or Opus) is delegating a single step to you. Your job: produce a Starlark program that accomplishes that step. Starlark looks like Python but is a STRICT SUBSET — read the rules carefully.

================================================================
HARD RULES — these will cause a parse error
================================================================

1. NO `import` statements. Modules are pre-loaded; reference them directly (json.encode, json.decode are already available — do NOT write `import json`).

2. NO f-strings. The syntax `f"x = {value}"` is REJECTED.
   Use `"x = " + str(value)` or `"x = {}".format(value)`.

3. NO top-level `for` / `if` statements. Wrap them inside a `def helper(): ...` and call the def. List comprehensions and inline ternary `a if cond else b` ARE allowed at top level.

4. NO `try`/`except`. Let errors propagate.

5. NO `class`, NO `with`, NO Python file objects, NO `os`, NO `sys`, NO `subprocess` module, NO `urllib`, NO `requests`. The ONLY way to do I/O is through the namespaced builtins below.

6. Every top-level statement must start at COLUMN 0. No leading whitespace on module-level lines.

================================================================
NAMESPACED BUILTINS (policy-gated; can fail at runtime)
================================================================

fs.read(path: str) -> str
fs.write(path: str, content: str)
fs.delete(path: str)
net.http_get(url: str) -> str
net.http_post(url: str, body: str) -> str
subprocess.exec(argv: list[str]) -> str   # returns stdout; raises on non-zero exit
env.read(name: str) -> str

================================================================
PURE HELPERS (no imports needed)
================================================================

json.encode(value) -> str
json.decode(s: str) -> value
print(...)                            # captured as program output
len, str, int, float, bool, list, dict, range, sorted, reversed, min, max, sum
.split, .strip, .startswith, .endswith, .replace, .upper, .lower, .format, .count, .find, .join
list/dict comprehensions

{tools_routing}================================================================
WORKED EXAMPLES — patterns most relevant to your step
================================================================

{retrieved_examples}

================================================================
OUTPUT FORMAT
================================================================

Output ONLY the Starlark program. No commentary. No markdown fences. Begin immediately at column 0.
"#;

/// One declared tool's routing info. Pulled from `[tools.X]`
/// long-form entries in the policy file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolRoute {
    pub name: String,
    pub capabilities: Vec<String>,
    pub backend_url: String,
    pub backend_method: String,
    pub description: String,
}

/// Parse the long-form `[tools.X]` entries out of a policy TOML file.
/// Short-form entries (`Tool = ["cap1", "cap2"]`) are skipped — they
/// have no backend_url to surface. Returns an empty vec on any read
/// or parse error so the caller can degrade gracefully.
pub fn load_tools_routing(policy_path: &Path) -> Vec<ToolRoute> {
    let body = match std::fs::read_to_string(policy_path) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    parse_tools_routing(&body)
}

/// TOML-string variant of [`load_tools_routing`]. Exposed for testing.
pub fn parse_tools_routing(toml_body: &str) -> Vec<ToolRoute> {
    let parsed: toml::Value = match toml::from_str(toml_body) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let tools = match parsed.get("tools").and_then(|v| v.as_table()) {
        Some(t) => t,
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    for (name, entry) in tools.iter() {
        let table = match entry.as_table() {
            Some(t) => t,
            None => continue, // short-form: skip
        };
        let url = match table.get("backend_url").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => continue,
        };
        let capabilities: Vec<String> = table
            .get("capabilities")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let backend_method = table
            .get("backend_method")
            .and_then(|v| v.as_str())
            .unwrap_or("GET")
            .to_uppercase();
        let description = table
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        out.push(ToolRoute {
            name: name.clone(),
            capabilities,
            backend_url: url,
            backend_method,
            description,
        });
    }
    // Stable ordering by name so the prompt is deterministic.
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Format a Declared-Tools block for the system prompt. Returns an
/// empty string if no routed tools — caller can drop the placeholder
/// entirely without leaving an awkward header.
pub fn render_tools_routing(routes: &[ToolRoute]) -> String {
    if routes.is_empty() {
        return String::new();
    }
    let mut lines = vec![
        "================================================================".to_string(),
        "DECLARED TOOLS (use these URLs when the orchestrator asks for them)".to_string(),
        "================================================================".to_string(),
        String::new(),
        "Each entry below is a named operation declared in the policy file".to_string(),
        "with a fixed backend URL. When the step description mentions one".to_string(),
        "of these tool names (or its purpose), call the listed URL via the".to_string(),
        "matching net.http_* builtin — do NOT invent a different host.".to_string(),
        String::new(),
    ];
    for r in routes {
        lines.push(format!(
            "- {}: {} {}",
            r.name, r.backend_method, r.backend_url
        ));
        if !r.description.is_empty() {
            lines.push(format!("    {}", r.description));
        }
    }
    lines.push(String::new());
    lines.join("\n")
}

/// Substitute the two placeholders in the system prompt template.
/// Both are simple string replaces — tools_routing typically ends
/// with a newline so the next-section header lines up.
pub fn render_system_prompt(tools_routing: &str, retrieved_examples: &str) -> String {
    SYSTEM_PROMPT_TEMPLATE
        .replace("{tools_routing}", tools_routing)
        .replace("{retrieved_examples}", retrieved_examples)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tools_routing_picks_up_long_form_only() {
        let body = r#"
[tools.GitHubRepo]
capabilities = ["net.http_get"]
backend_url = "https://api.github.com/repos"
backend_method = "GET"
description = "Fetch a repo's metadata"

[tools.SecondTool]
capabilities = ["net.http_post"]
backend_url = "https://api.example.com/post"
# no method → defaults to GET (.upper())

[tools]
ShortForm = ["fs.read"]
"#;
        let out = parse_tools_routing(body);
        assert_eq!(out.len(), 2, "two long-form entries; short-form skipped");
        // Stable order by name.
        assert_eq!(out[0].name, "GitHubRepo");
        assert_eq!(out[0].backend_method, "GET");
        assert_eq!(out[0].description, "Fetch a repo's metadata");
        assert_eq!(out[1].name, "SecondTool");
        assert_eq!(
            out[1].backend_method, "GET",
            "missing backend_method defaults to GET"
        );
    }

    #[test]
    fn parse_tools_routing_skips_entries_without_backend_url() {
        let body = r#"
[tools.NoUrl]
capabilities = ["net.http_get"]
description = "no URL set"
"#;
        let out = parse_tools_routing(body);
        assert!(out.is_empty());
    }

    #[test]
    fn parse_tools_routing_returns_empty_on_garbage_toml() {
        let out = parse_tools_routing("this is === broken === toml [[");
        assert!(out.is_empty());
    }

    #[test]
    fn parse_tools_routing_returns_empty_when_no_tools_section() {
        let out = parse_tools_routing("[network]\nhttp_get_allow = []\n");
        assert!(out.is_empty());
    }

    #[test]
    fn parse_tools_routing_uppercases_lowercase_methods() {
        let body = r#"
[tools.X]
backend_url = "https://x"
backend_method = "post"
"#;
        let out = parse_tools_routing(body);
        assert_eq!(out[0].backend_method, "POST");
    }

    #[test]
    fn render_tools_routing_returns_empty_for_no_routes() {
        assert_eq!(render_tools_routing(&[]), "");
    }

    #[test]
    fn render_tools_routing_includes_method_url_and_description() {
        let routes = vec![ToolRoute {
            name: "GitHubRepo".into(),
            capabilities: vec!["net.http_get".into()],
            backend_url: "https://api.github.com/repos/foo/bar".into(),
            backend_method: "GET".into(),
            description: "Fetch a repo".into(),
        }];
        let s = render_tools_routing(&routes);
        assert!(s.contains("DECLARED TOOLS"));
        assert!(s.contains("GitHubRepo: GET https://api.github.com/repos/foo/bar"));
        assert!(s.contains("    Fetch a repo"));
    }

    #[test]
    fn render_tools_routing_omits_description_line_when_empty() {
        let routes = vec![ToolRoute {
            name: "X".into(),
            capabilities: vec![],
            backend_url: "https://x".into(),
            backend_method: "GET".into(),
            description: "".into(),
        }];
        let s = render_tools_routing(&routes);
        assert!(s.contains("- X: GET https://x"));
        // No 4-space-indented description line.
        for line in s.lines() {
            assert!(
                !line.starts_with("    ") || line.is_empty(),
                "unexpected description line: {line:?}"
            );
        }
    }

    #[test]
    fn render_system_prompt_substitutes_both_placeholders() {
        let s = render_system_prompt("[ROUTING]", "[EXAMPLES]");
        assert!(s.contains("[ROUTING]"));
        assert!(s.contains("[EXAMPLES]"));
        assert!(!s.contains("{tools_routing}"));
        assert!(!s.contains("{retrieved_examples}"));
    }

    #[test]
    fn render_system_prompt_keeps_hard_rules_section() {
        let s = render_system_prompt("", "");
        assert!(s.contains("HARD RULES"));
        assert!(s.contains("NO `import` statements"));
        assert!(s.contains("NO f-strings"));
        assert!(s.contains("NO top-level `for` / `if`"));
    }

    #[test]
    fn load_tools_routing_returns_empty_for_missing_file() {
        let nonexistent = std::path::PathBuf::from("/nonexistent/policy.toml");
        let out = load_tools_routing(&nonexistent);
        assert!(out.is_empty());
    }
}
