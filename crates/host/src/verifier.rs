//! Pre-execution verifier. Walks the script source for any reference to
//! a known Denyx capability name and rejects the script before evaluation
//! if the capability is not in `policy.functions.allow`.
//!
//! This is the "compile-time" line of defense. The runtime interceptor
//! is the second line — both must agree before a capability fires. The
//! verifier strips comments and string literals first so capability names
//! quoted as data don't cause false positives.
//!
//! The verifier also enforces a static **tainted-output-flow** check
//! (the `taint_flow` module below): a script that reads any
//! `local_only_*` env var or filesystem path, and separately contains
//! an output-producing call (`print`, `fs.write`, `fs.delete`,
//! `net.http_*`, `subprocess.exec`) reachable from that read, is
//! refused before execution. This tightens the asymmetric Round-1
//! behaviour where `print` of a tainted value was permitted-then-
//! scrubbed and `fs.write` was refused at the arg-side gate; both now
//! refuse uniformly at the verifier when the check fires. The
//! motivation (Round-2 pentest) is documented in
//! `docs/security-pentest-r2-tool-poisoning.md`.
//!
//! Two passes implement this, in order (see `taint_flow`'s own module
//! doc for the full design): an AST-based pass (`detect_ast`, built on
//! `starlark_syntax`) that constant-folds simple string expressions
//! (literals, direct variable assignment, `+`-concatenation) and
//! tracks taint flow-sensitively across the top-level statement
//! sequence, plus a byte-level literal-argument pass (`detect`) kept
//! as a fallback for when parsing fails.
//!
//! **Honest scope note:** this remains a static pre-filter, not a
//! robust second line of defense equivalent to the runtime layer — it
//! exists to catch the easy and moderately obfuscated cases before
//! wasted execution, not to bound what a script can do. It does not
//! perform full data-flow analysis: values threaded through anything
//! beyond `+`-concatenation (string formatting, slicing, computed
//! results), or through a `def`/`lambda` call boundary under a
//! different name, can still evade the *precise* check (a coarse
//! whole-script fallback catches the `def`/`lambda`/`load()` case at
//! the cost of possible false positives — see `taint_flow`'s doc).
//! Whatever evades both passes falls through to the runtime taint
//! layer (`crates/host/src/taint.rs`), which is what actually enforces
//! the no-exfiltration property (see `docs/04-security-threat-model.md`).
//! Treat "the verifier didn't reject this script" as no signal at all
//! about whether it leaks local-only data.

use std::collections::BTreeSet;

use denyx_policy::Policy;

use crate::CAPABILITIES;

#[derive(Debug, thiserror::Error)]
pub enum VerifierRejection {
    #[error("verifier: capability {capability:?} called by script but not allowed by policy")]
    Capability { capability: String },

    /// A script reads at least one `local_only_*` value and also
    /// contains at least one output-producing call. The two cannot
    /// coexist: if the read is required for compute, the script must
    /// avoid all outputs; if any output is required, it must not
    /// also read local-only data.
    #[error(
        "verifier: tainted-output-flow refused — script reads local-only data \
         ({sources:?}) AND contains output-producing call(s) ({outputs:?}); \
         local-only values may not flow to non-local-only destinations. To use \
         local-only data, restructure the script so its outputs do not appear \
         after a local-only read, or route output through a local-only sink"
    )]
    TaintFlow {
        sources: Vec<String>,
        outputs: Vec<String>,
    },
}

pub fn verify(source: &str, policy: &Policy) -> Result<(), VerifierRejection> {
    let stripped = strip_strings_and_comments(source);
    let used = scan_capabilities(&stripped);
    for cap in used {
        if policy.check_function(&cap).is_err() {
            return Err(VerifierRejection::Capability { capability: cap });
        }
    }
    // `detect_ast` returns `Some(verdict)` when it successfully parsed
    // the script — in that case its verdict (including exemptions like
    // "subprocess.exec to a local_only_commands entry is a safe sink")
    // is authoritative and `detect` must NOT be run afterwards to
    // second-guess it with a blind byte-level scan that doesn't know
    // about that exemption. `detect` only runs as a fallback when the
    // AST pass couldn't even parse the script (`None`).
    match taint_flow::detect_ast(source, &stripped, policy) {
        Some(Some((sources, outputs))) => {
            return Err(VerifierRejection::TaintFlow { sources, outputs });
        }
        Some(None) => {}
        None => {
            if let Some((sources, outputs)) = taint_flow::detect(source, &stripped, policy) {
                return Err(VerifierRejection::TaintFlow { sources, outputs });
            }
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

/// Static tainted-output-flow detection. See module docstring.
///
/// The check is intentionally conservative: any `env.read` or `fs.read`
/// whose literal-string argument matches a `local_only_*` entry counts
/// as a local-only read. Non-literal arguments (variables,
/// concatenations) are not analysed here — they fall through to the
/// runtime taint layer, which is unchanged.
mod taint_flow {
    use super::{contains_word, is_ident_byte};
    use denyx_policy::Policy;
    use starlark_syntax::syntax::ast::{
        ArgumentP, AssignTargetP, AstExpr, AstLiteral, AstStmt, BinOp, ClauseP, ExprP, StmtP,
    };
    use starlark_syntax::syntax::module::AstModuleFields;
    use starlark_syntax::syntax::{AstModule, Dialect};
    use std::collections::{BTreeSet, HashMap};
    use std::path::Path;

    /// The output-producing calls. If any of these is present in a
    /// script that also reads a local-only value, the verifier refuses
    /// pre-exec. `subprocess.exec` is included even though its argv-
    /// gate would refuse a tainted argv at runtime: a tainted value can
    /// still influence subprocess behaviour via control flow (e.g.
    /// "spawn echo IF the secret starts with X"), so the conservative
    /// answer is to refuse the combination at source level.
    const OUTPUT_CALLS: &[&str] = &[
        "print",
        "fs.write",
        "fs.delete",
        "net.http_get",
        "net.http_post",
        "net.http_put",
        "net.http_patch",
        "net.http_delete",
        "subprocess.exec",
    ];

    /// Returns `Some((sources, outputs))` if the script contains BOTH
    /// a local-only read AND an output call. `source` is the raw
    /// script (used for literal-arg extraction); `stripped` is the
    /// strings-and-comments-removed view used for output-call
    /// presence checks (so a `"print"` string literal inside a
    /// docstring doesn't trip the gate).
    pub fn detect(
        source: &str,
        stripped: &str,
        policy: &Policy,
    ) -> Option<(Vec<String>, Vec<String>)> {
        let mut sources: Vec<String> = Vec::new();

        for name in extract_literal_args(source, "env.read") {
            if policy.env_is_local_only(&name) {
                let tag = format!("env.read({name:?})");
                if !sources.contains(&tag) {
                    sources.push(tag);
                }
            }
        }
        for path_str in extract_literal_args(source, "fs.read") {
            let p = Path::new(&path_str);
            if policy.fs_read_is_local_only(p) {
                let tag = format!("fs.read({path_str:?})");
                if !sources.contains(&tag) {
                    sources.push(tag);
                }
            }
        }
        if sources.is_empty() {
            return None;
        }

        let mut outputs: Vec<String> = Vec::new();
        for call in OUTPUT_CALLS {
            if contains_word(stripped, call) {
                outputs.push((*call).to_string());
            }
        }
        if outputs.is_empty() {
            return None;
        }
        Some((sources, outputs))
    }

    /// AST-based tainted-output-flow detection. Closes the evasion gap
    /// in `detect()` above, which only recognises LITERAL string
    /// arguments to `env.read`/`fs.read`: a script that instead builds
    /// the path/name from a variable or `+`-concatenation
    /// (`prefix = "local/only/"; path = prefix + "secret"; fs.read(path)`)
    /// is invisible to `extract_literal_args`'s byte scan but is exactly
    /// the kind of trivial rewrite an attacker (or an injected
    /// instruction) would try first.
    ///
    /// Scope, deliberately bounded — this is still a pre-filter, not the
    /// runtime taint layer that actually enforces the property:
    /// - Only the top-level statement sequence gets flow-sensitive
    ///   tracking: which identifiers currently hold a value derived from
    ///   a local-only read (`tainted`), and which currently hold a known
    ///   concrete string (`known`, used to fold `+`-concatenation and
    ///   simple reassignment so a *computed* path/name can still be
    ///   checked against the same `Policy` predicates `detect()` uses on
    ///   literals). Reassignment strong-updates both sets in program
    ///   order, matching how Starlark actually executes top-level code.
    /// - Every statement (including nested `if`/`for`/`def` bodies) is
    ///   still walked for the actual "does a call to an output function
    ///   reference a currently-tainted identifier" check, so a leak
    ///   inside a conditional or a nested block is caught directly.
    /// - If the script defines a function (`def`), a `lambda`, or uses
    ///   `load()` anywhere, the direct-reference check above cannot be
    ///   trusted to see every path a tainted value could reach an
    ///   output through — a call could pass it through under a
    ///   different parameter name and return something that looks
    ///   unrelated. Real interprocedural analysis is out of scope here,
    ///   so instead of silently under-reporting, the pass falls back to
    ///   a coarse whole-script check: if the sequential pass proved a
    ///   local-only read occurred at all, and an output call exists
    ///   anywhere in the script (byte-level, same technique `detect()`
    ///   uses), refuse — without trying to prove that specific data
    ///   flow. This mirrors `detect()`'s own coarseness, applied only
    ///   when the precise check could plausibly be blind.
    ///
    /// Known false-negative: this does not track values through
    /// assignment TARGETS other than a plain identifier (`x[i] = ...`,
    /// `obj.field = ...`), and does not attempt alias analysis across
    /// containers, dicts, or comprehensions. Those fall through to the
    /// runtime taint layer, same as before this pass existed.
    ///
    /// Returns `None` (outer) only when the script fails to parse — the
    /// caller should fall back to the byte-level `detect()` in that
    /// case. Once parsing succeeds, the inner `Option` is authoritative
    /// and must not be second-guessed by `detect()`: this pass reasons
    /// about specific exemptions (e.g. `subprocess.exec` to a
    /// `local_only_commands` entry is a safe sink, not a taint output)
    /// that the blind byte-level scan doesn't know about, so re-running
    /// `detect()` afterwards could re-flag a script this pass correctly
    /// cleared.
    pub fn detect_ast(
        source: &str,
        stripped: &str,
        policy: &Policy,
    ) -> Option<Option<(Vec<String>, Vec<String>)>> {
        let module = AstModule::parse("script", source.to_owned(), &Dialect::Standard).ok()?;
        let root = module.statement();

        let has_indirection = contains_def_lambda_or_load(root);
        let top_level = flatten_top_level(root);

        let mut known: HashMap<String, String> = HashMap::new();
        let mut tainted: BTreeSet<String> = BTreeSet::new();
        let mut sources: Vec<String> = Vec::new();
        let mut outputs: Vec<String> = Vec::new();

        for stmt in &top_level {
            // Evaluated against the taint state as of BEFORE this
            // statement's own assignment effect, matching real
            // execution order (a line's RHS/body runs before its own
            // LHS binds).
            collect_tainted_outputs(stmt, &tainted, &known, policy, &mut sources, &mut outputs);

            if let StmtP::Assign(assign) = &stmt.node {
                if let AssignTargetP::Identifier(id) = &assign.lhs.node {
                    let name = id.node.ident.clone();
                    match read_call_taint(&assign.rhs, &known, policy) {
                        Some(tag) => {
                            tainted.insert(name);
                            if !sources.contains(&tag) {
                                sources.push(tag);
                            }
                        }
                        None => {
                            tainted.remove(&name);
                            match fold_str(&assign.rhs, &known) {
                                Some(s) => {
                                    known.insert(name, s);
                                }
                                None => {
                                    known.remove(&name);
                                }
                            }
                        }
                    }
                }
            }
        }

        if !sources.is_empty() && !outputs.is_empty() {
            return Some(Some((sources, outputs)));
        }

        // Coarse fallback — see module doc above.
        if has_indirection && !sources.is_empty() {
            let mut all_outputs: Vec<String> = Vec::new();
            for call in OUTPUT_CALLS {
                if contains_word(stripped, call) {
                    all_outputs.push((*call).to_string());
                }
            }
            if !all_outputs.is_empty() {
                return Some(Some((sources, all_outputs)));
            }
        }

        Some(None)
    }

    /// Immediate child statements and expressions of `stmt`, for
    /// recursive walks. Assignment LHS targets other than a plain
    /// identifier (index/dot) are deliberately not descended into — see
    /// `detect_ast`'s "known false-negative" note.
    fn stmt_children(
        stmt: &StmtP<starlark_syntax::syntax::ast::AstNoPayload>,
    ) -> (Vec<&AstStmt>, Vec<&AstExpr>) {
        match stmt {
            StmtP::Break | StmtP::Continue | StmtP::Pass | StmtP::Load(_) => (vec![], vec![]),
            StmtP::Return(e) => (vec![], e.iter().collect()),
            StmtP::Expression(e) => (vec![], vec![e]),
            StmtP::Assign(a) => (vec![], vec![&a.rhs]),
            StmtP::AssignModify(_, _, e) => (vec![], vec![e]),
            StmtP::Statements(v) => (v.iter().collect(), vec![]),
            StmtP::If(cond, body) => (vec![body.as_ref()], vec![cond]),
            StmtP::IfElse(cond, bodies) => (vec![&bodies.0, &bodies.1], vec![cond]),
            StmtP::For(f) => (vec![f.body.as_ref()], vec![&f.over]),
            StmtP::Def(d) => (vec![d.body.as_ref()], vec![]),
        }
    }

    /// Immediate child expressions of `expr`, for recursive walks.
    fn expr_children(expr: &AstExpr) -> Vec<&AstExpr> {
        match &expr.node {
            ExprP::Tuple(v) | ExprP::List(v) => v.iter().collect(),
            ExprP::Dot(e, _) => vec![e],
            ExprP::Call(callee, args) => {
                let mut v = vec![callee.as_ref()];
                v.extend(args.args.iter().map(|a| a.node.expr()));
                v
            }
            ExprP::Index(b) => vec![&b.0, &b.1],
            ExprP::Index2(b) => vec![&b.0, &b.1, &b.2],
            ExprP::Slice(e, a, b, c) => {
                let mut v = vec![e.as_ref()];
                v.extend(a.as_deref());
                v.extend(b.as_deref());
                v.extend(c.as_deref());
                v
            }
            ExprP::Identifier(_) | ExprP::Literal(_) => vec![],
            ExprP::Lambda(l) => vec![&l.body],
            ExprP::Not(e) | ExprP::Minus(e) | ExprP::Plus(e) | ExprP::BitNot(e) => vec![e],
            ExprP::Op(l, _, r) => vec![l, r],
            ExprP::If(b) => vec![&b.0, &b.1, &b.2],
            ExprP::Dict(pairs) => pairs.iter().flat_map(|(k, v)| [k, v]).collect(),
            ExprP::ListComprehension(e, for_clause, clauses) => {
                let mut v = vec![e.as_ref(), &for_clause.over];
                v.extend(clauses.iter().map(clause_expr));
                v
            }
            ExprP::DictComprehension(b, for_clause, clauses) => {
                let mut v = vec![&b.0, &b.1, &for_clause.over];
                v.extend(clauses.iter().map(clause_expr));
                v
            }
            ExprP::FString(f) => f.expressions.iter().collect(),
        }
    }

    fn clause_expr(clause: &ClauseP<starlark_syntax::syntax::ast::AstNoPayload>) -> &AstExpr {
        match clause {
            ClauseP::For(fc) => &fc.over,
            ClauseP::If(e) => e,
        }
    }

    /// Whether `def`, `lambda`, or `load()` appears anywhere in the
    /// (sub)tree rooted at `stmt`.
    fn contains_def_lambda_or_load(stmt: &AstStmt) -> bool {
        if matches!(&stmt.node, StmtP::Def(_) | StmtP::Load(_)) {
            return true;
        }
        let (child_stmts, child_exprs) = stmt_children(&stmt.node);
        child_stmts.iter().any(|s| contains_def_lambda_or_load(s))
            || child_exprs.iter().any(|e| expr_contains_lambda(e))
    }

    fn expr_contains_lambda(expr: &AstExpr) -> bool {
        matches!(&expr.node, ExprP::Lambda(_))
            || expr_children(expr).iter().any(|e| expr_contains_lambda(e))
    }

    /// Split `stmt`'s subtree (module root, one top-level statement at a
    /// time) into its flat top-level list, or a single-element list if
    /// `stmt` isn't the `Statements` wrapper the parser wraps a module
    /// body in.
    fn flatten_top_level(stmt: &AstStmt) -> Vec<&AstStmt> {
        match &stmt.node {
            StmtP::Statements(v) => v.iter().collect(),
            _ => vec![stmt],
        }
    }

    /// Recursively walks `stmt`'s ENTIRE subtree (including nested
    /// `if`/`for`/`def` bodies) looking for calls to an `OUTPUT_CALLS`
    /// function whose argument expression references a currently-
    /// tainted identifier. Appends any findings to `sources`/`outputs`
    /// (deduplicated). `known` and `policy` are only used to evaluate
    /// the `subprocess.exec`-to-a-local-only-command exemption — see
    /// `is_local_only_subprocess_sink`.
    fn collect_tainted_outputs(
        stmt: &AstStmt,
        tainted: &BTreeSet<String>,
        known: &HashMap<String, String>,
        policy: &Policy,
        sources: &mut Vec<String>,
        outputs: &mut Vec<String>,
    ) {
        let (child_stmts, child_exprs) = stmt_children(&stmt.node);
        for e in &child_exprs {
            collect_tainted_outputs_expr(e, tainted, known, policy, sources, outputs);
        }
        for s in &child_stmts {
            collect_tainted_outputs(s, tainted, known, policy, sources, outputs);
        }
    }

    fn collect_tainted_outputs_expr(
        expr: &AstExpr,
        tainted: &BTreeSet<String>,
        known: &HashMap<String, String>,
        policy: &Policy,
        sources: &mut Vec<String>,
        outputs: &mut Vec<String>,
    ) {
        if let ExprP::Call(callee, args) = &expr.node {
            if let Some(name) = dotted_name(callee) {
                let exempt =
                    name == "subprocess.exec" && is_local_only_subprocess_sink(args, known, policy);
                if OUTPUT_CALLS.contains(&name.as_str()) && !exempt {
                    for a in &args.args {
                        if let Some(tag) = find_taint_in_expr(a.node.expr(), tainted, known, policy)
                        {
                            if !sources.contains(&tag) {
                                sources.push(tag);
                            }
                            if !outputs.contains(&name) {
                                outputs.push(name.clone());
                            }
                        }
                    }
                }
            }
        }
        for child in expr_children(expr) {
            collect_tainted_outputs_expr(child, tainted, known, policy, sources, outputs);
        }
    }

    /// Whether `subprocess.exec`'s argv[0] (the first element of its
    /// first positional argument, expected to be a list literal) folds
    /// to a command `policy` marks `local_only_commands` — the same
    /// safe-sink exemption the runtime taint layer already grants:
    /// local-only commands are a documented, intentional destination
    /// for local-only data, not exfiltration. An unresolvable argv[0]
    /// (built dynamically) is NOT exempted — conservative default,
    /// matching `OUTPUT_CALLS`'s own doc on why `subprocess.exec` is
    /// included at all (tainted control flow can still influence which
    /// command/branch runs).
    fn is_local_only_subprocess_sink(
        args: &starlark_syntax::syntax::ast::CallArgsP<starlark_syntax::syntax::ast::AstNoPayload>,
        known: &HashMap<String, String>,
        policy: &Policy,
    ) -> bool {
        let argv0 = args
            .args
            .iter()
            .find_map(|a| match &a.node {
                ArgumentP::Positional(e) => Some(e),
                _ => None,
            })
            .and_then(|first| match &first.node {
                ExprP::List(items) => items.first(),
                _ => None,
            })
            .and_then(|e| fold_str(e, known));
        argv0.is_some_and(|argv0| policy.subprocess_is_local_only(&argv0))
    }

    /// Does `expr`'s subtree contain a taint source — either a
    /// reference to an identifier currently in `tainted`, or an INLINE
    /// local-only `env.read`/`fs.read` call used directly as part of
    /// the expression (no intermediate variable, e.g.
    /// `print("token=" + fs.read("/local/only/path"))`)? Returns a
    /// source tag for the first match found: `<name>` for the
    /// identifier case, or `read_call_taint`'s own tag (e.g.
    /// `fs.read("/path")`) for the inline-call case.
    fn find_taint_in_expr(
        expr: &AstExpr,
        tainted: &BTreeSet<String>,
        known: &HashMap<String, String>,
        policy: &Policy,
    ) -> Option<String> {
        if let Some(tag) = read_call_taint(expr, known, policy) {
            return Some(tag);
        }
        if let ExprP::Identifier(id) = &expr.node {
            if tainted.contains(&id.node.ident) {
                return Some(format!("<{}>", id.node.ident));
            }
        }
        expr_children(expr)
            .into_iter()
            .find_map(|e| find_taint_in_expr(e, tainted, known, policy))
    }

    /// Fully-qualified call-target name (`"env.read"`, `"fs.read"`,
    /// `"print"`), or `None` if the callee isn't a plain
    /// identifier/dot-chain (e.g. an indexed or computed callee).
    fn dotted_name(expr: &AstExpr) -> Option<String> {
        match &expr.node {
            ExprP::Identifier(id) => Some(id.node.ident.clone()),
            ExprP::Dot(inner, field) => Some(format!("{}.{}", dotted_name(inner)?, field.node)),
            _ => None,
        }
    }

    /// Constant-fold a string expression: literals, identifiers already
    /// resolved to a known concrete string in `known`, and `+`-
    /// concatenation of foldable sub-expressions. Anything else (calls,
    /// formatting, unresolvable identifiers) is not foldable — `None`.
    fn fold_str(expr: &AstExpr, known: &HashMap<String, String>) -> Option<String> {
        match &expr.node {
            ExprP::Literal(AstLiteral::String(s)) => Some(s.node.clone()),
            ExprP::Identifier(id) => known.get(&id.node.ident).cloned(),
            ExprP::Op(lhs, BinOp::Add, rhs) => {
                let mut s = fold_str(lhs, known)?;
                s.push_str(&fold_str(rhs, known)?);
                Some(s)
            }
            _ => None,
        }
    }

    /// If `expr` is a call to `env.read`/`fs.read` whose first
    /// positional argument folds (via `fold_str`) to a concrete string
    /// that `policy` classifies as local-only, returns a source tag for
    /// it. This is `detect()`'s literal check generalised to any
    /// foldable expression, not just a bare string literal.
    fn read_call_taint(
        expr: &AstExpr,
        known: &HashMap<String, String>,
        policy: &Policy,
    ) -> Option<String> {
        let ExprP::Call(callee, args) = &expr.node else {
            return None;
        };
        let name = dotted_name(callee)?;
        if name != "env.read" && name != "fs.read" {
            return None;
        }
        let first_positional = args.args.iter().find_map(|a| match &a.node {
            ArgumentP::Positional(e) => Some(e),
            _ => None,
        })?;
        let value = fold_str(first_positional, known)?;
        let is_local_only = if name == "env.read" {
            policy.env_is_local_only(&value)
        } else {
            policy.fs_read_is_local_only(Path::new(&value))
        };
        is_local_only.then(|| format!("{name}({value:?})"))
    }

    /// Extract literal string arguments of every `fn_call("...")`
    /// occurrence in `source`. Walks bytes directly (no Starlark
    /// parser dependency), in the same style as the rest of the
    /// verifier. Skips occurrences where the arg is a variable / a
    /// concatenation / anything other than a single string literal —
    /// those cases fall through to the runtime taint layer.
    fn extract_literal_args(source: &str, fn_call: &str) -> Vec<String> {
        let bytes = source.as_bytes();
        let needle = fn_call.as_bytes();
        let mut out = Vec::new();
        if needle.is_empty() {
            return out;
        }
        let mut i = 0;
        while i + needle.len() <= bytes.len() {
            if &bytes[i..i + needle.len()] == needle {
                let before_ok = i == 0 || !is_ident_byte(bytes[i - 1]);
                let after_ok =
                    i + needle.len() < bytes.len() && !is_ident_byte(bytes[i + needle.len()]);
                if before_ok && after_ok {
                    let mut j = i + needle.len();
                    // Skip whitespace between the name and "(".
                    while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                        j += 1;
                    }
                    if j < bytes.len() && bytes[j] == b'(' {
                        j += 1;
                        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                            j += 1;
                        }
                        if j < bytes.len() && (bytes[j] == b'"' || bytes[j] == b'\'') {
                            let q = bytes[j];
                            j += 1;
                            let start = j;
                            while j < bytes.len() && bytes[j] != q && bytes[j] != b'\n' {
                                if bytes[j] == b'\\' && j + 1 < bytes.len() {
                                    j += 2;
                                } else {
                                    j += 1;
                                }
                            }
                            if j < bytes.len() && bytes[j] == q {
                                if let Ok(lit) = std::str::from_utf8(&bytes[start..j]) {
                                    out.push(lit.to_string());
                                }
                                i = j + 1;
                                continue;
                            }
                        }
                    }
                }
            }
            i += 1;
        }
        out
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn extract_literal_args_picks_up_double_and_single_quoted() {
            let src = r#"
                a = env.read("USER")
                b = env.read('HOME')
                c = fs.read("/tmp/x")
            "#;
            let env_args = extract_literal_args(src, "env.read");
            assert_eq!(env_args, vec!["USER".to_string(), "HOME".to_string()]);
            let fs_args = extract_literal_args(src, "fs.read");
            assert_eq!(fs_args, vec!["/tmp/x".to_string()]);
        }

        #[test]
        fn extract_literal_args_skips_variable_args() {
            let src = "name = \"USER\"\nx = env.read(name)";
            // No literal directly inside env.read(...) — should
            // return empty so the runtime taint layer handles it.
            let env_args = extract_literal_args(src, "env.read");
            assert!(
                env_args.is_empty(),
                "variable arg should not be extracted: {env_args:?}"
            );
        }

        #[test]
        fn extract_literal_args_ignores_unrelated_calls() {
            // `read("foo")` is NOT `env.read("foo")` — the
            // `before_ok` boundary should accept only when the
            // preceding byte isn't an ident byte. Here `obj.read`
            // is a different fully-qualified call. The function-call
            // string here is `env.read`, and `xenv.read` shouldn't
            // match either.
            let src = "xenv.read(\"X\")\nobj.read(\"Y\")";
            let args = extract_literal_args(src, "env.read");
            assert!(
                args.is_empty(),
                "boundary should reject prefix-attached: {args:?}"
            );
        }
    }
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

    // --- Single-quoted (non-triple) handling: lines 744-754 ---

    #[test]
    fn line_double_quoted_string_replaced_with_single_space() {
        // The base case of the non-triple branch: `"abc"` becomes a
        // single space and trailing real code is preserved verbatim.
        // Kills line 753 (post-loop closer-consume `i < len &&
        // bytes[i] == q`) and line 754 (`i += 1` after closer).
        assert_eq!(s("\"abc\"y"), " y");
    }

    #[test]
    fn newline_terminates_unclosed_double_quote_without_eating_newline() {
        // An unclosed string (`"abc\n...`) terminates at the newline.
        // The newline itself MUST stay in the output (the line-
        // counting downstream relies on it). Kills the line-753
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
        // line 747 makes us advance 2 bytes past the `\` so the
        // following `"` is NOT treated as the closer.
        // Original output: " y" (5-byte string + 'y' → space + 'y').
        // Mutant 747:33 (== → !=) on `bytes[i] == b'\\'`: never sees
        // backslash → treats inner `"` as closer at i=2 → output
        // begins differently. Mutant 747:42 (&& → ||): combined with
        // the ==, takes escape branch unconditionally — `i += 2`
        // past end of string would walk off and hit different bytes.
        // Mutant 748:27 (+= → *=): `i *= 2` instead of `i += 2`
        // makes the post-escape index wrong.
        assert_eq!(s("\"\\\"\"y"), " y");
    }

    #[test]
    fn backslash_at_end_of_buffer_does_not_escape_off_end() {
        // `"\` with no following byte. The escape branch has a bounds
        // check `i + 1 < bytes.len()` (line 747). Without it the
        // mutant `i += 2` would index past the end. We require the
        // strip to NOT panic and to emit a single space (the
        // unterminated string is treated as eating to end).
        // Kills the line-747 bounds-check mutants:
        // - 747:47 (+ → -, + → *): wrong arithmetic in `i + 1` makes
        //   the bound `i - 1 < len` (always true for i>0) or `i*1
        //   < len` (true while i < len) — both let the escape branch
        //   be taken with no following byte.
        // - 747:51 (< → ==, < → >, < → <=): bounds check predicates
        //   that diverge from `<` near end-of-buffer.
        assert_eq!(s("\"\\"), " ");
    }

    #[test]
    fn escape_in_string_does_not_skip_real_capability_after() {
        // After an escaped quote inside a string, the strip must
        // resume past the *true* closing quote and leave the
        // following real code intact. Kills 748:27 (`i += 2` →
        // `i *= 2`): a wrong post-escape index would consume more
        // (or fewer) bytes than intended, shifting where the closer
        // is found, so the trailing real code starts at a different
        // offset and the output diverges.
        assert_eq!(s("x = \"a\\nb\"\nfs.read"), "x =  \nfs.read");
    }

    #[test]
    fn unterminated_double_quoted_string_at_eof_emits_space() {
        // Pure end-of-input case (no `\n`, no closer). Kills line
        // 753:48 (`bytes[i] == q` → `!=`): with the post-loop check
        // mutated, an unterminated string would (under == → !=)
        // try to consume a non-quote byte as the closer. Since
        // there are zero bytes, `i < bytes.len()` is false anyway
        // → harmless on this exact input. The combination with
        // 753:22 (`<` → `>`) would make the post-loop branch fire
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

    // --- Triple-quoted handling: lines 734, 736, 738 ---

    #[test]
    fn triple_quoted_at_start_of_input_strips_entire_block() {
        // Critical for line 736:19 (`i += 3` → `i *= 3`). When the
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
        // Symmetric variant for the `'''...'''` form. Same line-736
        // kill applies, AND it forces the strip's quote-symmetry to
        // work: any mutation that hard-coded the closer to `"""`
        // would survive the double-quoted test but fail here.
        assert_eq!(s("'''hello'''"), " ");
    }

    #[test]
    fn triple_quoted_followed_by_real_code_preserves_real_code() {
        // The closer at line 738 must advance i past the closing
        // `"""` so the rest of the file scans normally. Kills:
        // - 738:33 (== → !=) on `bytes[i] == q`: the closer would be
        //   matched on any non-quote byte, ending the docstring
        //   on the very first content byte and exposing real
        //   docstring text.
        // - 738:38 (&& → ||): turns the closer-match into "ANY of
        //   {bytes[i]==q OR bytes[i+1..i+3]==qq}" → premature close
        //   on a SINGLE quote in the docstring.
        // - 738:49 (+ → *): `bytes[i * 1]` collapses the second
        //   check to `bytes[i] == q`, so the closer-match becomes
        //   `bytes[i]==q && bytes[i]==q && bytes[i+2]==q` —
        //   matches on a single-quote followed by something at i+2,
        //   prematurely closing on inputs like `"x"`.
        // - 738:59 (&& → ||): turns the third check into OR, so
        //   `bytes[i+2]==q` alone can close the docstring.
        // - 738:75 (== → !=) on `bytes[i + 2] == q`: closer-match
        //   would fire when bytes[i+2] is NOT q — i.e. on most
        //   docstring content.
        // Output: leading space (the docstring), then `\n` and the
        // real code untouched.
        assert_eq!(s("\"\"\"doc\"\"\"\nfs.read"), " \nfs.read");
    }

    #[test]
    fn triple_quoted_with_inner_double_quote_does_not_close_early() {
        // `"""said "hi" then more"""` contains a single `"` and a
        // pair `""` (no, actually `said "hi"` is `"hi"` = single+
        // single but adjacent to non-quote). Either way it's NOT
        // `"""`. Kills the 738:38 / 738:59 (&& → ||) mutants:
        // those would close on the inner single `"`, exposing
        // ` then more` (and re-processing it as code).
        assert_eq!(s("\"\"\"said \"hi\" then\"\"\""), " ");
    }

    #[test]
    fn triple_quote_detection_requires_three_consecutive_quotes() {
        // Input: `"x"y"z"`. Three single-quoted strings, NO triples
        // anywhere. Kills line 734:57 (+ → *) on `bytes[i + 1]`:
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
        // `"z"`). Kills 738:49 (+ → *): mutant collapses
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

    // --- Comment handling: line 727 ---

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
