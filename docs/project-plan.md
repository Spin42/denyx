# Agent-Safe Local Tooling — Project Plan

> Successor to Sigil (closed 2026-05-04). Carries forward the methodology,
> the harness, and the empirical answers; replaces the language-design bet
> with a safety-first bet.

---

## Vision

Make the failure mode **"agent deletes a production database"** structurally
impossible.

Today's agent stacks let language models execute arbitrary code, call
arbitrary tools, and touch arbitrary filesystems and network endpoints. The
"safety" usually amounts to a system prompt asking the model nicely. When
the model has a bad day — or a prompt-injection attacker has a good one —
nothing in the runtime stops a `DROP TABLE`, an `rm -rf`, an exfiltrating
`curl`, or a credentials-printing `cat ~/.aws`.

The thesis:
- The model never touches the OS directly.
- Every effect-producing action goes through a **typed capability** that
  the orchestrator (or the user) has explicitly granted for the duration
  of this task.
- Effects are **declared in the plan** before any code runs, and verified
  against the granted capabilities at compile time AND interception-checked
  at runtime.
- Destructive operations require **human-in-the-loop confirmation** unless
  the human has pre-authorized them via a typed capability with a clear
  scope (path glob, host allowlist, table name pattern, time window).
- Every action is **audit-logged** with structured provenance: which task,
  which step, which capability, which arguments.

If those four properties hold, "agent deletes production database" is no
longer a class of failure: it requires either (a) the human to have granted
a `db.write("prod_*")` capability, or (b) a bug in the verifier itself —
the same level of trust as any other software boundary.

---

## What ports from Sigil

(See `conclusions.md` and `papers/SIGIL_RESULT.md` for the full
retrospective.)

| Sigil asset | Status in next project |
|---|---|
| MCP server / harness shape | Direct port (`sigil_run_task` → `tool_run`) |
| A/B/C harness | Direct port; same Stream C / 30-task suite as ground truth |
| Validator-in-loop pattern | Direct port (Tier A: name-validity; Tier B: semantic shape-judge) |
| Principles-based 3B judge | Direct port; principles already domain-agnostic (14/14 OOD on synthetic shapes) |
| Cross-base ensemble fresh+T0 | Direct port |
| Sequential corpus generation | Direct port (smaller corpus needed; 200-500 examples not 2300) |
| Soft-pass rescoring discipline | Direct port |
| Meet-halfway methodology | Direct port (will be needed less often — Python is already on-distribution) |
| OCaml interpreter | Drop. Use embedded Starlark or RestrictedPython runtime. |
| 2300-entry Sigil corpus | Drop. Out of distribution for the new target. |
| Sigil-specific lints (paren balancer, language-header strip) | Drop. Unnecessary on Python-shape. |

---

## Architecture

### 1. Surface language: Starlark dialect

Why Starlark:
- Bazel/Buck2/Tilt have validated the embeddable-Python-subset model in
  production for ~10 years.
- `starlark-rust` (Buck2's implementation) is a single embeddable Rust
  crate. Single static binary, fast, maintained.
- Hermetic by design: no I/O, no time, no env, no filesystem in pure
  Starlark. Every effect must be a host-registered builtin.
- Models write Starlark with high zero-shot accuracy (probe data: 37%
  pass on multi-step Path C zero-shot, 12/30 with current 7B local
  Python coder, vs Sigil at 7/30 with 7 retrains).

What's added on top:
- A capability-typed standard library (next section).
- Effect annotations parsed from docstrings or decorators.
- A verifier that checks declared effects ⊂ granted capabilities before
  execution.
- Runtime interception of all builtin calls; second-line check at call
  time (path scope, host allowlist, etc.).

### 2. Capability system

Every potentially-effecting builtin is parameterized by a **capability
token**. Capabilities are typed objects the host grants per-task:

```python
# host code, before execution
caps = {
    "fs": fs_capability(read=["/tmp/*", "/data/inputs/*"],
                        write=[],          # no writes
                        delete=[]),        # no deletes
    "net": net_capability(http_get=["api.example.com"],
                          http_post=[]),
    "subprocess": denied(),                # no shell at all
    "db": db_capability(read=["analytics_*"],
                        write=[],
                        connection="readonly_replica"),
}
```

In the agent's Starlark code:

```python
# @effects(["fs.read"])
def parse_input():
    return fs.read("/data/inputs/today.csv", caps.fs)
```

The verifier:
1. Parses `@effects(["fs.read"])` from the docstring.
2. Walks the AST. If any builtin call's effect is not in the declared list
   → reject before execution.
3. If declared list ⊄ granted capabilities → reject before execution.
4. Runtime interception: when `fs.read` is called, the wrapper checks the
   path is in `caps.fs.read` whitelist. If not → raise + audit log.

This is the U09 thesis Sigil never built, made concrete.

### 3. Destructive-action gating

A separate capability tier for irreversible operations:

```python
caps = {
    "fs.delete": confirm_per_call(),     # human prompt every time
    "fs.delete": pre_authorized(scope="/tmp/*", expires="5m"),
    "db.write.prod": denied(),
}
```

`confirm_per_call()` triggers a synchronous human-confirm hook before the
action runs; the capability framework calls back to the orchestrator's
host (Claude Code, opencode, custom CLI) to surface a confirmation UI.
This is the agent-safety story's deployment surface — nothing runs without
the human seeing it.

### 4. Declarative authorization policies — language-enforced, not runtime-interpreted

This is the headline product differentiator. **Today's agent stacks are
limited to two modes:**

1. **"Approve each command"** — the user clicks yes/no on every shell call,
   network request, file write. Friction-heavy, fatigue-inducing, and the
   *runtime* (Claude Code, opencode, Cursor) decides what to surface — the
   model can construct commands that look innocuous but aren't.
2. **"Auto mode" / YOLO** — everything runs unprompted. No safety. This is
   how production databases get deleted.

Neither is a real authorization system. Both depend on the *agent host's
interpretation* of what the model emitted, which the model can game.

**This project's model: declarative policy files enforced by the language
itself.** The user (or operator, or CI pipeline) writes a policy. The
language verifier reads the policy at parse-time and rejects any agent
plan that violates it before execution. The runtime intercepts every
effecting call and second-line-checks. The model literally cannot emit
code that bypasses the policy — the rejection happens in the language
layer, not in a prompt-engineered wrapper.

```python
# policy_dev.star — checked into version control, reviewed in PRs
policy(
    name = "dev",
    description = "Local development; allow most things in project tree",

    fs = fs_policy(
        read_allow  = ["~/projects/myapp/**", "/tmp/**", "/etc/hosts"],
        write_allow = ["~/projects/myapp/**", "/tmp/**"],
        delete_allow = ["/tmp/**"],                  # never outside /tmp
        deny        = ["~/.aws/**", "~/.ssh/**",
                       "~/.config/credentials*",
                       "**/.env", "**/secrets/**"],   # belt-and-suspenders
    ),

    net = net_policy(
        http_get_allow  = ["api.github.com", "*.npmjs.org"],
        http_post_allow = [],                          # no POST
        deny_hosts      = ["169.254.169.254",          # cloud metadata
                           "10.0.0.0/8", "192.168.0.0/16",
                           "evil-exfil.example.com"],
        deny_ports      = [22, 25, 3306, 5432],         # no SSH/SMTP/DB
    ),

    subprocess = subprocess_policy(
        allow_commands = ["git", "npm", "pytest", "ruff"],
        deny_commands  = ["rm", "dd", "mkfs", "shred",
                          "curl", "wget", "nc", "ssh"],
        deny_flags = {"git": ["push --force", "reset --hard"]},
    ),

    db = db_policy(
        connections = {"localdev": {"read": True, "write": True}},
        deny_connections = ["prod_*", "staging_*"],
    ),

    confirm_per_call = ["fs.delete", "subprocess.exec"],
    pre_authorized_window = "5m",
)
```

```python
# policy_prod_readonly.star — for the same agent in a different env
policy(
    name = "prod_readonly",
    description = "Diagnose prod; cannot mutate anything",
    fs = fs_policy(read_allow = ["/var/log/myapp/**"], write_allow = [],
                   delete_allow = []),
    net = net_policy(http_get_allow = ["api.example.com"], http_post_allow = []),
    subprocess = subprocess_policy(allow_commands = []),  # no shell
    db = db_policy(connections = {"prod_replica": {"read": True, "write": False}}),
    confirm_per_call = [],   # nothing to confirm — nothing destructive is allowed
)
```

Properties of this design:

- **Language-enforced, not interpretation-dependent.** The verifier rejects
  forbidden code at parse time. The runtime second-checks at call time.
  The model can't talk its way around the policy via clever phrasing.
- **Composable.** Policies are typed values. `policy_prod_readonly` can be
  derived from `policy_dev` with a layered overlay; CI policy can extend
  user policy with stricter `deny_hosts`.
- **Environment-aware.** The host (Claude Code / opencode / custom CLI)
  selects the policy based on cwd, env vars, or explicit flag —
  *not* based on the model's prompt. So an agent running against `prod_*`
  literally cannot write, regardless of what its plan says.
- **Diff-able and reviewable.** Policy is text in version control. PRs
  to the policy file go through the same human review as code.
  "Why does the agent have access to write `~/.aws/`?" is answerable by
  reading a file, not by tracing runtime behavior.
- **Negative space is explicit.** Allowlists alone are insufficient — a
  `read_allow = ["~/projects/**"]` policy doesn't prevent a clever
  symlink attack. Belt-and-suspenders with explicit `deny` patterns
  (cloud-metadata IPs, SSH config, credentials files) closes the
  enumeration gaps.
- **Different policies for different environments.** The same agent code
  with the same model running against `dev`, `staging`, and `prod`
  policies behaves three different ways at the *language* level. No model
  re-prompting needed.
- **Confirm-per-call is a fallback, not the primary safety.** Most actions
  are pre-authorized by the policy and run silently with audit logging.
  Confirm prompts only fire for explicitly-marked categories (default:
  fs.delete, subprocess.exec). This avoids confirm-fatigue while keeping
  destructive actions human-gated.

This makes "agent deletes production database" structurally impossible
unless the human has signed off on a `prod_writable` policy *and* the
agent runs under that policy, which is a deliberate, auditable act —
not an oopsie from the model misreading a prompt.

### 6. Audit log

Every capability-gated action emits a structured event:

```json
{
  "ts": "2026-05-15T10:23:14.521Z",
  "task_id": "2026-05-15-sales-report",
  "step_idx": 2,
  "capability": "fs.read",
  "args": {"path": "/data/inputs/sales-2026-05.csv"},
  "granted_by": "user:marc",
  "result": "ok",
  "bytes_read": 18432,
}
```

Stored append-only. Tamper-evident if needed (signed log lines, Merkle chain).
This is the post-hoc accountability story — even if a bad outcome happens,
you can reconstruct exactly which agent did what when.

### 7. Executor stack

From NH10 + NH10b empirical findings:

- **Single-step delegation:** local 7B Python coder (`qwen2.5-coder:7b` or
  `deepseek-coder:6.7b`). Stream-C-shape tasks pass at high rate.
- **Multi-step composition:** capability-aware orchestrator decides per-step
  whether to route locally or escalate to cloud. Most steps go local; the
  hard composition shapes go cloud.
- **No mid-size local sweet spot for hard composition.** The 22B Python
  result (NH10b: 12/30, same as 7B) confirms: don't pay for 22B local in
  this band; either accept the easy-step subset locally or route to cloud.

Optional: ensemble fallback (codestral:22b + qwen-coder:7b oracle ceiling
18/30 vs 12/30 each) — adds ~6 tasks of capability for swap cost.

### 8. Orchestrator-executor calibration

NH16 refuted "stronger orchestrator → better outcome": Opus over-decomposed
and broke the limited executor. Lesson:

- **Pass the executor's capability profile to the orchestrator** in its
  system prompt: "decompose for an executor that is a 7B Python coder; use
  atomic single-verb steps; keep step descriptions under N tokens; do not
  ask for compound transforms in one step."
- **Bounded plan schema** — typed plan, capped step count, length-bounded
  descriptions. Prevents an orchestrator's natural verbosity from leaking
  through.

---

## What's new (vs Sigil)

Things the new project does that Sigil never did:

1. **Effect type annotations** parsed from `@effects([...])` docstrings.
2. **Capability tokens** as first-class typed objects in the language.
3. **Runtime interception** of all builtin calls with second-line check.
4. **Pre-execution verification** that declared effects ⊂ granted
   capabilities.
5. **Synchronous human-confirm hook** for destructive-tier capabilities.
6. **Structured audit log** with append-only / tamper-evident option.
7. **Capability-aware orchestrator system prompt** that calibrates plan
   shape to the executor's known competence.

Each of these is a piece Sigil's mammouth U09 thesis sketched and Sigil
never built.

---

## Milestones (4-week sketch)

Adapted from the memory's pre-existing 4-week plan, refined with empirical
findings:

### Week 1 — host + Starlark embedding
- Fork `starlark-rust`. Single-binary, embeddable.
- Define the capability-token type system (Rust traits + JSON schema for
  the per-task grants file).
- Port the MCP server from Sigil (`tool_run_task`, `tool_run_pipeline`)
  on top of the new binary.

### Week 2 — verifier + capability stdlib
- AST walker for `@effects([...])` annotations on Starlark functions.
- Capability stdlib: `fs.read`, `fs.write`, `fs.delete`, `net.http_get`,
  `net.http_post`, `subprocess.exec`, `db.read`, `db.write`, `env.read`,
  `time.now`, `random.bytes`. All host-registered, all capability-gated.
- Runtime interception layer: each registered builtin wraps a permission
  check + audit log emission.
- Confirmation hook protocol: synchronous callback when a
  `confirm_per_call` capability fires.

### Week 3 — methodology port + harness
- Port Stream C 30-task suite, retarget tasks to Starlark.
- Port A/B/C harness, swap Sigil executor for Starlark executor.
- Port Tier A name-validator (mostly trivial — Starlark builtins are a
  small whitelist).
- Port Tier B 3B step-judge (zero changes — already domain-agnostic).
- Run the same A/B/C suite with vanilla `qwen2.5-coder:7b` writing
  Starlark; baseline expected ~12-15/30 on multi-step (NH10 floor).

### Week 4 — safety story + 200-example fine-tune (decision)
- Build 5-10 example agent tasks that *would* destroy data without the
  capability layer (`rm -rf /data`, `psql -c "DROP TABLE"`, etc.).
  Demonstrate end-to-end: model emits the destructive code, verifier
  rejects, audit log records the attempted call. This is the demo.
- Decide whether to fine-tune. If vanilla Starlark + grants is at 27+/30
  on Stream C zero-shot, skip fine-tuning. If ~20/30, fine-tune on 200-500
  examples (negative training, ~10× smaller corpus than Sigil's).

---

## Risks and what to watch

- **Starlark dialect lock-in.** `starlark-rust` differs from Bazel-Starlark
  in subtle ways (no top-level for-loops without function wrapping, etc.).
  Models drift to Bazel-shaped Starlark or pure Python; the meet-halfway
  methodology should absorb the most common drifts at the parser level.
- **Capability granularity.** Too coarse → not safe enough; too fine →
  unusable. The right level is probably "what would I trust an intern to
  do" — file reads in a project dir, no writes outside `/tmp`, no deletes
  at all, no production DB writes, network reads to allowlisted hosts.
- **Confirm-fatigue.** If every action prompts the user, the user clicks
  through everything and the safety vanishes. Pre-authorized capabilities
  with explicit scope+expiry are the answer; only truly unknown actions
  prompt.
- **Verifier completeness.** Static analysis can miss dynamic dispatch.
  Belt-and-suspenders: every capability-gated builtin also checks at
  runtime. Static check catches design errors; runtime check catches
  cleverness.
- **Audit log integrity.** Append-only at minimum. For high-trust
  deployments, signed lines + Merkle chain + offsite mirror.
- **Cloud-orchestrator-shaped tax.** The orchestrator still needs to
  know the executor's capability profile. Free-text decompositions from
  Opus exceed what limited executors handle (NH16). The orchestration
  recipe is itself a first-class engineered object.

---

## Why this bet is stronger than Sigil's

| dimension | Sigil's bet | This project's bet |
|---|---|---|
| Pre-training tax | High (novel surface, 7 retrains, 2300 examples) | Low (Python subset, ≤500 examples) |
| Value claim | "AI-native language with token efficiency" | "Agents can't delete production DBs by construction" |
| Sharpness of value claim | Diffuse, hard to demo | Concrete, demoable in 5 minutes |
| What's load-bearing | Language design + corpus quality | Capability system + verifier + audit |
| Methodology reuse | Built it from scratch | Inherits validated tools |
| Executor calibration | Local 7B Sigil ceiling 7/30 multi-step | Local 7B Python ceiling 12/30 + cloud route for hard steps |
| Safety story | Sketched, never built | The headline product |
| Strategic robustness | Pre-training drift could obsolete Sigil | Python target inherits whatever pre-training corpora become |

Sigil produced exactly the empirical answers needed to direct this bet:
language proximity gains ~5/30 at 7B, scale doesn't help mid-size, the
methodology transfers, the safety story is the unbuilt valuable piece.

The next project starts where Sigil ended — with all the methodology
proven and a sharper goal.

---

## Open design questions to resolve in week 1

1. Does `starlark-rust` support custom decorators / annotations on
   functions, or do we parse `@effects` from docstrings? (Affects
   syntax cleanliness.)
2. Is the capability token a runtime-only object, or does Starlark's
   type system see it? (Affects how strict the static check can be.)
3. Confirmation hook protocol: how do we call back to the orchestrator
   (Claude Code / opencode / custom CLI) synchronously? Probably
   stdin/stdout JSON-RPC.
4. Audit log format: structured logs, OpenTelemetry, custom? (Affects
   integration with existing observability stacks.)
5. How do we expose the capability-token grant file to the model? It
   must be visible in the system prompt so the model knows what's
   allowed before generating, otherwise it'll keep emitting code that
   gets rejected.

---

*Started 2026-05-04. The Sigil retrospective lives at
`papers/SIGIL_RESULT.md` in the sibling Sigil repo. Methodology
artifacts to port live in `tools/agent_harness/` and `benchmark/`
in that repo.*
