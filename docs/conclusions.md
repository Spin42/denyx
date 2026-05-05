# Post-Sigil — Lessons and Corollary Hypotheses

A live document. The conclusions below emerged from the Sigil project but
are not Sigil-specific; they are inputs for the next project on
**agent-safe local tooling**.

> **Status (2026-05-04): Sigil experiment closed.**
>
> - Project retrospective: [`SIGIL_RESULT.md`](../sigil/papers/SIGIL_RESULT.md) (sibling repo)
> - Next-project plan: [`./project-plan.md`](./project-plan.md) — Starlark-dialect host with capability-typed effects, runtime verifier, and audit logging. Designed to make "agent deletes production database" structurally impossible.
> - This file remains the strategic-conclusions reference; the
>   project-plan.md is the actionable next-steps doc.

Origin: refined during the 2026-05-04 NH2 Tier B work, where the lift
estimator made the multi-step ceiling concrete; subsequent NH6 / NH10 /
NH10b / NH16 results closed the strategic question.

---

## Part I — Headline conclusions Sigil validated

### C1. The pre-training bias is real but not the dominant constraint at small model size; scale is

Sigil reached single-step parity (29/30 vs Sonnet) only after 7 retrains,
a 2300-entry corpus, a 200-line static-name validator, a 3B step-judge,
multiple ensembles, and ~6 months of methodology. A baseline qwen2.5-coder:7b
produces shape-correct Starlark on 37% of the same task class with zero
fine-tuning, just a system prompt. The gap is not a measure of Starlark's
quality — it is a measure of how much *any* novel surface language has to
pay to reach the model's distribution.

**NH10 + NH10b (Python-as-control + larger Python executor on the
multi-step harness, 2026-05-04) measure language vs scale
contributions.**

Same harness, same orchestration. Path C scores by per-step executor:

| executor | parameters | language | Path C |
|---|---|---|---|
| qwen-sigil-v7 | 7B | Sigil (fine-tuned) | 7/30 |
| qwen2.5-coder | 7B | Python (no FT) | 12/30 |
| codestral | 22B | Python (no FT) | 12/30 |
| Sonnet | (cloud) | Python | 26/30 |

**Two findings:**

  - **Language proximity gains +5 tasks at fixed 7B size** (Sigil → Python
    on the same parameter count and the same orchestration).
  - **Scaling 7B → 22B locally gains zero on this benchmark.** Tasks
    shuffle (codestral excels at structural parsing; qwen-coder excels
    at regex), but the total stays at 12/30. The scale axis is
    *non-monotonic in the 7B-22B band*; a much larger jump (70B+ or
    cloud) is needed to close to Sonnet's 26/30.

So **pre-training-language proximity is real and cheap; mid-size scale
is real but does NOT come in gradual steps.** There's a capability
cliff between mid-size local Python and cloud Python that no
deployable mid-size local model bridges on this benchmark.

This refines C1's framing: the calculus is *not* "spend on a Python
subset and you close most of the gap with a small local model." It is:

  - At 7B body size: Python ≈ 46% of cloud, Sigil ≈ 27% of cloud.
    The +19% from language is the cheapest move, but doesn't get you
    near cloud parity.
  - At 22B body size: Python ≈ 46% of cloud (same as 7B). No further
    gain from scale alone.
  - The remaining ~54% gap to cloud is bound by capability the
    7B-22B band does not have.

For the next project, this rules out the "mid-size local sweet spot"
deployment story. The viable options become:

  1. **Cloud orchestrator + cloud executor** — what Path A already is.
     The "savings" claim collapses unless the executor is dramatically
     cheaper than the cloud one.
  2. **Cloud orchestrator + small/mid local executor** — accept ~12/30
     on hard composition, route easy single-steps locally (Stream C
     29/30 is real). This is the realistic deployment story.
  3. **Cloud orchestrator + 70B+ local executor** — exists but costly
     to run, and the unit economics may not beat cloud-cloud.
  4. **Capability-aware routing** (CH14): the orchestrator decides
     per-step whether to route locally or escalate. Most steps can go
     local; the hard ones go cloud. Likely the right deployment shape.

### C2. Validator / judge / RAG infrastructure is the durable asset, not the language

Of everything we built for Sigil, the language-portable parts are:
- The static name validator (Tier A — language-agnostic shape)
- The principles-based 3B step-judge (Tier B — language-agnostic semantics)
- The MCP harness (Stream A/B/C — language-agnostic transport)
- The cross-base ensemble pattern (fresh prompt + temp=0)
- The corpus generation methodology (sequential, validated, pristine)
- The "meet the model halfway" methodology

The language-specific parts (paren balancer, fence stripping, smart-argv,
language-header detection, the OCaml interpreter, the 2300-entry corpus)
become unnecessary once you stop fighting the model's syntactic intuitions.

### C3. Multi-step composition is a CODE-GEN problem, not an orchestration problem (PROVEN 2026-05-04)

NH6 result (Sonnet-as-step-executor diagnostic) was decisive. Replacing
*only* the per-step executor in the chained Path C pipeline — keeping
Sonnet's decomposition, the same harness, same shape annotations,
same step-judge — lifted Path C from 7/30 to **26/30**. That equals
Path A's single-shot performance and proves the chained recipe is not
lossy.

The gap to date in every multi-step result was exactly the local
executor's per-step Sigil generation ability under
Sonnet-decomposed step shapes. Every prior "Path C = X/30" claim was a
local-executor capability statement, not an orchestration limit.

**This refines C1's framing:** the pre-training tax wasn't just on
single-step Sigil generation; it manifests at every per-step
generation in a chain. The orchestrator decomposes assuming a
Sonnet-quality executor. When the executor is a 7B model trained away
from Python, each per-step description is a fresh capability mismatch.

**Implications for the next project:**

  - **The orchestration recipe is not where the leverage is.** Stop
    iterating on prompt formats, decomposition strategies, plan
    schemas. The recipe is fine.
  - **Executor capability per step is the load-bearing variable.** A
    Python-subset executor that's on-distribution for whatever step
    Sonnet writes will close most of the 19-task gap because the
    orchestrator's step shape assumes Python-subset capability anyway.
  - **The hybrid stack design is upside-down for limited executors.**
    Sonnet writes step descriptions calibrated to its own
    capability; that's the wrong calibration for a 7B local model.
    Either: (a) calibrate the orchestrator to the executor by passing
    the executor's capability profile in the system prompt, or (b)
    constrain the orchestrator output to a typed plan with bounded
    step complexity (CH11), or (c) accept that hybrid stacks need
    cloud-shaped executors.

The first two are open design problems for the next project.

---

## Part II — Strategic conclusions for language design in the AI age

### S1. "AI-native language" is the wrong frame

The frame that worked in 2023-2024 — design a token-efficient,
deterministic, AI-friendly language and fine-tune small models on it —
no longer pays for itself. The bring-up cost (corpus, retrains,
validators, harnesses) is so large that you arrive at deployment-readiness
years after a Python-subset competitor would have.

The right frame is "AI-fluent capability layer on top of a language the
model already speaks." Restricted Python (Starlark, RestrictedPython,
Skylark, Pyret), restricted JS, embeddable WASM are all instances of
this pattern.

### S2. The new design metric is "is it on the model's manifold?"

Traditional language-design metrics — ergonomics, performance, type
soundness, expressiveness — still matter, but a new one now dominates:
how close is this language to the distribution the model was trained on?
A language that scores well on ergonomics but poorly on
manifold-proximity will lose to a syntactically-uglier competitor that
the model writes correctly out of the box.

### S3. Convergence is in language-designers' incentives, not in the model

Larger models speak more languages well, not fewer. What converges is
the *economics of language design*: shipping a new surface language now
incurs a "model-onboarding tax" that is roughly proportional to its
syntactic distance from Python (today's local maximum in pre-training).
Teams designing new languages will increasingly cluster near the
manifold to dodge that tax.

This will produce many more Python-subset languages. It will not
eliminate niche languages (Lean, Coq, Verilog, OCaml stay in their
niches) but will make new general-purpose languages outside the manifold
extinction-vulnerable.

### S4. Pre-training lock-in is contingent

Python won the pre-training center of gravity because of the 2015-2020
data-science crawl. The language landscape is being shaped by which
languages are over-represented in the training corpus, which is itself
shaped by which communities published openly during the formative years.
This is not destiny — the next pre-training center could shift if a
different language becomes the dominant *new* code substrate. Designing
for the current center is a path-dependent bet.

### S5. The interesting unsolved design problem

There exist properties highly desirable for AI-safe code that the model
does not natively express well: capability tokens, effect rows,
structural recursion guarantees, deterministic IO boundaries. There
exist Python features that the model loves to write but are dangerous in
agent contexts: unrestricted `import`, mutable comprehension state,
chained comparisons (Starlark forbids them), implicit globals.

The unsolved design problem is **finding properties that are good for
AI safety AND expressible inside Python's syntactic envelope.**
Bazel/Starlark proved one corner (no I/O, bounded execution).
Capability typing is the obvious next corner. Effect tracking via
docstring annotations (read by a verifier, not the language) is a third.

---

## Part III — Methodology that transfers to the next project

These are the techniques that worked for Sigil and will keep working
regardless of language target:

- **Meet the model halfway.** When the model misuses a construct
  consistently, change the language layer to absorb the misuse, not the
  prompt. Aliases, smart input parsing, default flags, fence stripping.
- **Validator-in-loop with surgical hints.** A static validator that
  catches known failure shapes (wrong language emission, unknown names,
  hallucinated builtins) and produces a targeted retry hint converts
  ~15-25% of attempts.
- **Principles-based judging.** When using a small model as a judge,
  teach it generic reasoning principles (numeric limits, ordering,
  transformation-happened, filtering-applied) with synthetic
  domain-agnostic examples. Anchoring to the test set's specific tasks
  causes overfitting and harms OOD generalization.
- **Hybrid deterministic + model judging.** Where you can mechanically
  verify (line counts, monotonicity, header presence), do so first.
  Reserve the model for the genuinely fuzzy cases.
- **Cross-base ensemble with fresh prompt + temp=0 on the alternative.**
  When falling back from a primary model, do not carry validator hints
  forward — they pollute the alternative model's natural reach. A
  fresh prompt at deterministic temperature is the right contract.
- **Sequential corpus generation, not parallel.** Parallel synthesis
  produces correlated examples that don't teach diverse shapes.
- **Interpreter loudness is a feature.** Silent failures rob the model
  of the feedback signal it needs to self-correct. Default warnings to
  ON and provide a per-test opt-out.
- **Empty-stdout retry as a separate signal from semantic-judge retry.**
  These are different failure modes with different fix shapes.
- **Generate K, pick best by deterministic features.** Untested for
  Sigil but well-supported in the literature. Likely cheap lift.

---

## Part IV — Corollary hypotheses for the next project

These are open hypotheses that follow from the conclusions above. Each
is a candidate experiment for whatever language target the next project
adopts.

### CH1. The model-onboarding tax is quantifiable

We should be able to estimate the cost of bringing a new language to
deployment-readiness as a function of its distance from Python on a
small set of axes: token-level edit distance on idiomatic snippets,
syntactic novelty ratio (parse-tree shapes Python doesn't have),
semantic divergence (constructs that look Python but mean something
different). A first-cut formula calibrated against Sigil (fully novel),
Starlark (subset), Mojo (superset), gives a rough budget for any future
language choice.

### CH2. Validator infrastructure should be packaged as a language-agnostic toolkit

The judge, RAG, harness, and methodology survive any language pivot.
Concrete next step: extract the Sigil-side artefacts (`sigil_step_judge.py`,
`sigil_name_validator.py`, `judge_replay_all.py`, `sigil_mcp_server.py`,
the harness scoring loop) into a small library that any local-LLM
tooling project can consume. Name it independently of Sigil.

### CH3. Capability-typed Python subset is the deployment-ready pattern

Bazel/Starlark, RestrictedPython, Mojo, Pyret all converge on
restricted-Python-with-extras. The next valuable contribution is not
another such language but a *standard* for capability-typed effect
tracking on top of any of them. Specifically: `@effects(["read_file",
"http_get"])` decorators, AST-walker verifier, runtime interceptor that
checks against an embedder-supplied whitelist. ~3-5 days from scratch
in Rust over starlark-rs.

### CH4. Convergence to canonical subsets, not to a single subset

We expect 2-4 canonical Python-subset niches to dominate by surface
area: hermetic config (Starlark already won), agent/tool runtime
(open), ML-shape (Mojo competing), domain-specific (varies). The
strategically valuable position is the *agent/tool* runtime niche,
which has no clear winner and is exactly the niche Sigil's
infrastructure was pointed at.

### CH5. The best model for AI-safe tooling is a small fine-tune over a strong Python coder

Not a custom-language model. Not a frontier general model. The sweet
spot is qwen2.5-coder:7b or similar with a 200-500 example fine-tune
focused on the safety-conscious patterns that the language layer can't
enforce alone (capability acquisition order, effect declarations,
defensive parsing). Cheap, local, deployable, updateable. This is the
quantitative version of S1.

### CH6. Multi-step composition needs orchestration-side moves, not language-side moves

The Sigil multi-step plateau (Path C 6/30, stuck since Phase 21) did
not yield to any language-side intervention. Likely orchestration moves
worth testing on the next project's harness:
- Typed cross-step contracts (each step declares input/output types)
- Persistent named state (closer to a REPL than a Unix pipe)
- Input-shape annotation injected by the orchestrator
- Generate-K-pick-best at each step
- Step-level context augmentation (overall goal + downstream consumer)

### CH7. AI safety design metrics differ from human ergonomics metrics

Some Python features (chained comparisons, mutable comprehensions,
unrestricted import, regex) are great for humans and dangerous for AI
use. Some non-Python ideas (effect rows, capability tokens, structural
recursion) are great for AI safety but the model doesn't know them.
The unsolved design space is the intersection: properties good for
safety AND expressible inside the model's manifold. Each new entry in
this intersection is a defensible product.

### CH8. The pre-training center of gravity is a tracked variable, not a constant

Python's dominance in pre-training was contingent on 2015-2020 crawl
composition. If a different language becomes the dominant *new* code
substrate (Mojo for ML, Rust for systems-shaped agents, something
unborn), the optimal language-design target shifts. Worth tracking:
github-archive composition trends per year, what languages new repos
are being created in, what the next-generation pre-training corpus mix
looks like. A language built on a 2026 assumption that gets deployed in
2030 may be aiming at a stale center.

### CH9. The orchestration ceiling is unmeasured (high-priority diagnostic)

Until NH6 (Sonnet-as-executor diagnostic) is run, we do not actually
know whether the multi-step ceiling is code-gen or orchestration.
~30 minutes of work resolves this and changes which of CH1-CH8 are
worth doing. Run it before designing the next project's harness.

### CH10. Soft-pass scoring may be hiding real lift

Path A (Sonnet-Python) scores 26/30 partly because Python tolerates
whitespace. Our `expected_shape` check is byte-exact. A normalized
comparator (strip trailing whitespace, collapse internal whitespace,
optionally ignore line-order when no sort is asked) might show the
local ensemble already reaches 8-12/30 by a defensible definition.
Worth measuring before drawing strong conclusions about local-vs-cloud
gaps. ~1 hour of work.

### CH14. Orchestrator-executor capability calibration is a first-class hybrid-stack design variable

NH6 + NH16 together show:

  - A weaker local executor cannot keep up with a strong orchestrator's
    decomposition (NH16: Opus over-decomposed, broke the executor).
  - With a strong executor (Sonnet), the same orchestration recipe
    runs cleanly (NH6: Path C 26/30, parity with single-shot).

The implication: the orchestrator must "know" how capable the executor
is and shape its plans accordingly. In Sigil's current harness, Sonnet
writes step descriptions calibrated to its own capability — which is
the wrong calibration for a 7B local model.

For the next project, options to test:

  - **Capability-aware orchestrator system prompt**: pass the
    executor's capability profile (model size, supported builtins, known
    failure modes) into Sonnet's decomposition system prompt. "Decompose
    for an executor that is a 7B model fine-tuned on a Python subset
    with these limitations: ..."
  - **Bounded plan schema**: typed plan structure (CH11) with hard caps
    on step description length, complexity score, builtin variety per
    step. Forces any orchestrator's plans into the executor-tractable
    region.
  - **Plan-quality verifier loop**: small local model judges whether
    the orchestrator's plan is executable by the small executor before
    running, retries with a "simpler please" hint if not.

Each of these is testable in isolation. The combined design is what a
deployment-ready hybrid stack actually looks like — orchestrator-side
software, not a single prompt.

### CH11. Empty-pipeline failures are dominated by input-shape misperception, not by missing capability

Diagnostic finding from 2026-05-04 NH8 work: the local 7B Sigil model
infers `$0`'s shape from the *step description's verbs*, not from the
actual upstream stdout it receives. When the description says "count
words", the model assumes space-separation and writes `(split $0 " ")`,
even when `$0` is line-separated. This is the dominant failure mode for
the 19/23 Path C empty-pipeline failures.

This generalizes beyond Sigil: any chained LLM-orchestration pipeline
where the executor sees only the immediate step description and a raw
stdin will have this problem. The orchestrator inherently knows the
shape contract between steps (it's part of the plan); the executor
needs to be told.

**For the next project, treat shape annotation as a first-class
property of the inter-step contract, not a prompt-engineering
afterthought.** Likely shapes:
  - Each step's plan declares `input_type` and `output_type` as a
    structural schema (line-separated rows of T, single JSON, etc.).
  - The executor receives both the plan-step *and* the type context.
  - Type mismatches between adjacent steps trigger orchestrator-side
    retry with a corrected shape, not blind generation.

The Sigil NH8 attempt to bolt shape annotation onto Sonnet's free-text
JSON revealed that prompt-engineering the annotation also reshapes
Sonnet's planning behavior — the *form* of the annotation entangles
with the *quantity* of steps Sonnet emits. Cleaner architecture: a
typed plan structure, not a textual annotation on top of an existing
JSON shape.

### CH13. Orchestrator quality is NOT monotonically helpful — there's a capability-matching sweet spot

Tested directly in Sigil (NH16, 2026-05-04): swapping the orchestrator
from Sonnet to Opus while keeping the local executor identical
*regressed* both Path B (5/30 → 1/30) and Path C (7/30 → 4/30) at 6.6×
the cloud cost. Stronger orchestrator actively hurt.

The mechanism: free-text decompositions inherit the orchestrator's
style. Opus is more elaborate, more decomposing, more verbose — and the
7B executor cannot track its longer step descriptions or thread its
finer-grained step plans without dropping output. Average n_steps went
from 1.70 → 2.03; empty-pipeline failures rose 21 → 23.

This is analogous to the **teacher-student gap** in ML knowledge
distillation: a teacher too far above the student's capability
distribution becomes unhelpful or counterproductive. The same applies
to LLM orchestration: a planner whose natural verbosity exceeds what
the executor can track is the wrong planner regardless of its raw
intelligence.

**Implications for the next project's hybrid stack:**

  - Budget orchestrator capability to *match* the executor, not to
    exceed it. Don't assume "bigger orchestrator → better outcome."
  - Worth measuring: at what orchestrator capability does the
    executor's failure rate plateau? That's the right size to budget for.
  - If you do want a stronger orchestrator, *constrain its output
    structurally* (typed plan schema, capped step count, length-bounded
    descriptions). The structural constraint pulls a stronger
    orchestrator's style back toward what the executor can handle.
  - Free-text plan-as-prompt is the wrong abstraction for hybrid
    stacks. The orchestration recipe should be a typed object that the
    orchestrator fills in, not a free-text JSON it generates.

**For the next project, the orchestration recipe is itself a
first-class object that should be designed, versioned, and evaluated
independently from the executor.** Sigil's harness conflated them —
`path_c_chained_hybrid` is a single function with an orchestration
prompt baked in. The next project should expose the orchestration
recipe as a swappable module so different orchestrator/executor
combinations can be A/B-ed without code edits, and so the recipe can
be optimized independently (potentially via fine-tuning a smaller
orchestrator specifically for plan-shape rather than general-purpose
reasoning).

### CH12. The "meet halfway" methodology has a discoverable trigger pattern

When a fine-tuned model produces non-target-language idioms under
composition pressure (qwen-sigil-v7 drifting to Clojure `(let [x v]...)`
syntax once given a correct shape hint), the cheapest fix is parser-level
absorption of the alternate form. This is the same pattern as Sigil's
smart-argv, parse_float/to_int aliases, and PCRE multiline default —
move pre-training reflexes into the language layer rather than fighting
them at prompt or training time.

Concretely: if the next project ships a Python-subset surface with a
restricted runtime, the parser should *intentionally* accept harmless
Python-isms (e.g., `for ... else:` blocks, unpacking expressions, simple
comprehensions over immutable accumulators) even if the formal Starlark
spec rejects them. Each absorbed pre-training reflex is a saved retry
and a fewer corpus example needed.

---

## Part V — What stays open after Sigil

These are questions the Sigil work raised but did not resolve. They
should bias the next project's first sprint:

- **Is the multi-step ceiling code-gen or orchestration?** (NH6, ~30 min)
- **Does soft-pass scoring change the headline gap?** (CH10, ~1 hour)
- **Does the same model produce Python multi-step at higher accuracy
  than Sigil multi-step?** (NH10 + CH5; ~1 day) — the answer determines
  whether the entire Sigil thesis was Sigil-specific or
  composition-general.
- **What is the lift of N-of-K sampling at step level?** (NH7; ~1 day)
- **Does typed cross-step state lift the orchestration ceiling?**
  (NH12; ~2 days)

---

## Part VI — Document conventions

- **Conclusions (C1-Cn, S1-Sn)** are claims supported by Sigil's evidence.
  Refine them only when contradicting evidence appears.
- **Corollary hypotheses (CH1-CHn)** are open questions for the next
  project. Mark as resolved (with verdict + evidence link) when answered;
  do not delete unanswered ones.
- **Open questions (Part V)** are the highest-priority unresolved items
  inherited from Sigil. They should land in the next project's first
  sprint plan.

This document is intended as a living strategic reference. Add new
conclusions as evidence accumulates; promote corollary hypotheses to
conclusions when they're tested; demote conclusions to "previously
believed" if they fail under new evidence.
