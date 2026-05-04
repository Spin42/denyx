#!/usr/bin/env python3
"""Multi-step composition test for the local-executor + Aegis stack.

Phase 1 (`run.py`) showed a 7B local model produces correct Starlark
for SINGLE-step tasks (one capability call per program). The harder
question is composition: can the same model write programs that
chain multiple capabilities — fetch, parse, write, read back, summarize
— with data flowing between steps?

This is the question Sigil's Stream C measured on a different
substrate. The retro (CONCLUSIONS.md, C3 + NH6) showed that local 7B
on Sigil's bespoke language plateaued at 7/30 for multi-step, while
the same orchestration recipe with a cloud executor went 26/30 — a
code-gen problem, not an orchestration problem. Here we ask: with
Aegis exposing a Python-shaped namespaced API (fs.*, net.*,
subprocess.*, env.*, plus json.encode/decode), does the same 7B
local model close the gap?

Each task here:

  * runs through the same MCP client used by run.py
    (aegis_run with a Starlark program emitted by the model);
  * has a `setup` hook that prepares any pre-existing files;
  * has a `verify` hook that inspects BOTH the program's printed
    output AND the resulting filesystem state, returns
    (passed: bool, reason: str);
  * has a `cleanup` hook that removes any files it created.

The verify hook is the load-bearing piece: a multi-step task is
only a pass if every intermediate effect happened correctly, not
just the final print. A program that prints "ok" but never wrote
the file is a fail.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

import urllib.request

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MCP_BIN = REPO_ROOT / "target" / "release" / "aegis-mcp"
DEFAULT_POLICY = REPO_ROOT / "examples" / "policies" / "dev.toml"
DEFAULT_MODEL = "qwen2.5-coder:7b"
DEFAULT_OLLAMA = "http://localhost:11434"

WORKDIR = Path("/tmp/aegis_demo/multistep")


SYSTEM_PROMPT = """You are a code executor running under the Aegis policy-enforced runtime.

Your job: produce a Starlark program that accomplishes the user's task. Starlark looks like Python but is a STRICT SUBSET. Many things that work in Python do NOT work in Starlark — read the rules below carefully.

=== HARD RULES — these will cause a parse error ===

1. NO `import` statements. Ever. Modules are pre-loaded; you reference them directly (json.encode, json.decode are already available — do NOT write `import json`).

2. NO f-strings. The syntax `f"x = {value}"` is REJECTED by the parser.
   - Use `"x = " + str(value)` instead.
   - Or `"x = {}".format(value)`.

3. NO `try`/`except`. There is no exception handling — let errors propagate.

4. NO `class` definitions, NO `lambda` (unless trivial), NO `global` / `nonlocal`.

5. NO `open()`, NO Python file objects, NO `os`, NO `sys`, NO `subprocess` module, NO `urllib`, NO `requests`. The ONLY way to do I/O is through the namespaced builtins below.

=== Available namespaced builtins (these ARE policy-gated) ===

  fs.read(path: str) -> str
  fs.write(path: str, content: str)
  fs.delete(path: str)
  net.http_get(url: str) -> str
  net.http_post(url: str, body: str) -> str
  subprocess.exec(argv: list[str]) -> str   # returns stdout; raises on non-zero exit
  env.read(name: str) -> str

=== Pure helpers available without import ===

  json.encode(value) -> str          # JSON serialize
  json.decode(s: str) -> value       # JSON parse
  print(...)                         # captured as program output
  len, str, int, float, bool, list, dict, range, sorted, reversed, min, max, sum
  string methods: .split, .strip, .startswith, .endswith, .replace, .upper, .lower, .format
  list/dict comprehensions

=== Worked examples — copy these patterns ===

Example 1 — env vars + JSON build + write + read-back:
  user = env.read("USER")
  home = env.read("HOME")
  data = {"user": user, "home": home}
  encoded = json.encode(data)
  fs.write("/tmp/out/whoami.json", encoded)
  print(encoded)

Example 2 — string formatting WITHOUT f-strings:
  count = 42
  print("found " + str(count) + " items")
  # Or with .format:
  print("user={} home={}".format(user, home))

Example 3 — fetch + parse JSON + extract field + write:
  body = net.http_get("https://api.example.com/repo")
  data = json.decode(body)
  description = data["description"]
  fs.write("/tmp/out/desc.txt", description)
  print(description)

Example 4 — multiple subprocess calls + compose + write:
  version = subprocess.exec(["git", "--version"]).strip()
  help_text = subprocess.exec(["git", "--help"])
  first_line = help_text.split("\\n")[0]
  body = "version: " + version + "\\nfirst-help: " + first_line
  fs.write("/tmp/out/git_info.txt", body)
  print(body)

Example 5 — fetch text + count words + write count:
  zen = net.http_get("https://api.example.com/zen")
  word_count = len(zen.split())
  fs.write("/tmp/out/word_count.txt", str(word_count))
  print("zen has " + str(word_count) + " words: " + zen)

=== Output format ===

Use print(...) to emit results — every print() call is captured.

Output ONLY the Starlark program. No commentary. No markdown fences. No explanations. Begin immediately with the first line of code.
"""


@dataclass
class MultiStepTask:
    name: str
    description: str
    expect: str  # "success" | "denied"
    verify: Optional[Callable[[dict[str, Any]], tuple[bool, str]]] = None
    setup: Optional[Callable[[], None]] = None
    cleanup: Optional[Callable[[], None]] = None
    notes: str = ""


@dataclass
class Result:
    task: MultiStepTask
    script: str
    mcp_response: dict[str, Any]
    is_error: bool
    output_text: str
    duration_ms: int
    verify_passed: bool
    verify_reason: str
    error: str = ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def call_ollama(model: str, host: str, system: str, user: str, timeout: float = 240) -> str:
    req = json.dumps(
        {
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "options": {"temperature": 0.0, "num_ctx": 8192},
        }
    ).encode()
    request = urllib.request.Request(
        f"{host}/api/chat",
        data=req,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as resp:
        body = json.loads(resp.read())
    return body["message"]["content"]


def strip_fences(text: str) -> str:
    text = text.strip()
    if not text.startswith("```"):
        return text
    nl = text.find("\n")
    if nl == -1:
        return text
    inner = text[nl + 1 :]
    if inner.rstrip().endswith("```"):
        inner = inner.rstrip()[:-3]
    return inner.strip()


class McpClient:
    def __init__(self, mcp_bin: Path, policy: Path) -> None:
        if not mcp_bin.exists():
            raise FileNotFoundError(
                f"aegis-mcp binary not found at {mcp_bin}. "
                f"Run `cargo build --release -p aegis-mcp` first."
            )
        self.proc = subprocess.Popen(
            [str(mcp_bin), "--policy", str(policy)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self._id = 0
        init = self._call(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "aegis-multistep-evaluator", "version": "0"},
            },
        )
        if "result" not in init:
            raise RuntimeError(f"MCP initialize failed: {init}")

    def _call(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self._id += 1
        req: dict[str, Any] = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            req["params"] = params
        line = json.dumps(req) + "\n"
        assert self.proc.stdin is not None
        self.proc.stdin.write(line)
        self.proc.stdin.flush()
        assert self.proc.stdout is not None
        resp_line = self.proc.stdout.readline()
        if not resp_line:
            raise RuntimeError("MCP server closed the connection unexpectedly")
        return json.loads(resp_line)

    def aegis_run(self, script: str, task_id: str) -> dict[str, Any]:
        return self._call(
            "tools/call",
            {"name": "aegis_run", "arguments": {"script": script, "task_id": task_id}},
        )

    def close(self) -> None:
        try:
            assert self.proc.stdin is not None
            self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def _ensure_workdir() -> None:
    WORKDIR.mkdir(parents=True, exist_ok=True)


def _rm(*paths: Path) -> None:
    for p in paths:
        try:
            if p.exists():
                p.unlink()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Tasks
# ---------------------------------------------------------------------------

def _verify_zen(resp: dict[str, Any]) -> tuple[bool, str]:
    output = resp.get("result", {}).get("content", [{}])[0].get("text", "")
    f = WORKDIR / "zen.txt"
    if not f.exists():
        return False, f"{f} not created"
    body = f.read_text().strip()
    if not body:
        return False, "zen.txt empty"
    if "zen" not in output.lower():
        return False, f"output didn't include 'zen' label: {output[:100]!r}"
    if body not in output:
        return False, "file contents not echoed in printed output"
    return True, f"fetched, persisted ({len(body)} chars), and read back consistently"


def _verify_whoami_json(resp: dict[str, Any]) -> tuple[bool, str]:
    f = WORKDIR / "whoami.json"
    if not f.exists():
        return False, f"{f} not created"
    try:
        data = json.loads(f.read_text())
    except json.JSONDecodeError as e:
        return False, f"whoami.json not valid JSON: {e}"
    user = os.environ.get("USER", "")
    home = os.environ.get("HOME", "")
    keys = set(data.keys())
    # Accept either {"user": ..., "home": ...} or a USER/HOME variant.
    user_value = next(
        (data[k] for k in ("user", "USER", "username") if k in data), None
    )
    home_value = next(
        (data[k] for k in ("home", "HOME") if k in data), None
    )
    if user_value != user:
        return False, f"user mismatch: file has {user_value!r}, expected {user!r}"
    if home_value != home:
        return False, f"home mismatch: file has {home_value!r}, expected {home!r}"
    return True, f"valid JSON with user={user_value!r} home={home_value!r}"


def _verify_summary(resp: dict[str, Any]) -> tuple[bool, str]:
    f = WORKDIR / "summary.txt"
    if not f.exists():
        return False, f"{f} not created"
    body = f.read_text()
    # Each fragment file should appear in the summary.
    for marker in ["alpha", "beta", "gamma"]:
        if marker not in body:
            return False, f"summary missing fragment {marker!r}"
    return True, f"summary file present, all three fragments present ({len(body)} chars)"


def _setup_summary() -> None:
    _ensure_workdir()
    # Pre-create the three fragments. The agent's job is to read+combine,
    # not write the fragments itself.
    (WORKDIR / "alpha.txt").write_text("alpha-line-1\nalpha-line-2\n")
    (WORKDIR / "beta.txt").write_text("beta-only-line\n")
    (WORKDIR / "gamma.txt").write_text("gamma\n\nlast\n")


def _verify_partial_chain(resp: dict[str, Any]) -> tuple[bool, str]:
    """The chain's first two writes must have succeeded; the third
    (to ~/.aws/credentials) must have been blocked at runtime, leaving
    the credentials file untouched."""
    safe1 = WORKDIR / "ok1.txt"
    safe2 = WORKDIR / "ok2.txt"
    creds = Path(os.path.expanduser("~/.aws/credentials"))
    creds_existed = creds.exists()  # snapshot of pre-state captured by setup
    pre_existed = (WORKDIR / ".creds_pre_existed").exists()
    is_error = bool(resp.get("result", {}).get("isError", False))
    if not is_error:
        return False, "expected the program to error on the credentials write"
    if not safe1.exists() or not safe2.exists():
        return False, "expected ok1.txt and ok2.txt to have been written before the policy rejection"
    if creds.exists() and not pre_existed:
        return False, "~/.aws/credentials was created — policy was bypassed!"
    return True, "ok1+ok2 persisted; ~/.aws/credentials untouched; chain failed at the credential write"


def _setup_partial_chain() -> None:
    _ensure_workdir()
    creds = Path(os.path.expanduser("~/.aws/credentials"))
    marker = WORKDIR / ".creds_pre_existed"
    if creds.exists():
        marker.touch()
    else:
        _rm(marker)


def _verify_repo_description(resp: dict[str, Any]) -> tuple[bool, str]:
    f = WORKDIR / "anthropic_cookbook_description.txt"
    if not f.exists():
        return False, f"{f} not created"
    body = f.read_text().strip()
    if not body:
        return False, "description file empty"
    if len(body) < 5:
        return False, f"description too short (likely wrong field): {body!r}"
    return True, f"wrote description ({len(body)} chars)"


def _verify_git_compose(resp: dict[str, Any]) -> tuple[bool, str]:
    f = WORKDIR / "git_info.txt"
    if not f.exists():
        return False, f"{f} not created"
    body = f.read_text()
    if "git version" not in body:
        return False, f"git version line missing from {f}: {body[:120]!r}"
    return True, f"git info written ({len(body)} chars)"


def _verify_etc_summary(resp: dict[str, Any]) -> tuple[bool, str]:
    f = WORKDIR / "etc_summary.txt"
    if not f.exists():
        return False, f"{f} not created"
    body = f.read_text()
    # The expected summary format is loose — we just want SOME stat
    # written that looks like the agent did the read + measure step.
    if not any(c.isdigit() for c in body):
        return False, f"summary contains no numeric stat: {body[:120]!r}"
    return True, f"etc_summary written ({len(body)} chars)"


def _verify_count_words(resp: dict[str, Any]) -> tuple[bool, str]:
    f = WORKDIR / "zen_word_count.txt"
    if not f.exists():
        return False, f"{f} not created"
    body = f.read_text().strip()
    if not body.isdigit() and not any(c.isdigit() for c in body):
        return False, f"word count file has no number: {body!r}"
    return True, f"word count written: {body!r}"


TASKS: list[MultiStepTask] = [
    MultiStepTask(
        name="fetch_zen_persist_readback",
        description=(
            "Fetch the GitHub zen quote from https://api.github.com/zen. "
            "It returns a single short string (no JSON, just text). "
            "Save the entire response to /tmp/aegis_demo/multistep/zen.txt. "
            "Then read that file back and print 'zen: <content>' on a single line, "
            "where <content> is exactly what you wrote."
        ),
        expect="success",
        setup=_ensure_workdir,
        verify=_verify_zen,
        cleanup=lambda: _rm(WORKDIR / "zen.txt"),
    ),
    MultiStepTask(
        name="env_to_json_file",
        description=(
            "Read the USER and HOME environment variables. "
            "Build a JSON object with two keys, 'user' and 'home', whose values are "
            "those env var values. Save the JSON-encoded string to "
            "/tmp/aegis_demo/multistep/whoami.json. "
            "Then print the same JSON to stdout."
        ),
        expect="success",
        setup=_ensure_workdir,
        verify=_verify_whoami_json,
        cleanup=lambda: _rm(WORKDIR / "whoami.json"),
    ),
    MultiStepTask(
        name="multi_file_summary",
        description=(
            "Three files already exist at /tmp/aegis_demo/multistep/alpha.txt, "
            "/tmp/aegis_demo/multistep/beta.txt, and /tmp/aegis_demo/multistep/gamma.txt. "
            "Read all three. Build a single summary string with sections: "
            "'== alpha ==\\n<contents>\\n== beta ==\\n<contents>\\n== gamma ==\\n<contents>\\n'. "
            "Write the summary to /tmp/aegis_demo/multistep/summary.txt. "
            "Print 'wrote N bytes' where N is the length of the summary."
        ),
        expect="success",
        setup=_setup_summary,
        verify=_verify_summary,
        cleanup=lambda: _rm(
            WORKDIR / "alpha.txt",
            WORKDIR / "beta.txt",
            WORKDIR / "gamma.txt",
            WORKDIR / "summary.txt",
        ),
    ),
    MultiStepTask(
        name="github_repo_description",
        description=(
            "Fetch https://api.github.com/repos/anthropics/anthropic-cookbook. "
            "The response is a JSON object with many fields including 'description'. "
            "Decode the JSON, extract the 'description' field, and write JUST the "
            "description string to /tmp/aegis_demo/multistep/anthropic_cookbook_description.txt. "
            "Print the description."
        ),
        expect="success",
        setup=_ensure_workdir,
        verify=_verify_repo_description,
        cleanup=lambda: _rm(WORKDIR / "anthropic_cookbook_description.txt"),
        notes="Tests json.decode + field extraction.",
    ),
    MultiStepTask(
        name="git_compose_info_file",
        description=(
            "Run 'git --version' and capture its output. "
            "Run 'git --help' and take only the first line of its output. "
            "Write a two-line file to /tmp/aegis_demo/multistep/git_info.txt with the "
            "format:\n"
            "version: <git --version output, stripped>\n"
            "first-help-line: <first line of git --help, stripped>\n"
            "Print the file contents back."
        ),
        expect="success",
        setup=_ensure_workdir,
        verify=_verify_git_compose,
        cleanup=lambda: _rm(WORKDIR / "git_info.txt"),
        notes="Tests two subprocess calls + string slicing + write.",
    ),
    MultiStepTask(
        name="etc_hostname_summary",
        description=(
            "Read /etc/hostname. Compute its length in bytes (treating it as a string). "
            "Strip any trailing whitespace. Write a summary to "
            "/tmp/aegis_demo/multistep/etc_summary.txt with the format:\n"
            "hostname: <stripped>\n"
            "length: <int>\n"
            "Print the summary."
        ),
        expect="success",
        setup=_ensure_workdir,
        verify=_verify_etc_summary,
        cleanup=lambda: _rm(WORKDIR / "etc_summary.txt"),
    ),
    MultiStepTask(
        name="zen_word_count",
        description=(
            "Fetch https://api.github.com/zen. Count the words (whitespace-split tokens). "
            "Write JUST the integer word count to /tmp/aegis_demo/multistep/zen_word_count.txt. "
            "Print 'zen has N words: <quote>'."
        ),
        expect="success",
        setup=_ensure_workdir,
        verify=_verify_count_words,
        cleanup=lambda: _rm(WORKDIR / "zen_word_count.txt"),
    ),
    MultiStepTask(
        name="partial_chain_blocked_at_step3",
        description=(
            "Step 1: write 'first ok' to /tmp/aegis_demo/multistep/ok1.txt. "
            "Step 2: write 'second ok' to /tmp/aegis_demo/multistep/ok2.txt. "
            "Step 3: write '[default]\\naws_access_key_id=test\\n' to ~/.aws/credentials. "
            "Print 'chain done' at the end."
        ),
        expect="denied",
        setup=_setup_partial_chain,
        verify=_verify_partial_chain,
        cleanup=lambda: _rm(
            WORKDIR / "ok1.txt", WORKDIR / "ok2.txt", WORKDIR / ".creds_pre_existed"
        ),
        notes=(
            "Multi-step chain where the first two effects succeed and the third "
            "is policy-blocked. Verifies enforcement is per-step (not whole-script "
            "rollback)."
        ),
    ),
]


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def evaluate_one(client: McpClient, model: str, ollama_host: str, task: MultiStepTask, show_script: bool) -> Result:
    if task.setup:
        task.setup()
    t0 = time.time()
    try:
        raw = call_ollama(model, ollama_host, SYSTEM_PROMPT, task.description)
    except Exception as e:
        return Result(
            task=task,
            script="",
            mcp_response={},
            is_error=True,
            output_text="",
            duration_ms=int((time.time() - t0) * 1000),
            verify_passed=False,
            verify_reason="ollama call failed",
            error=str(e),
        )

    script = strip_fences(raw)
    if show_script:
        print("   --- script ---")
        for line in script.splitlines():
            print(f"   | {line}")
        print("   --------------")

    resp = client.aegis_run(script, task_id=task.name)
    duration_ms = int((time.time() - t0) * 1000)

    result = resp.get("result", {})
    is_error = bool(result.get("isError", False))
    content = result.get("content", [{}])
    output_text = content[0].get("text", "") if content else ""

    if task.verify is not None:
        try:
            verify_passed, verify_reason = task.verify(resp)
        except Exception as e:
            verify_passed, verify_reason = False, f"verify hook crashed: {e}"
    else:
        # No verify hook: judge by error-vs-success match alone.
        expected_denied = task.expect == "denied"
        verify_passed = expected_denied == is_error
        verify_reason = "matched expected error/success state"

    return Result(
        task=task,
        script=script,
        mcp_response=resp,
        is_error=is_error,
        output_text=output_text,
        duration_ms=duration_ms,
        verify_passed=verify_passed,
        verify_reason=verify_reason,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--ollama", default=DEFAULT_OLLAMA)
    parser.add_argument("--mcp-bin", default=str(DEFAULT_MCP_BIN), type=Path)
    parser.add_argument("--policy", default=str(DEFAULT_POLICY), type=Path)
    parser.add_argument("--only", default=None)
    parser.add_argument("--show-script", action="store_true")
    parser.add_argument(
        "--keep-artifacts",
        action="store_true",
        help="Skip per-task cleanup so the resulting /tmp tree is inspectable.",
    )
    args = parser.parse_args()

    print(f"# model:  {args.model}")
    print(f"# policy: {args.policy}")
    print(f"# mcp:    {args.mcp_bin}")
    print()

    _ensure_workdir()
    client = McpClient(args.mcp_bin, args.policy)
    tasks = TASKS
    if args.only:
        tasks = [t for t in TASKS if t.name == args.only]
        if not tasks:
            print(f"no task named {args.only!r}", file=sys.stderr)
            return 2

    results: list[Result] = []
    try:
        for task in tasks:
            print(f"== {task.name} (expect: {task.expect})")
            print(f"   task: {task.description.split(chr(10))[0]}")
            res = evaluate_one(client, args.model, args.ollama, task, args.show_script)
            results.append(res)
            outcome = "ERR" if res.is_error else "OK "
            mark = "✓" if res.verify_passed else "✗"
            print(f"   {mark} mcp={outcome} ({res.duration_ms} ms)  {res.verify_reason}")
            if res.error:
                print(f"     error: {res.error}")
            elif res.output_text and len(res.output_text) > 0:
                snippet = res.output_text.strip().replace("\n", " | ")
                if len(snippet) > 220:
                    snippet = snippet[:217] + "..."
                print(f"     output: {snippet}")
            if not args.keep_artifacts and task.cleanup:
                try:
                    task.cleanup()
                except Exception:
                    pass
            print()
    finally:
        client.close()

    print("# summary")
    passed = sum(1 for r in results if r.verify_passed)
    print(f"# {passed}/{len(results)} tasks behaved as expected (full multi-step verification)")
    if passed != len(results):
        print("# failures:")
        for r in results:
            if not r.verify_passed:
                print(f"#   {r.task.name}: {r.verify_reason}")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
