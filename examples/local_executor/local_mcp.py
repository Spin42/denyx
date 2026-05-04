#!/usr/bin/env python3
"""Local-executor MCP server.

Exposes a SINGLE tool, `delegate_to_local`, that takes a natural-language
step description from a cloud orchestrator (Sonnet/Opus, via Claude CLI)
and turns it into:

  1. A Starlark program emitted by a local Ollama model (qwen2.5-coder:7b
     by default), guided by the same in-context-RAG prompt + retrieval
     library used by run_multistep.py.
  2. An execution through aegis-mcp, which runs the program under the
     configured Aegis policy (filesystem/network/env/subprocess gating
     plus audit log).
  3. A result string returned to the orchestrator: either the program's
     printed output or the full Aegis diagnostic on failure.

The retry-on-syntax-error loop from run_multistep.py is preserved: if
the local model's first program produces a parse/eval error from
Aegis (NOT a policy denial — those are returned as-is), the diagnostic
is fed back and the model gets one fix-it attempt.

This server is itself an MCP server. The orchestrator (Claude CLI)
loads it via --mcp-config; it speaks newline-delimited JSON-RPC 2.0
on stdio.

Usage from Claude CLI:

  claude -p "<task>" \\
    --mcp-config '{"mcpServers":{"local-executor":{"command":"python3",\\
        "args":["examples/local_executor/local_mcp.py","--policy",\\
                "examples/policies/multistep_test.toml"]}}}' \\
    --tools "" \\
    --allowedTools mcp__local-executor__delegate_to_local
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

# Same-directory import for the embedding retrieval library.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import rag  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_AEGIS_MCP = REPO_ROOT / "target" / "release" / "aegis-mcp"

PROTOCOL_VERSION = "2024-11-05"

LOCAL_SYSTEM_PROMPT_TEMPLATE = """You are a local code executor running under the Aegis policy-enforced runtime.

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

================================================================
WORKED EXAMPLES — patterns most relevant to your step
================================================================

{retrieved_examples}

================================================================
OUTPUT FORMAT
================================================================

Output ONLY the Starlark program. No commentary. No markdown fences. Begin immediately at column 0.
"""


# ---------------------------------------------------------------------------
# Ollama + aegis-mcp clients
# ---------------------------------------------------------------------------

def call_ollama_chat(
    model: str, host: str, messages: list[dict], timeout: float = 240
) -> str:
    req = json.dumps(
        {
            "model": model,
            "messages": messages,
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


class AegisMcpClient:
    """Subprocess client for aegis-mcp — speaks the same JSON-RPC
    protocol we expose upstream, just one layer down."""

    def __init__(self, mcp_bin: Path, policy: Path, audit_log: Path | None = None) -> None:
        cmd = [str(mcp_bin), "--policy", str(policy)]
        if audit_log is not None:
            cmd += ["--audit-log", str(audit_log)]
        self.proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        self._id = 0
        init = self._call(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "local-executor", "version": "0"},
            },
        )
        if "result" not in init:
            raise RuntimeError(f"aegis-mcp initialize failed: {init}")

    def _call(self, method: str, params: dict | None = None) -> dict:
        self._id += 1
        req: dict = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            req["params"] = params
        line = json.dumps(req) + "\n"
        assert self.proc.stdin is not None
        self.proc.stdin.write(line)
        self.proc.stdin.flush()
        assert self.proc.stdout is not None
        resp_line = self.proc.stdout.readline()
        if not resp_line:
            raise RuntimeError("aegis-mcp server closed unexpectedly")
        return json.loads(resp_line)

    def aegis_run(self, script: str, task_id: str) -> dict:
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


# ---------------------------------------------------------------------------
# Local executor pipeline (qwen + retry + aegis-mcp)
# ---------------------------------------------------------------------------

def is_retryable(output_text: str) -> bool:
    head = output_text.lstrip()
    if head.startswith("policy violation"):
        return False
    if "confirm hook denied" in head:
        return False
    return True


def build_retry_message(error_text: str, step: str) -> str:
    snippet = error_text.strip()
    if len(snippet) > 600:
        snippet = snippet[:597] + "..."
    return (
        "Your previous Starlark program produced this error from the "
        "Aegis runtime:\n\n"
        f"{snippet}\n\n"
        "Common fixes:\n"
        "  - top-level `for`/`if` → wrap in `def helper(): ...` and call it.\n"
        "  - `import ...` → DELETE the line; modules are pre-loaded.\n"
        "  - f-strings `f\"...\"` → use `\"...\" + str(x)` or `\"...\".format(x)`.\n"
        "  - `|` between calls (shell-pipe) → use SEPARATE statements.\n"
        "  - `try`/`except` → DELETE; let errors propagate.\n\n"
        "Rewrite the WHOLE program. Output ONLY the corrected Starlark "
        "code, starting at column 0.\n\n"
        f"Step: {step}"
    )


def execute_step(
    aegis: AegisMcpClient,
    step: str,
    *,
    model: str,
    ollama_host: str,
    counter: list[int],
    max_retries: int = 1,
) -> tuple[str, bool, int, str]:
    """Run one delegated step. Returns (text, is_error, retries_used, script)."""
    examples = rag.retrieve(step, k=4, host=ollama_host)
    system_prompt = LOCAL_SYSTEM_PROMPT_TEMPLATE.replace(
        "{retrieved_examples}", rag.render_examples(examples)
    )
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": step},
    ]
    raw = call_ollama_chat(model, ollama_host, messages)
    script = strip_fences(raw)

    counter[0] += 1
    task_id = f"orchestrated-{counter[0]}"
    resp = aegis.aegis_run(script, task_id=task_id)
    result = resp.get("result", {})
    is_error = bool(result.get("isError", False))
    content = result.get("content", [{}])
    text = content[0].get("text", "") if content else ""

    retries = 0
    while retries < max_retries and is_error and is_retryable(text):
        retries += 1
        retry_msg = build_retry_message(text, step)
        messages.append({"role": "assistant", "content": raw})
        messages.append({"role": "user", "content": retry_msg})
        raw = call_ollama_chat(model, ollama_host, messages)
        script = strip_fences(raw)
        counter[0] += 1
        task_id = f"orchestrated-{counter[0]}-r{retries}"
        resp = aegis.aegis_run(script, task_id=task_id)
        result = resp.get("result", {})
        is_error = bool(result.get("isError", False))
        content = result.get("content", [{}])
        text = content[0].get("text", "") if content else ""

    return text, is_error, retries, script


# ---------------------------------------------------------------------------
# Outer MCP server (the orchestrator's view)
# ---------------------------------------------------------------------------

def tool_definitions() -> list[dict]:
    return [
        {
            "name": "delegate_to_local",
            "description": (
                "Delegate a single step to a local 7B-class executor model "
                "(qwen2.5-coder:7b) running under the Aegis policy-enforced "
                "runtime. The local executor synthesizes a Starlark program "
                "from your step description and runs it. The program has "
                "access to fs.read/write/delete, net.http_get/post, "
                "subprocess.exec, env.read, json.encode/decode — every "
                "effecting call goes through the Aegis policy (filesystem "
                "deny patterns, network host/IP checks, subprocess command "
                "and arg gates, env var allow/deny). Returns the program's "
                "printed output on success, or the Aegis diagnostic on "
                "failure (policy denial, parse error, runtime crash).\n\n"
                "Pass ONE atomic step per call. Decompose multi-step plans "
                "yourself and dispatch sequentially — each call is "
                "independent (no shared state across calls except whatever "
                "the program persists to disk)."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "step": {
                        "type": "string",
                        "description": "Natural-language description of the single step to execute.",
                    }
                },
                "required": ["step"],
            },
        }
    ]


def make_response(id_: object, result: dict | None = None, error: dict | None = None) -> dict:
    out: dict = {"jsonrpc": "2.0", "id": id_}
    if error is not None:
        out["error"] = error
    else:
        out["result"] = result if result is not None else {}
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--mcp-bin", default=str(DEFAULT_AEGIS_MCP), type=Path)
    parser.add_argument("--model", default="qwen2.5-coder:7b")
    parser.add_argument("--ollama", default="http://localhost:11434")
    parser.add_argument("--audit-log", default=None, type=Path)
    parser.add_argument(
        "--trace",
        default=None,
        type=Path,
        help="Append per-step trace lines (JSON) to this file for analysis.",
    )
    args = parser.parse_args()

    if not args.mcp_bin.exists():
        print(f"aegis-mcp binary not at {args.mcp_bin}", file=sys.stderr)
        return 2

    # Pre-warm the embedding cache before the first call so the first
    # tool invocation isn't slow.
    rag.precompute_library_embeddings(host=args.ollama)

    aegis = AegisMcpClient(args.mcp_bin, args.policy, args.audit_log)
    counter = [0]

    def trace(event: dict) -> None:
        if args.trace is None:
            return
        try:
            with open(args.trace, "a") as f:
                f.write(json.dumps(event) + "\n")
        except Exception:
            pass

    stdin = sys.stdin
    stdout = sys.stdout

    try:
        for line in stdin:
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
            except json.JSONDecodeError as e:
                print(json.dumps(make_response(None, error={"code": -32700, "message": f"parse error: {e}"})), flush=True)
                continue

            method = req.get("method", "")
            id_ = req.get("id", None)
            params = req.get("params", {}) or {}

            if method == "initialize":
                resp = make_response(
                    id_,
                    result={
                        "protocolVersion": PROTOCOL_VERSION,
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "local-executor", "version": "0.1.0"},
                    },
                )
            elif method in ("initialized", "notifications/initialized"):
                resp = make_response(id_, result={})
            elif method == "tools/list":
                resp = make_response(id_, result={"tools": tool_definitions()})
            elif method == "tools/call":
                name = params.get("name", "")
                args_ = params.get("arguments", {}) or {}
                if name != "delegate_to_local":
                    resp = make_response(id_, error={"code": -32601, "message": f"unknown tool: {name}"})
                else:
                    step = args_.get("step", "")
                    if not isinstance(step, str) or not step.strip():
                        resp = make_response(id_, result={
                            "content": [{"type": "text", "text": "missing or empty 'step' argument"}],
                            "isError": True,
                        })
                    else:
                        t0 = time.time()
                        try:
                            text, is_error, retries, script = execute_step(
                                aegis,
                                step,
                                model=args.model,
                                ollama_host=args.ollama,
                                counter=counter,
                            )
                        except Exception as e:
                            text, is_error, retries, script = (f"local-executor crash: {e}", True, 0, "")
                        dur_ms = int((time.time() - t0) * 1000)
                        trace({
                            "ts": time.time(),
                            "step": step,
                            "script": script,
                            "result": text,
                            "is_error": is_error,
                            "retries": retries,
                            "duration_ms": dur_ms,
                        })
                        # Surface a small header so the orchestrator's
                        # transcript shows the local-side script and
                        # whether retries were needed — useful for the
                        # eval write-up.
                        header = (
                            f"[local-executor model={args.model} "
                            f"retries={retries} duration={dur_ms}ms]"
                        )
                        body = header + "\n\n--- Starlark program executed ---\n" + script
                        body += "\n\n--- Aegis result ---\n" + text
                        resp = make_response(id_, result={
                            "content": [{"type": "text", "text": body}],
                            "isError": is_error,
                        })
            elif method == "ping":
                resp = make_response(id_, result={})
            else:
                resp = make_response(id_, error={"code": -32601, "message": f"method not found: {method}"})

            stdout.write(json.dumps(resp) + "\n")
            stdout.flush()
    finally:
        aegis.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
