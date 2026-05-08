//! `denyx-local-mcp` — the production-shape Rust port of
//! `examples/local_executor/local_mcp.py`.
//!
//! This crate ships a single binary, `denyx-local-mcp`, which speaks
//! MCP over stdio JSON-RPC and exposes one tool, `delegate_to_local`.
//! When a cloud orchestrator (Sonnet / Opus / etc.) calls that tool
//! with a natural-language step description, the binary:
//!
//!   1. retrieves the top-K relevant Starlark code examples from the
//!      embedded library (cosine similarity over Ollama embeddings),
//!   2. asks a local Ollama chat model (qwen2.5-coder:7b by default)
//!      to emit a Starlark program for the step, given the retrieved
//!      examples + a strict-rules system prompt,
//!   3. runs the program through a child `denyx-mcp` subprocess so
//!      the Denyx policy gates every effecting call,
//!   4. on a parse / runtime error (NOT a policy denial), feeds the
//!      diagnostic back to the model and gives it one fix-it attempt,
//!   5. returns the Denyx output (or full diagnostic on failure) to
//!      the orchestrator as a tool-call result.
//!
//! ## Design notes
//!
//! Every external dependency (Ollama HTTP, the denyx-mcp subprocess)
//! is mediated by a trait so unit tests can inject deterministic
//! stubs. The HTTP-backed implementations live in [`ollama`].
//!
//! ## What's NOT in this crate
//!
//! The eval harnesses (`run_multistep.py`, `run_pentest.py`,
//! `run_exfil.py`) stay in `examples/local_executor/` — they are
//! research-shape scripts, not production. The Python `local_mcp.py`
//! is also kept there as a teaching reference. The Rust crate is
//! the version users `cargo install`.

pub mod denyx_client;
pub mod ollama;
pub mod openai_compat;
pub mod pipeline;
pub mod prompt;
pub mod provider;
pub mod rag;
pub mod server;
