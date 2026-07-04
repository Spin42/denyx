//! Cheap Landlock availability probe for
//! `Policy::guard_sandbox_available` — same "fail load if the
//! configured sandbox backend isn't actually usable" posture as the
//! `which_on_path("bwrap")` check for `sandbox = "bwrap"`.
//!
//! `Ruleset::create()` never restricts the *calling* process — only
//! `RulesetCreated::restrict_self()` does that, which is a one-way
//! door for the process that calls it. This probe only ever calls
//! `create()` under `CompatLevel::HardRequirement`, so it's safe to
//! run directly in the `denyx` process itself: no forking, and this
//! process is not sandboxed by having asked the question. Real
//! subprocess-time enforcement (the actual `restrict_self()` call)
//! happens per-child in `denyx-host`'s `landlock_sandbox` module, via
//! `Command::pre_exec` in the forked child — never in this process.

use landlock::{Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr, ABI};

/// Whether this kernel supports Landlock at all, under a
/// `HardRequirement` compatibility check (which surfaces "kernel too
/// old / feature disabled" as an error instead of the crate's default
/// best-effort silent degradation).
pub(crate) fn is_available() -> bool {
    Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(ABI::V1))
        .and_then(|r| r.create())
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_available_does_not_panic_and_does_not_restrict_this_process() {
        // Whatever the answer is on the test-running kernel, calling
        // this must not sandbox the test process itself — prove it by
        // reading a file the test process can obviously still reach
        // immediately afterward.
        let _ = is_available();
        assert!(std::path::Path::new("/proc/self/status").exists());
    }
}
