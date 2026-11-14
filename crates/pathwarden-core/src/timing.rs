//! Phase timings for profiling large collections: set `PATHWARDEN_TIMINGS=1`
//! and each phase prints its duration to stderr.

use std::sync::OnceLock;
use std::time::Instant;

/// Whether `PATHWARDEN_TIMINGS` asks for timings (and the UI's cache lines).
pub fn enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("PATHWARDEN_TIMINGS").is_some_and(|v| v != "0"))
}

/// Runs `f`, printing how long it took when timings are enabled.
pub fn phase<T>(name: &str, f: impl FnOnce() -> T) -> T {
    if !enabled() {
        return f();
    }
    let start = Instant::now();
    let out = f();
    eprintln!(
        "[timing] {name:<28} {:>9.2}s",
        start.elapsed().as_secs_f64()
    );
    out
}

/// Prints a duration measured elsewhere, when timings are enabled.
pub fn report(name: &str, took: std::time::Duration) {
    if enabled() {
        eprintln!("[timing] {name:<28} {:>9.2}s", took.as_secs_f64());
    }
}
