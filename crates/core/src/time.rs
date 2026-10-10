//! The library's wall clock. An app that moves its clock, such as a test or a benchmark
//! replaying seeded data, installs its own with [`set_clock`]; better-auth follows a
//! patched `Date` the same way.
use chrono::{DateTime, Utc};
use std::sync::OnceLock;

static CLOCK: OnceLock<fn() -> DateTime<Utc>> = OnceLock::new();

/// Install the process's clock once, before the first request. Returns the clock back
/// if one is already installed.
pub fn set_clock(clock: fn() -> DateTime<Utc>) -> Result<(), fn() -> DateTime<Utc>> {
    CLOCK.set(clock)
}

/// The current time: the installed clock, else the system's.
pub fn now() -> DateTime<Utc> {
    CLOCK.get().map_or_else(Utc::now, |clock| clock())
}
