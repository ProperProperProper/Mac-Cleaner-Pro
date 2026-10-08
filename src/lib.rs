//! Mac Cleaner Pro — transparent disk cleaner + macOS security audit & fixes.
//! Pure Rust; no network calls of its own, no telemetry.

pub mod cleaner;
pub mod cli;
pub mod cmd;
pub mod gui;
pub mod history;
pub mod schedule;
pub mod security;
pub mod util;
