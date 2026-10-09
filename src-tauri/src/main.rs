// Prevents a console window from appearing on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Binary entry point for UnENVerse.
//!
//! All application logic lives in [`unenverse_lib`].  This crate merely
//! delegates to [`unenverse_lib::run`] so that `cargo tauri dev` and
//! `cargo test` can share the same library crate without recompiling the
//! binary.

/// Application entry point.  Calls [`unenverse_lib::run`] which builds the
/// Tauri application, registers all commands, and starts the event loop.
fn main() {
    unenverse_lib::run();
}
