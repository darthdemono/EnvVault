# ADR-0056: StateFlags::VISIBLE excluded from window-state

Status: accepted

## Context

The tray handler hides the window; saving visibility restores an invisible window after hide-to-tray + quit

## Decision

`StateFlags::VISIBLE` excluded from window-state

## Evidence

`src-tauri/src/lib.rs`
