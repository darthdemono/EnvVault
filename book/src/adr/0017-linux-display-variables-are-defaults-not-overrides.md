# ADR-0017: Linux display variables are defaults, not overrides

Status: accepted

## Context

The old code forced XWayland on Wayland sessions and could not be turned off on hardware it had never seen

## Decision

Linux display variables are defaults, not overrides

## Evidence

`src-tauri/src/lib.rs`
