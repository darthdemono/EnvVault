# ADR-0004: Read Caps Lock state from the operating system

Status: accepted

## Context

Deriving Caps Lock from typed letters cannot show the hint before text is
entered, and modifier-state APIs have disagreed with the actual lock state on
some Linux window systems.

## Decision

The desktop asks the operating system for the current Caps Lock toggle state on
focus and after a Caps Lock key event. Unsupported platforms return no answer;
the existing typed-character inference remains the fallback. Browser mode does
not make an OS query.

## Consequences

The hint can reflect the lock before a password is typed. The native query must
be smoke-tested in a real Tauri window on both X11 and Wayland; a failed or
unknown query must not erase the fallback's last useful state.

## Evidence

`src-tauri/src/lib.rs` (`caps_lock_state`), `src/ts/ui-qol.ts`
