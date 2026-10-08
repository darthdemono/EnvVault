# ADR-0077: The next code is opt-in everywhere

Status: accepted

## Context

It is a second working credential with a longer life than the one on screen, so a panel that always painted one would make every screenshot good for two periods instead of one. `--next` in the CLI, a toggle in the panel, and a separate cache key so turning it on is never served an answer that lacks it

## Decision

The next code is opt-in everywhere

## Evidence

`vault-core/src/totp.rs`, `src/ts/auth-panel.ts`
