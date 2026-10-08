# ADR-0086: The Authenticator section is not data-gated, unlike Tags and Key Pools

Status: accepted

## Context

Those are pure filters with nothing to offer when empty. This one carries the Import button, and an empty authenticator list is exactly when somebody is looking for it

## Decision

The Authenticator section is **not** data-gated, unlike Tags and Key Pools

## Evidence

`src/ts/state.ts`, `src/ts/render.ts`
