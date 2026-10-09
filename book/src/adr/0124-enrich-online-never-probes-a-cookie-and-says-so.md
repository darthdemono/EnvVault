# ADR-0124: Enrich --online never probes a cookie, and says so by name

Status: accepted

## Context

It exists to ask an _issuer_ about its own credential. Replaying a session cookie from a desktop app is indistinguishable, at the far end, from the session hijack the cookie exists to prevent, and it can trip fraud detection on an account the user still needs. Named in the report rather than silently skipped, so the counts add up

## Decision

`enrich --online` never probes a cookie, and says so by name

## Evidence

`unv-cli/src/enrich.rs`
