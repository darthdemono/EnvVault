# ADR-0076: The Authenticator became a fifth activity-bar panel, reversing Phase 22

Status: accepted

## Context

Phase 22 argued it was a filter over the Secrets panel rather than a place to be, and that a fifth entry adds a second navigation idiom. What changed is the surface: three kinds, a hand-advanced counter and a next-code view do not fit in a one-line sidebar row. The sidebar section **stays** — still the fastest path to one code. Recorded as a reversal, because an unwritten one is indistinguishable from having forgotten the reasoning

## Decision

The Authenticator became a fifth activity-bar panel, reversing Phase 22

## Evidence

`src/ts/auth-panel.ts`
