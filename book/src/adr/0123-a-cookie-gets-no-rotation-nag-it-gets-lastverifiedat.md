# ADR-0123: A cookie gets no rotation nag; it gets last_verified_at

Status: accepted

## Context

Rotating a session means logging in again in a browser, which nothing here can do — so the entry would be flagged overdue forever with no available fix, and a nag with no fix is how a health scan trains people to ignore it. "Never verified" has a fix and it takes ten seconds

## Decision

A cookie gets no rotation nag; it gets `last_verified_at`

## Evidence

`envv-cli/src/scan.rs`, `src/ts/tools.ts`
