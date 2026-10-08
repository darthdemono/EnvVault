# ADR-0057: LastConnectedAt stamped only after auth succeeds

Status: accepted

## Context

Saving a server is not evidence you can get into it; stamping on save would let a mistyped URL outrank the server used daily

## Decision

`lastConnectedAt` stamped only after auth succeeds

## Evidence

`remote-panel.ts`
