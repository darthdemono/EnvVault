# ADR-0048: Rate counter only on auth failures

Status: accepted

## Context

Incrementing on all requests would block legitimate probing (e.g., checking if vault exists)

## Decision

Rate counter only on auth failures

## Evidence

`envv-server/main.rs`
