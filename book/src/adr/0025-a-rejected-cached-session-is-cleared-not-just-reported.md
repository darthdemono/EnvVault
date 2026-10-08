# ADR-0025: A rejected cached session is cleared, not just reported

Status: accepted

## Context

Otherwise every subsequent command fails identically with a 401 that never mentions the cache

## Decision

A rejected cached session is cleared, not just reported

## Evidence

`envv-cli/src/main.rs`
