# ADR-0029: Env_file chunk values masked whole, ignoring per-field secret flags

Status: accepted

## Context

`chunk set` defaults to `field_type: var`, so a password added that way carries no flag — trusting the flag means the first unflagged password leaks

## Decision

`env_file` chunk values masked whole, ignoring per-field secret flags

## Evidence

`envv-cli/src/out.rs`
