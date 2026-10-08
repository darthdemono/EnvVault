# ADR-0035: CLI lookups refuse ambiguity instead of taking the first match

Status: accepted

## Context

`envv entry rm git` against GitHub + GitLab would delete whichever sorted earlier — the array-index bug class wearing a different hat

## Decision

CLI lookups refuse ambiguity instead of taking the first match

## Evidence

`envv-cli/src/data.rs`
