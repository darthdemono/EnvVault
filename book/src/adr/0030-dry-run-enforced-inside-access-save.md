# ADR-0030: --dry-run enforced inside Access::save

Status: accepted

## Context

The single write point; a command that forgets to check the flag still cannot write

## Decision

`--dry-run` enforced inside `Access::save`

## Evidence

`unv-cli/src/access.rs`
