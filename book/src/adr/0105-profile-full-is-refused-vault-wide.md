# ADR-0105: --profile full is refused vault-wide

Status: accepted

## Context

One entry's metadata is a convenience; every entry's — purposes, projects, tags, rotation dates — is a map of what matters in the vault, and it lands in whatever the user pastes into next. Same rule and same reasoning as Phase 14's refusal of a vault-wide export to stdout

## Decision

`--profile full` is refused vault-wide

## Evidence

`unv-cli/src/envfile.rs`, `src/ts/import-export.ts`
