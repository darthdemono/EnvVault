# ADR-0021: Enrich fills gaps only unless --force

Status: accepted

## Context

A wrong guess that silently replaces a deliberate choice is worse than no guess

## Decision

`enrich` fills gaps only unless `--force`

## Evidence

`envv-cli/src/enrich.rs`
