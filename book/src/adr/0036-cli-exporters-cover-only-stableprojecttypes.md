# ADR-0036: CLI exporters cover only STABLE_PROJECT_TYPES

Status: accepted

## Context

Porting all ten doubles the Rust and creates ten pairs of implementations with nothing checking they agree

## Decision

CLI exporters cover only `STABLE_PROJECT_TYPES`

## Evidence

`unv-cli/src/exporters.rs`
