# ADR-0104: Extra_vars are masked by default, with public as a per-value opt-out

Status: accepted

## Context

The old rule masked only when `secret: true`, a flag that defaults to unset — so an entry whose payload is named variables printed all of them. Opt-out per value and **never per type**: a client id, a region and an account SID are each safe to print and the secret beside them is not. Without it the `basic` profile is either useless (everything masked) or unsafe (nothing)

## Decision

`extra_vars` are masked by default, with `public` as a per-value opt-out

## Evidence

`envv-cli/src/out.rs`
