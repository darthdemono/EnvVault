# ADR-0126: A cookie entry's extra_vars are masked whole, public ignored

Status: accepted

## Context

A jar split one cookie per var is N session credentials and any one of them is enough to be the account. There is no "public half" here the way there is beside a client secret, so the per-value opt-out does not apply — the same rule `env_file` chunks already follow

## Decision

A cookie entry's `extra_vars` are masked whole, `public` **ignored**

## Evidence

`envv-cli/src/out.rs`
