# ADR-0061: Sessions ephemeral (restart = re-auth)

Status: accepted

## Context

Intentional design; `ENVV_PASSWORD` env var covers Docker auto-unlock use case

## Decision

Sessions ephemeral (restart = re-auth)

## Evidence

`unv-server/main.rs`
