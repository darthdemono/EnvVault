# ADR-0117: Envv exec's scratch directory cleans up in Drop

Status: accepted

## Context

An explicit delete after `status()` is skipped on a panic and on every early return above it, and what would be left behind is a decrypted credential sitting in `/tmp` with nothing to say it is there

## Decision

`envv exec`'s scratch directory cleans up in `Drop`

## Evidence

`unv-cli/src/filecred.rs`
