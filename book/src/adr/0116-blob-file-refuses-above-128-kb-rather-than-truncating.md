# ADR-0116: --blob-file refuses above 128 KB rather than truncating

Status: accepted

## Context

A truncated credential fails at deploy time with an error about malformed JSON, which names the consumer and not the vault that broke it. A bundle that large belongs on disk with `--mount-path` pointing at it

## Decision

`--blob-file` refuses above 128 KB rather than truncating

## Evidence

`unv-cli/src/entries.rs`
