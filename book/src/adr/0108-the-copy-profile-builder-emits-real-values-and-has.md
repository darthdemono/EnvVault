# ADR-0108: The copy-profile builder emits real values and has no masker

Status: accepted

## Context

Redaction is the caller's job and is already decided by the Phase 14 rule that governs every artefact — refuse to stdout unless `--reveal`, write the real thing with `--out`. A second redaction policy inside the builder is the shape that produced the Phase 22 seed leak

## Decision

The copy-profile builder emits **real values** and has no masker

## Evidence

`src/ts/copy-profile.ts`, `envv-cli/src/profile.rs`
