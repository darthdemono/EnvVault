# ADR-0020: --online enrichment is opt-in

Status: accepted

## Context

It transmits a credential — only to its issuer, but a vault reader should not make network calls by default

## Decision

`--online` enrichment is opt-in

## Evidence

`unv-cli/src/enrich.rs`
