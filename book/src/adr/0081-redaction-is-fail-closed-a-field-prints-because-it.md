# ADR-0081: Redaction is fail-closed: a field prints because it is known safe, not because nobody

Status: accepted

## Context

The allow-list-of-secrets shape means any field the running build has not heard of prints verbatim, and a binary older than the vault it reads is ordinary rather than exotic — which is exactly how a stored TOTP seed reached a transcript from `envv list --json`. Inverting costs an old binary the _visibility_ of a new metadata field, recoverable with `--reveal`; the other direction costs a credential, which is not recoverable at all

## Decision

Redaction is **fail-closed**: a field prints because it is known safe, not because nobody marked it secret

## Evidence

`unv-cli/src/out.rs`
