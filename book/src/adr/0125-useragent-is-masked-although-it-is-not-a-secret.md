# ADR-0125: User_agent is masked although it is not a secret

Status: accepted

## Context

It is a browser fingerprint: it identifies the machine and build a session was minted in, and a listing full of them says which of the user's machines holds which account

## Decision

`user_agent` is masked although it is not a secret

## Evidence

`envv-cli/src/out.rs`
