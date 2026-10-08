# ADR-0090: HOTP entries are refused on import, and named in the report

Status: accepted

## Context

Counter-based means no clock, so "the current code" does not exist; importing one gives a card whose code never changes. Dropping them silently is how somebody learns six months later that an account never came across

## Decision

HOTP entries are refused on import, and **named** in the report

## Evidence

`vault-core/src/totp_import.rs`
