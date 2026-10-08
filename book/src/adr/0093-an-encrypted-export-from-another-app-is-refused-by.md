# ADR-0093: An encrypted export from another app is refused by name, never decrypted

Status: accepted

## Context

Six apps, six KDFs and envelopes; implementing them means six password-guessing paths whose failures look exactly like a corrupt file. `detect()` recognises each encrypted shape and says which app it is and what to do instead

## Decision

An **encrypted** export from another app is refused by name, never decrypted

## Evidence

`vault-core/src/totp_import.rs`
