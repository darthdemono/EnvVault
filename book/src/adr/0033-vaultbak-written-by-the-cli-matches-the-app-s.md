# ADR-0033: .vaultbak written by the CLI matches the app's WebCrypto envelope byte for byte

Status: accepted

## Context

A backup format that only one half of the product can read is not a backup; verified in both directions against Node's WebCrypto

## Decision

`.vaultbak` written by the CLI matches the app's WebCrypto envelope byte for byte

## Evidence

`unv-cli/src/backup.rs`
