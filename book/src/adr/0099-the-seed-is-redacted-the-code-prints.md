# ADR-0099: The seed is redacted; the code prints

Status: accepted

## Context

Phase 14's rule governs stored values. A code is derived, six digits, and dead in thirty seconds; a command that exists to hand you one and then refuses has no purpose. The `otpauth://` URI follows the seed's rule instead, because it contains the seed. Written down because an unwritten exemption is indistinguishable from an oversight (invariant 10)

## Decision

The **seed** is redacted; the **code** prints

## Evidence

`unv-cli/src/totp_cmd.rs`
