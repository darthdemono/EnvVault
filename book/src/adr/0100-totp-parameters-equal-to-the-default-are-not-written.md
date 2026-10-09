# ADR-0100: TOTP parameters equal to the default are not written

Status: accepted

## Context

`totp_algorithm: "SHA1"` on every entry cannot be told apart from a defaulted one, so nothing downstream can say whether the issuer chose it or we did. Absent means what an omitted `otpauth://` parameter means

## Decision

TOTP **parameters equal to the default are not written**

## Evidence

`unv-cli/src/entries.rs`, `src/ts/modals.ts`
