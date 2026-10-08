# ADR-0110: The .env link scorer scores a template match and a PROVIDER_KEYID match the same, and

Status: accepted

## Context

They make the same claim about the same syntax. Scoring one above the other would pick a winner where the data does not; scoring them equal makes the collision visible, and a tie now yields no link rather than whichever entry came first in the array (invariant 1)

## Decision

The `.env` link scorer scores a template match and a `PROVIDER_KEYID` match **the same**, and refuses ties

## Evidence

`src/ts/chunks/env-link.ts`
