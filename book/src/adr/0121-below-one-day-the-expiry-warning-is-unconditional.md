# ADR-0121: Below one day, the expiry warning is unconditional

Status: accepted

## Context

`expiryWarningDays` exists to tune how far ahead a _long-lived_ credential warns. A credential dying within the hour is not a matter of taste

## Decision

Below one day, the expiry warning is unconditional

## Evidence

`src/ts/render.ts`
