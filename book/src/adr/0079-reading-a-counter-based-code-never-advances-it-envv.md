# ADR-0079: Reading a counter-based code never advances it; envv totp advance and a card button do

Status: accepted

## Context

Such a code stands until it is used, and the service moves on only when it accepts one. Advancing on every read walks the vault past the service the first time somebody looks at a card twice, and the failure — a second factor that stops working with no error anywhere — is indistinguishable from a wrong seed

## Decision

Reading a counter-based code never advances it; `envv totp advance` and a card button do

## Evidence

`unv-cli/src/totp_cmd.rs`, `src/ts/auth-panel.ts`
