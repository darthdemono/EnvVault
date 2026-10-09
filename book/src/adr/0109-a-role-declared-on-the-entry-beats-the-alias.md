# ADR-0109: A role declared on the entry beats the ${…} alias table

Status: accepted

## Context

`primary_role: "id"` says the primary value _is_ a client id, so `${X/ID}` must answer with it rather than with the `key_id` beside it — while an entry declaring no role resolves exactly as Phase 21 left it. It is also what makes the no-primary shapes addressable: `${Twilio/ACCOUNT_SID}` and `${Twilio/AUTH_TOKEN}` name the halves by the issuer's own words

## Decision

A role declared on the entry beats the `${…}` alias table

## Evidence

`unv-cli/src/refs.rs`, `src/ts/chunk-ops.ts`
