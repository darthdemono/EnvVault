# ADR-0115: One environment-variable name template, and key_id stays a segment in it

Status: accepted

## Context

The design lists six segments and excludes `key_id` on the grounds that it is identity rather than a value. True of what it means, false of what it already does: `dotenvKey` has put it in the name since Phase 3, `env-link.ts` scores `PROVIDER_KEYID` as a tier-1 match, and `find_entry` parses a bare `${NAME}` by splitting into exactly that pair. Dropping it silently renames every variable a keyed entry generates — the failure the design's own "must not break" section is about — for nothing

## Decision

One environment-variable name template, and `key_id` stays a segment in it

## Evidence

`src/ts/state.ts`, `envv-cli/src/envfile.rs`
