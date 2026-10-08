# ADR-0107: Profile metadata is # comments by default

Status: accepted

## Context

An `.env` is loaded into a process. Injecting six non-functional variables per credential into every container is a cost the user did not ask for by pressing Copy. One `# name: value` line per field rather than one joined line, because `full` adds nine and a `.env` comment does not wrap

## Decision

Profile metadata is `#` comments by default

## Evidence

`src/ts/copy-profile.ts`
