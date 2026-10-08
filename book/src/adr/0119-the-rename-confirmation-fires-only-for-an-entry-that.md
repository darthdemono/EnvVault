# ADR-0119: The rename confirmation fires only for an entry that has been copied

Status: accepted

## Context

`last_copied_name` is the evidence that something out there may be reading the old name. Asking on every rename of an entry nobody has ever deployed is the kind of confirmation people learn to click through, and then click through on the one that mattered

## Decision

The rename confirmation fires **only** for an entry that has been copied

## Evidence

`src/ts/modals.ts`
