# ADR-0103: The Settings copy preview uses an invented entry, not one of the user's

Status: accepted

## Context

The panel must show the same thing on an empty vault, and a real credential's name in a settings screenshot is a small leak for no gain

## Decision

The Settings copy preview uses an **invented** entry, not one of the user's

## Evidence

`src/ts/settings-panel.ts`
