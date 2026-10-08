# ADR-0008: Focus trapping is driven by a MutationObserver on classes, not by hooking each overlay

Status: accepted

## Context

Thirteen overlays, at least four modules that open one. A rule that has to be remembered at every open site is a rule that gets missed at one

## Decision

Focus trapping is driven by a `MutationObserver` on classes, not by hooking each overlay

## Evidence

`src/ts/ui-qol.ts`
