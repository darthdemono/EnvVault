# ADR-0043: SwitchToLocalVault() shared by Disconnect and the vault switcher

Status: accepted

## Context

The two paths had already diverged — one cleared `projects`, the other didn't, and neither prompted for the master password when local was still locked

## Decision

`switchToLocalVault()` shared by Disconnect and the vault switcher

## Evidence

`remote-panel.ts`
