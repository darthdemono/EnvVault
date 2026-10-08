# ADR-0065: _toolsInited, _remotePanelListenersAdded, _usersPanelInited flags

Status: accepted

## Context

Panels re-initialize on every unlock cycle; guards prevent listener accumulation

## Decision

`_toolsInited`, `_remotePanelListenersAdded`, `_usersPanelInited` flags

## Evidence

`tools.ts`, `remote-panel.ts`, `users.ts`
