# ADR-0150: The app is screenshotted by driving its real window inside a container

Status: accepted

## Context

jsdom has no layout and Chromium is a different engine from the desktop app's WebKitGTK. Defects such as the ghost widgets, the cascade losing to an inline style and clipped controls only show in the real engine, and no screenshot of the real app existed.

## Decision

`tools/viewer/` holds a Docker image (Xvfb, WebKitGTK 4.1, `tauri-driver`, `webkit2gtk-driver`) and `shots.py`, a small W3C WebDriver client. `run.sh` builds `dist/` on the host, builds the app in the container, starts it on a virtual display with a throwaway home directory, creates a vault, seeds it, walks the main screens and settings tabs, and writes PNGs plus `report.json` listing any JavaScript error the page logged. Nothing is mocked: it is the real engine, the real IPC bridge and a real SQLCipher vault, and the host's display, home directory and vault are never touched.

## Consequences

A run is both a picture and a check (exit status 1 on a page error). The first build compiles the app inside a named volume and takes minutes; later runs reuse it. It does not replace the Playwright UI lab (fast, Chromium) and should be run after a visual change.
