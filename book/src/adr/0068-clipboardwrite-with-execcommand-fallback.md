# ADR-0068: ClipboardWrite() with execCommand fallback

Status: accepted

## Context

`navigator.clipboard` silently fails in Tauri WebView on Linux without HTTPS

## Decision

`clipboardWrite()` with `execCommand` fallback

## Evidence

`utils.ts`
