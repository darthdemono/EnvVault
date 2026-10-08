# Phase 24: reliability and delivery

Phase 24 fixes defects in previously shipped behaviour: remote authenticator
codes, desktop exports, form generation, credential-card grouping, sidebar
layout, and forward-compatible edits. CI adds dependency auditing, CodeQL,
Dependabot, and immutable action pins. This guide is built with mdBook and
published alongside the TypeScript and Rust API references.

## Sub-phases

- **24.1 Bundles and composites.** A composite is one value with named secret
  parts; a bundle is one card over several entries plus its own typed variables,
  addressed as `${bundle:Name/slot/field}`. Python config modules import as
  bundle variables and export back with templates as f-strings.
- **24.2 The secrets grid.** Type chips, pools as one card, a health scan that
  names type, field and state.
- **24.3 Calendar feeds.** A revocable, token-addressed `.ics` URL served by
  `envv-server`; it never carries a value, and a locked server answers 503
  rather than an empty calendar.
- **24.4 Unique-ID registry.** Keyed hashes only, token-bucket rate limits that
  count per value (`--uid-rate` to override), chunked pruning.
- **24.5 Credential model.** A type registry, web-session capture import, files
  emitted for the tools that read them, OAuth refresh with store-first ordering,
  and BIP39 checksum validation against the bundled wordlist.
