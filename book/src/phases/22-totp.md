# Phase 22: stored authenticators

An entry can hold a third-party authenticator seed alongside its credential and
produce a live code in the desktop app or CLI. Seeds are redacted stored values;
the short-lived derived code is intentionally copyable. URI parsing accepts
common `otpauth://` exports and preserves non-default algorithm, digits, and
period settings.
