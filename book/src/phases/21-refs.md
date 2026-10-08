# Phase 21: reference correctness

Reference aliases now resolve identity fields such as `ID` consistently in the
desktop app and CLI. Metadata fields are rejected from rendered configuration
references, preventing an entry UUID from being silently substituted where a
credential value was expected.
