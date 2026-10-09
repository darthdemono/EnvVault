#!/usr/bin/env bash
# Runs, locally, the same gates CI runs on every push (ci.yml). Run it before
# committing: `npm run preflight`. Rust formatting and clippy are the two that
# have gone red in CI most often.
set -euo pipefail
cd "$(dirname "$0")/.."
step() { printf '\n== %s\n' "$*"; }
step "cargo fmt";    cargo fmt --all -- --check
step "cargo clippy"; cargo clippy --workspace --locked --all-targets -- -D warnings
step "cargo test";   cargo test --workspace --locked
step "npm check";    npm run check
step "vite build";   npx vite build >/dev/null
printf '\npreflight ok\n'
