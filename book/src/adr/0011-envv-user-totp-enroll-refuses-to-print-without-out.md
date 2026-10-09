# ADR-0011: Envv user totp enroll refuses to print without --out/--reveal, and refuses before minting

Status: accepted

## Context

Same rule and same ordering as `user token new`: enrolling and then declining to print leaves a secret nobody can reach and no `confirm` can be run against

## Decision

`envv user totp enroll` refuses to print without `--out`/`--reveal`, and refuses _before_ minting

## Evidence

`unv-cli/src/users_cmd.rs`
