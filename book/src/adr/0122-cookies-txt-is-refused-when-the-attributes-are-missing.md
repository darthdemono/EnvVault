# ADR-0122: Cookies.txt is refused when the attributes are missing

Status: accepted

## Context

The format needs a domain, an include-subdomains flag, a path, a secure flag and an expiry per cookie, and a bare `document.cookie` paste has none. A file `yt-dlp` reads and silently ignores is worse than no button: the user discovers it as "the download is not logged in", with nothing pointing at the file

## Decision

`cookies.txt` is **refused** when the attributes are missing

## Evidence

`src/ts/cookies.ts`, `envv-cli/src/cookies.rs`
