#!/usr/bin/env bash
# Build the app and screenshot its real window. See Dockerfile and README.md.
#
#   tools/viewer/run.sh [scenario ...]     scenarios are in tools/viewer/shots.py
#   OUT=/some/dir tools/viewer/run.sh      where the PNGs go (default shots/native)
set -euo pipefail
cd "$(dirname "$0")/../.."
OUT="${OUT:-shots/native}"
mkdir -p "$OUT"

# The window loads dist/, built on the host where Node 22 is.
npx vite build >/dev/null
node --experimental-strip-types --no-warnings -e "
  import('./ui-lab/seed.ts').then((m) =>
    require('fs').writeFileSync('$OUT/seed.json', JSON.stringify(m.SEED_VAULT)))"

docker image inspect unv-viewer >/dev/null 2>&1 || docker build -t unv-viewer tools/viewer

# The cargo target directory lives in a named volume so the 10-minute first
# build is paid once.
docker run --rm \
  -v "$PWD":/src:ro \
  -v unv-viewer-target:/cargo-target \
  -v unv-viewer-cargo:/usr/local/cargo/registry \
  -v "$PWD/$OUT":/out \
  unv-viewer bash -c '
    set -euo pipefail
    cd /src
    cargo build -p envvault --release --features tauri/custom-protocol 2>&1 | tail -3
    dbus-run-session -- python3 tools/viewer/shots.py /cargo-target/release/envvault /out "$@"
  ' bash "$@"
echo "Screenshots in $OUT"
