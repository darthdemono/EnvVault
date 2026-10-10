#!/usr/bin/env bash
# Builds a throwaway demo server (all data fake), seeds it, drives the real
# desktop app against it in the viewer container and writes PNGs.
#
#   tools/demo/run.sh            -> Screenshots/demo/*.png
#   OUT=/dir tools/demo/run.sh
#
# Needs docker and the unv-viewer image (tools/viewer/Dockerfile; built if missing).
set -euo pipefail
cd "$(dirname "$0")/../.."
OUT="${OUT:-Screenshots}"
IMAGE="${SERVER_IMAGE:-ghcr.io/darthdemono/unenverse/unv-server:latest}"
PORT=18743
DATA="$(mktemp -d)"
trap 'docker rm -f unv-demo >/dev/null 2>&1 || true; rm -rf "$DATA"' EXIT
mkdir -p "$OUT"

cargo build -q -p unv-cli
docker rm -f unv-demo >/dev/null 2>&1 || true
docker run -d --name unv-demo -p 127.0.0.1:$PORT:8743 -v "$DATA":/data \
  --user "$(id -u):$(id -g)" -e UNV_PASSWORD=demo-passphrase-123 "$IMAGE" --nodes >/dev/null
sleep 4
UNV_SERVER_URL=http://localhost:$PORT UNV_PASSWORD=demo-passphrase-123 \
  python3 tools/demo/seed.py target/debug/unv

npx vite build >/dev/null
docker image inspect unv-viewer >/dev/null 2>&1 || docker build -t unv-viewer tools/viewer
docker run --rm --network host -e SHOT_CROP=1920x1200 \
  -v "$PWD":/src:ro -v unv-viewer-target:/cargo-target -v unv-viewer-cargo:/usr/local/cargo/registry \
  -v "$PWD/$OUT":/out -e DEMO_SERVER=http://localhost:$PORT \
  unv-viewer bash -c '
    set -euo pipefail
    cd /src
    cargo build -p unenverse --release --features tauri/custom-protocol,vault-core/bundled 2>&1 | tail -6
    dbus-run-session -- python3 tools/demo/shots_demo.py /cargo-target/release/unenverse /out
  '
echo "Screenshots in $OUT"
