#!/usr/bin/env bash
# Turns raw app screenshots into the site's WebP images and writes the manifest
# that build-site.mjs reads for width/height (so every <img> reserves its space).
#
#   scripts/site-shots.sh <dir with PNGs> main=unenverse card-expanded=card-expanded config-history=config-history
#
# Each NAME=FILE pair reads <dir>/FILE.png and writes website/assets/shots/NAME.webp.
set -euo pipefail
src="$1"; shift
out="$(cd "$(dirname "$0")/.." && pwd)/website/assets/shots"
mkdir -p "$out"
printf '{' > "$out/manifest.json"
sep=''
for pair in "$@"; do
  name="${pair%%=*}"; file="${pair#*=}"
  magick "$src/$file.png" -resize '1600x>' -quality 82 "$out/$name.webp"
  dims="$(magick identify -format '%w %h' "$out/$name.webp")"
  w="${dims% *}"; h="${dims#* }"
  printf '%s"%s":{"width":%s,"height":%s}' "$sep" "$name" "$w" "$h" >> "$out/manifest.json"
  sep=','
done
printf '}\n' >> "$out/manifest.json"
echo "wrote $(ls "$out"/*.webp | wc -l) images to $out"
