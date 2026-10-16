#!/usr/bin/env bash
# End-to-end: extract PSSH, fetch keys, decrypt. Requires a .wvd device.
set -euo pipefail
DEVICE="${1:?usage: decrypt.sh device.wvd license_url input.mp4 output.mp4}"
LIC="${2:?}"
IN="${3:?}"
OUT="${4:?}"

echo "== pssh =="
wv pssh -i "$IN"

echo "== decrypt =="
wv decrypt -d "$DEVICE" -l "$LIC" -p "$IN" -i "$IN" -o "$OUT"

echo "== verify =="
ffprobe -v error -count_frames -select_streams v:0 \
  -show_entries stream=nb_read_frames -of csv=p=0 "$OUT" | xargs -I{} echo "frames: {}"
