#!/usr/bin/env bash
# provision.sh — bring a fresh/reset Meshtastic node to deadmesh test baseline
# Usage: ./provision.sh <port> <long_name> <short_name> [channel_url]
#
# Examples:
#   ./provision.sh COM7 deadmesh.003 DM03
#   ./provision.sh /dev/ttyACM0 deadmesh.004 DM04 "https://meshtastic.org/e/#..."
#   ./provision.sh COM5 SEND_NODES SNDN "$(cat ~/.deadmesh/channel.url)"

set -euo pipefail

PORT="${1:?usage: \$0 <port> <long_name> <short_name> [channel_url]}"
LONG_NAME="${2:?missing long name}"
SHORT_NAME="${3:?missing short name (max 4 chars)}"
CHANNEL_URL="${4:-}"

BASELINE="$(dirname "\$0")/node-baseline.yaml"

if [ ! -f "$BASELINE" ]; then
  echo "ERROR: $BASELINE not found" >&2
  exit 1
fi

if [ "${#SHORT_NAME}" -gt 4 ]; then
  echo "ERROR: short name '$SHORT_NAME' is >4 chars" >&2
  exit 1
fi

echo "==> [$PORT] applying baseline config from $BASELINE"
meshtastic --port "$PORT" --configure "$BASELINE"

echo "==> [$PORT] setting owner: $LONG_NAME ($SHORT_NAME)"
meshtastic --port "$PORT" \
  --set-owner "$LONG_NAME" \
  --set-owner-short "$SHORT_NAME"

if [ -n "$CHANNEL_URL" ]; then
  echo "==> [$PORT] applying channel URL"
  meshtastic --port "$PORT" --seturl "$CHANNEL_URL"
else
  echo "==> [$PORT] no channel URL provided — leaving channel as-is"
fi

echo "==> [$PORT] verifying"
meshtastic --port "$PORT" --info | grep -E "Owner:|modemPreset|region|role" || true

echo "==> [$PORT] done."
