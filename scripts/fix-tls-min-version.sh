#!/usr/bin/env bash
#
# Raise the Cloudflare zone TLS floor to 1.2 (M-1).
#
# Requires a Cloudflare API token with Zone Settings:Edit on the zone, plus
# either CLOUDFLARE_ZONE_ID or CLOUDFLARE_ZONE_NAME. The token is read from
# the environment and is never written to disk or printed.
#
# Usage:
#   CLOUDFLARE_API_TOKEN=... CLOUDFLARE_ZONE_NAME=pranithjain.qzz.io \
#     ./scripts/fix-tls-min-version.sh
#
# The dashboard equivalent is:
#   SSL/TLS -> Edge Certificates -> Minimum TLS Version = TLS 1.2
#   SSL/TLS -> Edge Certificates -> TLS 1.3 = On
#
set -euo pipefail

: "${CLOUDFLARE_API_TOKEN:?Set CLOUDFLARE_API_TOKEN to a token with Zone Settings:Edit}"
ZONE_NAME="${CLOUDFLARE_ZONE_NAME:-pranithjain.qzz.io}"
API="https://api.cloudflare.com/client/v4"

api() {
  local method="$1"
  local path="$2"
  local data="${3:-}"
  if [ -n "$data" ]; then
    curl -fsS -X "$method" \
      -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
      -H "Content-Type: application/json" \
      --data "$data" \
      "$API$path"
  else
    curl -fsS -X "$method" \
      -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
      "$API$path"
  fi
}

if [ -n "${CLOUDFLARE_ZONE_ID:-}" ]; then
  ZONE_ID="$CLOUDFLARE_ZONE_ID"
else
  ZONE_ID="$(api GET "/zones?name=$ZONE_NAME" | node -e '
    let s = "";
    process.stdin.on("data", (d) => (s += d)).on("end", () => {
      const j = JSON.parse(s);
      const zone = Array.isArray(j.result) ? j.result[0] : null;
      if (!zone) {
        console.error("zone not found");
        process.exit(1);
      }
      process.stdout.write(zone.id);
    });
  ')"
fi

echo "Zone: $ZONE_NAME ($ZONE_ID)"

echo "Setting minimum TLS version to 1.2..."
api PATCH "/zones/$ZONE_ID/settings/min_tls_version" '{"value":"1.2"}' >/dev/null
echo "  ok"

echo "Enabling TLS 1.3..."
if api PATCH "/zones/$ZONE_ID/settings/tls_1_3" '{"value":"on"}' >/dev/null 2>&1; then
  echo "  ok"
else
  echo "  skipped (the setting is plan-dependent; TLS 1.2 is the security floor)"
fi

echo "Verifying that TLS 1.1 is rejected..."
if curl -sS --tls-max 1.1 -o /dev/null "https://$ZONE_NAME/" 2>/dev/null; then
  echo "FAIL: TLS 1.1 still completes. Check for a proxy or a cached zone setting." >&2
  exit 1
fi
echo "  ok: TLS 1.1 rejected"

echo
echo "Next: re-run the CBC/SHA1 probe from the audit. A TLS 1.2 floor is the"
echo "critical fix; custom cipher selection is plan-dependent and optional."
