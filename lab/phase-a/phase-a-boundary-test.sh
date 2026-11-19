#!/usr/bin/env bash
set -Eeuo pipefail

readonly GW="rma-lab-gw"
readonly A="rma-lab-a"
readonly SINK="rma-lab-sink"
readonly PORT=44002
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PY="$ROOT/traffic.py"

die() { echo "FAIL: $*" >&2; exit 1; }
for x in ip nft python3; do command -v "$x" >/dev/null 2>&1 || die "missing tool: $x"; done
for ns in "$GW" "$A" "$SINK"; do
  ip netns list | awk '{print $1}' | grep -Fxq "$ns" || die "namespace missing: $ns"
done
[[ -f "$PY" ]] || die "traffic.py not found"

TMP="$(mktemp -d)"
SINK_PID=""
cleanup() {
  if [[ -n "$SINK_PID" ]]; then kill "$SINK_PID" 2>/dev/null || true; fi
  rm -rf "$TMP"
}
trap cleanup EXIT

echo "[Q-05] Exact quota boundary: 53 x 1200-byte payloads + 1 x 424-byte payload"
ip netns exec "$GW" nft reset quota inet rma_lab shared_ab >/dev/null
ip netns exec "$SINK" python3 "$PY" serve --port "$PORT" --duration 3.0 --output "$TMP/boundary.json" --ready-file "$TMP/ready" &
SINK_PID=$!
for _ in $(seq 1 50); do
  [[ -f "$TMP/ready" ]] && break
  kill -0 "$SINK_PID" 2>/dev/null || die "sink exited before ready"
  sleep 0.1
done
[[ -f "$TMP/ready" ]] || die "sink readiness timeout"

# IPv4 + UDP headers add 28 bytes to each UDP payload.
# 53 * (1200 + 28) + (424 + 28) = 65536 bytes exactly.
ip netns exec "$A" python3 "$PY" send --port "$PORT" --count 53 --payload-size 1200 --interval 0
ip netns exec "$A" python3 "$PY" send --port "$PORT" --count 1 --payload-size 424 --interval 0

QUOTA_AT_BOUNDARY="$(ip netns exec "$GW" nft list quota inet rma_lab shared_ab)"
printf '%s\n' "$QUOTA_AT_BOUNDARY"
grep -q 'used 64 kbytes' <<<"$QUOTA_AT_BOUNDARY" || die "quota did not report exactly 64 kbytes at planned boundary"

echo "[Q-06] Send one additional full-size packet after the quota boundary; it must be dropped"
ip netns exec "$A" python3 "$PY" send --port "$PORT" --count 1 --payload-size 1200 --interval 0
wait "$SINK_PID"
SINK_PID=""

cat "$TMP/boundary.json"
python3 - "$TMP/boundary.json" <<'CHECK'
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    data = json.load(f)
a = data.get("10.10.1.2", {})
packets = a.get("packets", 0)
payload_bytes = a.get("payload_bytes", 0)
expected_payload = 53 * 1200 + 424
if packets != 54:
    raise SystemExit(f"FAIL: expected 54 accepted packets, observed {packets}; extra packet may have crossed the quota")
if payload_bytes != expected_payload:
    raise SystemExit(f"FAIL: expected {expected_payload} payload bytes, observed {payload_bytes}")
print(f"PASS: exactly {packets} packets ({payload_bytes} payload bytes) reached the sink; the post-boundary packet was blocked.")
CHECK

QUOTA_FINAL="$(ip netns exec "$GW" nft list quota inet rma_lab shared_ab)"
printf '%s\n' "$QUOTA_FINAL"
grep -q 'used 64 kbytes' <<<"$QUOTA_FINAL" || die "quota changed after the post-boundary packet"
echo "PASS: quota remained at 64 kbytes after the additional packet."
echo "Phase-A boundary tests passed. This validates the planned IPv4/UDP packet-size boundary in this lab; it does not certify TCP, IPv6, or production readiness."
