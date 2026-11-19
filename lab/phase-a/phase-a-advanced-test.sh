#!/usr/bin/env bash
set -Eeuo pipefail

readonly GW="rma-lab-gw"
readonly A="rma-lab-a"
readonly B="rma-lab-b"
readonly SINK="rma-lab-sink"
readonly PORT=44001
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PY="$ROOT/traffic.py"

die() { echo "FAIL: $*" >&2; exit 1; }
need_tools() {
  for x in ip nft python3; do command -v "$x" >/dev/null 2>&1 || die "missing tool: $x"; done
}
need_ns() {
  for ns in "$GW" "$A" "$B" "$SINK"; do
    ip netns list | awk '{print $1}' | grep -Fxq "$ns" || die "namespace missing: $ns"
  done
}
quota_reset() {
  ip netns exec "$GW" nft reset quota inet rma_lab shared_ab >/dev/null
}
show_quota() {
  ip netns exec "$GW" nft list quota inet rma_lab shared_ab
}
TMP="$(mktemp -d)"
SINK_PID=""
cleanup() {
  if [[ -n "$SINK_PID" ]]; then kill "$SINK_PID" 2>/dev/null || true; fi
  rm -rf "$TMP"
}
trap cleanup EXIT

need_tools
need_ns
[[ -f "$PY" ]] || die "traffic.py not found"

echo "[Q-03] Concurrent shared-quota stress: A and B send simultaneously"
quota_reset
ip netns exec "$SINK" python3 "$PY" serve --port "$PORT" --duration 3.0 --output "$TMP/concurrent.json" --ready-file "$TMP/ready" &
SINK_PID=$!
for _ in $(seq 1 50); do
  [[ -f "$TMP/ready" ]] && break
  kill -0 "$SINK_PID" 2>/dev/null || die "sink exited before ready"
  sleep 0.1
done
[[ -f "$TMP/ready" ]] || die "sink readiness timeout"

ip netns exec "$A" python3 "$PY" send --port "$PORT" --count 100 --interval 0.001 &
PID_A=$!
ip netns exec "$B" python3 "$PY" send --port "$PORT" --count 100 --interval 0.001 &
PID_B=$!
wait "$PID_A"
wait "$PID_B"
wait "$SINK_PID"
SINK_PID=""

cat "$TMP/concurrent.json"
show_quota

python3 - "$TMP/concurrent.json" <<'CHECK'
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    data = json.load(f)
a = data.get("10.10.1.2", {}).get("packets", 0)
b = data.get("10.10.2.2", {}).get("packets", 0)
total = a + b
if total <= 0:
    raise SystemExit("FAIL: no concurrent traffic reached the sink")
if total >= 200:
    raise SystemExit(f"FAIL: all {total}/200 packets passed; shared quota did not constrain traffic")
print(f"PASS: concurrent senders delivered {total}/200 packets (A={a}, B={b}); aggregate cap constrained the combined flow.")
CHECK

echo "[Q-04] Confirm quota remains exhausted after concurrent test"
QUOTA_OUTPUT="$(show_quota)"
printf '%s\n' "$QUOTA_OUTPUT"
grep -q 'used 64 kbytes' <<<"$QUOTA_OUTPUT" || die "expected shared quota to reach 64 kbytes"
echo "PASS: shared quota reached its configured 64-kbyte limit."

echo "Phase-A advanced UDP tests passed. This stage tests concurrency and quota exhaustion only; it does not certify exact packet-boundary accounting, TCP, IPv6, bidirectional traffic, or production readiness."
